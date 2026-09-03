from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import joblib
import re
import psycopg2
from psycopg2.extras import RealDictCursor
from newspaper import Article

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
CORS(app)
bcrypt = Bcrypt(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://"
)

import os

app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'dev-only-fallback-key')
jwt = JWTManager(app)

model = joblib.load('model.pkl')
vectorizer = joblib.load('vectorizer.pkl')

DB_CONFIG = {
    'host': os.environ.get('DB_HOST', 'localhost'),
    'database': os.environ.get('DB_NAME', 'fakenews_db'),
    'user': os.environ.get('DB_USER', 'postgres'),
    'password': os.environ.get('DB_PASSWORD', 'allijr10'),
    'port': int(os.environ.get('DB_PORT', 5432))
}
def get_db_connection():
    sslmode = 'require' if DB_CONFIG['host'] != 'localhost' else 'prefer'
    return psycopg2.connect(**DB_CONFIG, sslmode=sslmode)

def require_admin(user_id):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT role FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    cur.close()
    conn.close()
    return user and user['role'] == 'admin'

def require_super_admin(user_id):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT is_super_admin FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    cur.close()
    conn.close()
    return user and user['is_super_admin']


def clean_text(text):
    text = str(text)
    text = re.sub(r'^.*?\(Reuters\)\s*-\s*', '', text)
    text = re.sub(r'http\S+|www\S+', '', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def scrape_url(url):
    article = Article(url)
    article.download()
    article.parse()
    return article.text


@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users (username, password_hash) VALUES (%s, %s) RETURNING id",
            (username, password_hash)
        )
        user_id = cur.fetchone()[0]
        conn.commit()
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return jsonify({'error': 'Username already taken'}), 409
    finally:
        cur.close()
        conn.close()

    token = create_access_token(identity=str(user_id))
    return jsonify({'token': token, 'username': username})


@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if not user or not bcrypt.check_password_hash(user['password_hash'], password):
        return jsonify({'error': 'Invalid username or password'}), 401

    token = create_access_token(identity=str(user['id']))
    return jsonify({
        'token': token,
        'username': user['username'],
        'role': user['role'],
        'is_super_admin': user.get('is_super_admin', False)
    })


@app.route('/predict', methods=['POST'])
@jwt_required()
@limiter.limit("10 per minute")
def predict():
    user_id = get_jwt_identity()
    data = request.get_json()

    if 'url' in data and data['url']:
        try:
            text = scrape_url(data['url'])
        except Exception as e:
            return jsonify({'error': f'Could not fetch article: {str(e)}'}), 400

        if len(text.strip()) < 200:
            return jsonify({
                'error': 'Could not extract enough article text from this URL. '
                         'This can happen with slideshow pages, JavaScript-heavy sites, '
                         'or paywalled content. Try pasting the article text directly instead.'
            }), 400
    elif 'text' in data and data['text']:
        text = data['text']
    else:
        return jsonify({'error': 'Provide either text or url'}), 400

    cleaned = clean_text(text)
    vectorized = vectorizer.transform([cleaned])
    prediction = model.predict(vectorized)[0]
    probability = model.predict_proba(vectorized)[0]

    confidence = float(max(probability))
    confidence_pct = round(confidence * 100, 2)

    if confidence_pct < 60:
        label = 'Uncertain'
    else:
        label = 'Real' if prediction == 1 else 'Fake'

    feature_names = vectorizer.get_feature_names_out()
    coefficients = model.coef_[0]

    nonzero_indices = vectorized.nonzero()[1]
    word_scores = [(feature_names[i], coefficients[i]) for i in nonzero_indices]

    if prediction == 1:
        word_scores.sort(key=lambda x: x[1], reverse=True)
    else:
        word_scores.sort(key=lambda x: x[1])

    top_words = [
        {'word': w, 'weight': round(float(s), 3)}
        for w, s in word_scores[:8]
    ]

    result = {
        'label': label,
        'confidence': confidence_pct,
        'extracted_text_preview': cleaned[:300],
        'top_words': top_words
    }

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO checks (user_id, input_type, input_source, text_preview, label, confidence)
           VALUES (%s, %s, %s, %s, %s, %s)""",
        (
            user_id,
            'url' if 'url' in data and data['url'] else 'text',
            data.get('url'),
            result['extracted_text_preview'],
            result['label'],
            result['confidence']
        )
    )
    conn.commit()
    cur.close()
    conn.close()

    return jsonify(result)


@app.route('/history', methods=['GET'])
@jwt_required()
def history():
    user_id = get_jwt_identity()

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute(
        """SELECT id, input_type, input_source, text_preview, label, confidence, checked_at
           FROM checks WHERE user_id = %s ORDER BY checked_at DESC""",
        (user_id,)
    )
    checks = cur.fetchall()
    cur.close()
    conn.close()

    for c in checks:
        c['checked_at'] = c['checked_at'].isoformat()

    return jsonify(checks)


@app.route('/history/<int:check_id>', methods=['DELETE'])
@jwt_required()
def delete_check(check_id):
    user_id = get_jwt_identity()

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "DELETE FROM checks WHERE id = %s AND user_id = %s",
        (check_id, user_id)
    )
    deleted = cur.rowcount
    conn.commit()
    cur.close()
    conn.close()

    if deleted == 0:
        return jsonify({'error': 'Not found'}), 404

    return jsonify({'success': True})

@app.route('/admin/users', methods=['GET'])
@jwt_required()
def admin_list_users():
    user_id = get_jwt_identity()
    if not require_admin(user_id):
        return jsonify({'error': 'Admin access required'}), 403

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute(
        """SELECT u.id, u.username, u.role, u.is_super_admin, u.created_at,
                  COUNT(c.id) as check_count
           FROM users u
           LEFT JOIN checks c ON c.user_id = u.id
           GROUP BY u.id
           ORDER BY u.created_at DESC"""
    )
    users = cur.fetchall()
    cur.close()
    conn.close()

    for u in users:
        u['created_at'] = u['created_at'].isoformat()

    return jsonify(users)


@app.route('/admin/checks', methods=['GET'])
@jwt_required()
def admin_list_checks():
    user_id = get_jwt_identity()
    if not require_admin(user_id):
        return jsonify({'error': 'Admin access required'}), 403

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute(
        """SELECT c.id, c.label, c.confidence, c.checked_at, c.input_type, u.username
           FROM checks c
           JOIN users u ON u.id = c.user_id
           ORDER BY c.checked_at DESC
           LIMIT 100"""
    )
    checks = cur.fetchall()
    cur.close()
    conn.close()

    for c in checks:
        c['checked_at'] = c['checked_at'].isoformat()

    return jsonify(checks)


@app.route('/admin/users/<int:target_id>', methods=['DELETE'])
@jwt_required()
def admin_delete_user(target_id):
    user_id = get_jwt_identity()
    if not require_admin(user_id):
        return jsonify({'error': 'Admin access required'}), 403

    if str(target_id) == str(user_id):
        return jsonify({'error': "You can't delete your own account here"}), 400

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT is_super_admin FROM users WHERE id = %s", (target_id,))
    target = cur.fetchone()
    if target and target['is_super_admin']:
        cur.close()
        conn.close()
        return jsonify({'error': 'This account cannot be removed'}), 403

    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id = %s", (target_id,))
    conn.commit()
    cur.close()
    conn.close()

    return jsonify({'success': True})

@app.route('/admin/users/<int:target_id>/role', methods=['PATCH'])
@jwt_required()
def admin_update_role(target_id):
    user_id = get_jwt_identity()
    if not require_super_admin(user_id):
        return jsonify({'error': 'Super admin access required'}), 403

    data = request.get_json()
    new_role = data.get('role')
    if new_role not in ('user', 'admin'):
        return jsonify({'error': 'Invalid role'}), 400

    if str(target_id) == str(user_id):
        return jsonify({'error': "You can't change your own role here"}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE users SET role = %s WHERE id = %s", (new_role, target_id))
    conn.commit()
    cur.close()
    conn.close()

    return jsonify({'success': True})


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True, host='0.0.0.0', port=port)