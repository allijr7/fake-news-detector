from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime
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

import re as re_module

def validate_password(password):
    if len(password) < 8:
        return "Password must be at least 8 characters"
    if not re_module.search(r'[A-Z]', password):
        return "Password must include at least one uppercase letter"
    if not re_module.search(r'[0-9]', password):
        return "Password must include at least one number"
    if not re_module.search(r'[!@#$%^&*(),.?":{}|<>_\-+=]', password):
        return "Password must include at least one special character"
    return None
    
def validate_username(username):
    if not re_module.match(r'^[A-Za-z0-9_.]{3,20}$', username):
        return "Username must be 3-20 characters (letters, numbers, underscores, dots only)"
    return None
    
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

    username_error = validate_username(username)
    if username_error:
        return jsonify({'error': username_error}), 400

    password_error = validate_password(password)
    if password_error:
        return jsonify({'error': password_error}), 400

    password_error = validate_password(password)
    if password_error:
        return jsonify({'error': password_error}), 400

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
    return jsonify({'token': token, 'username': username, 'role': 'user', 'is_super_admin': False, 'name': None})


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

    if not user:
        cur.close()
        conn.close()
        return jsonify({'error': 'Invalid username or password'}), 401

    if user['is_suspended']:
        cur.close()
        conn.close()
        return jsonify({'error': 'This account has been suspended. Contact an administrator.'}), 403

    if user['locked_until'] and user['locked_until'] > datetime.utcnow():
        remaining = int((user['locked_until'] - datetime.utcnow()).total_seconds() / 60) + 1
        cur.close()
        conn.close()
        return jsonify({'error': f'Account locked due to failed attempts. Try again in {remaining} minute(s).'}), 403

    if not bcrypt.check_password_hash(user['password_hash'], password):
        new_attempts = user['failed_login_attempts'] + 1
        cur2 = conn.cursor()
        if new_attempts >= 5:
            from datetime import timedelta
            lock_time = datetime.utcnow() + timedelta(minutes=15)
            cur2.execute(
                "UPDATE users SET failed_login_attempts = %s, locked_until = %s WHERE id = %s",
                (new_attempts, lock_time, user['id'])
            )
            conn.commit()
            cur2.close()
            cur.close()
            conn.close()
            return jsonify({'error': 'Too many failed attempts. Account locked for 15 minutes.'}), 403
        else:
            cur2.execute(
                "UPDATE users SET failed_login_attempts = %s WHERE id = %s",
                (new_attempts, user['id'])
            )
            conn.commit()
            cur2.close()
            cur.close()
            conn.close()
            remaining_tries = 5 - new_attempts
            return jsonify({'error': f'Invalid username or password. {remaining_tries} attempt(s) remaining.'}), 401

    # Successful login — reset failed attempts
    cur2 = conn.cursor()
    cur2.execute("UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = %s", (user['id'],))
    conn.commit()
    cur2.close()
    cur.close()
    conn.close()

    token = create_access_token(identity=str(user['id']))
    return jsonify({
        'token': token,
        'username': user['username'],
        'role': user['role'],
        'is_super_admin': user.get('is_super_admin', False),
        'name': user.get('name')
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

    result = run_prediction(text)
    save_check(user_id, 'url' if 'url' in data and data['url'] else 'text', data.get('url'), result)

    return jsonify(result)

@app.route('/predict-batch', methods=['POST'])
@jwt_required()
@limiter.limit("3 per minute")
def predict_batch():
    user_id = get_jwt_identity()
    data = request.get_json()
    urls = data.get('urls', [])

    if not urls or not isinstance(urls, list):
        return jsonify({'error': 'Provide a list of URLs'}), 400
    if len(urls) > 10:
        return jsonify({'error': 'Maximum 10 URLs per batch'}), 400

    results = []
    for url in urls:
        url = url.strip()
        if not url:
            continue
        try:
            text = scrape_url(url)
            if len(text.strip()) < 200:
                results.append({'url': url, 'error': 'Could not extract enough article text'})
                continue
            result = run_prediction(text)
            save_check(user_id, 'url', url, result)
            results.append({'url': url, **result})
        except Exception as e:
            results.append({'url': url, 'error': f'Could not fetch article: {str(e)}'})

    return jsonify({'results': results})

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
        """SELECT u.id, u.username, u.role, u.is_super_admin, u.is_suspended, u.created_at,
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

@app.route('/admin/analytics', methods=['GET'])
@jwt_required()
def admin_analytics():
    user_id = get_jwt_identity()
    if not require_admin(user_id):
        return jsonify({'error': 'Admin access required'}), 403

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute(
        """SELECT DATE(checked_at) as day, COUNT(*) as count
           FROM checks
           WHERE checked_at >= NOW() - INTERVAL '14 days'
           GROUP BY DATE(checked_at)
           ORDER BY day"""
    )
    daily = cur.fetchall()

    cur.execute("SELECT label, COUNT(*) as count FROM checks GROUP BY label")
    by_label = cur.fetchall()

    cur.execute("SELECT COUNT(*) as total_users FROM users")
    total_users = cur.fetchone()['total_users']

    cur.execute("SELECT COUNT(*) as total_checks FROM checks")
    total_checks = cur.fetchone()['total_checks']

    cur.close()
    conn.close()

    for d in daily:
        d['day'] = d['day'].isoformat()

    return jsonify({
        'daily': daily,
        'by_label': by_label,
        'total_users': total_users,
        'total_checks': total_checks
    })

@app.route('/admin/users/<int:target_id>/suspend', methods=['PATCH'])
@jwt_required()
def admin_toggle_suspend(target_id):
    user_id = get_jwt_identity()
    if not require_admin(user_id):
        return jsonify({'error': 'Admin access required'}), 403

    if str(target_id) == str(user_id):
        return jsonify({'error': "You can't suspend your own account"}), 400

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT username, is_suspended, is_super_admin FROM users WHERE id = %s", (target_id,))
    target = cur.fetchone()

    if not target:
        cur.close()
        conn.close()
        return jsonify({'error': 'User not found'}), 404

    if target['is_super_admin']:
        cur.close()
        conn.close()
        return jsonify({'error': 'This account cannot be suspended'}), 403

    new_status = not target['is_suspended']
    cur2 = conn.cursor()
    cur2.execute("UPDATE users SET is_suspended = %s WHERE id = %s", (new_status, target_id))
    conn.commit()
    cur2.close()

    # Log this action
    actor_cur = conn.cursor(cursor_factory=RealDictCursor)
    actor_cur.execute("SELECT username FROM users WHERE id = %s", (user_id,))
    actor = actor_cur.fetchone()
    actor_cur.close()

    log_cur = conn.cursor()
    action = 'suspend' if new_status else 'reactivate'
    log_cur.execute(
        "INSERT INTO admin_audit_log (actor_id, action, target_username, details) VALUES (%s, %s, %s, %s)",
        (user_id, action, target['username'], f"{actor['username']} {action}ed {target['username']}")
    )
    conn.commit()
    log_cur.close()
    cur.close()
    conn.close()

    return jsonify({'success': True, 'is_suspended': new_status})

@app.route('/change-password', methods=['POST'])
@jwt_required()
def change_password():
    user_id = get_jwt_identity()
    data = request.get_json()
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')

    if not current_password or not new_password:
        return jsonify({'error': 'Both current and new password are required'}), 400
    password_error = validate_password(new_password)

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT password_hash FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()

    if not user or not bcrypt.check_password_hash(user['password_hash'], current_password):
        cur.close()
        conn.close()
        return jsonify({'error': 'Current password is incorrect'}), 401

    new_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
    cur = conn.cursor()
    cur.execute("UPDATE users SET password_hash = %s WHERE id = %s", (new_hash, user_id))
    conn.commit()
    cur.close()
    conn.close()

    return jsonify({'success': True})

@app.route('/change-name', methods=['POST'])
@jwt_required()
def change_name():
    user_id = get_jwt_identity()
    data = request.get_json()
    new_name = (data.get('name') or '').strip()

    if len(new_name) > 50:
        return jsonify({'error': 'Name must be 50 characters or fewer'}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE users SET name = %s WHERE id = %s", (new_name or None, user_id))
    conn.commit()
    cur.close()
    conn.close()

    return jsonify({'success': True, 'name': new_name})


@app.route('/change-username', methods=['POST'])
@jwt_required()
def change_username():
    user_id = get_jwt_identity()
    data = request.get_json()
    new_username = (data.get('username') or '').strip()

    username_error = validate_username(new_username)
    if username_error:
        return jsonify({'error': username_error}), 400

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT username, username_changed_at FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()

    if user['username_changed_at']:
        days_since = (datetime.utcnow() - user['username_changed_at']).days
        if days_since < 14:
            cur.close()
            conn.close()
            return jsonify({'error': f'You can change your username again in {14 - days_since} day(s)'}), 400

    if new_username == user['username']:
        cur.close()
        conn.close()
        return jsonify({'error': 'That is already your username'}), 400

    try:
        cur2 = conn.cursor()
        cur2.execute(
            "UPDATE users SET username = %s, username_changed_at = NOW() WHERE id = %s",
            (new_username, user_id)
        )
        conn.commit()
        cur2.close()
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        cur.close()
        conn.close()
        return jsonify({'error': 'Username already taken'}), 409

    cur.close()
    conn.close()
    return jsonify({'success': True, 'username': new_username})

@app.route('/check-username', methods=['GET'])
def check_username():
    username = request.args.get('username', '').strip()

    format_error = validate_username(username)
    if format_error:
        return jsonify({'available': False, 'error': format_error})

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT id FROM users WHERE username = %s", (username,))
    exists = cur.fetchone()
    cur.close()
    conn.close()

    return jsonify({'available': not exists})


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True, host='0.0.0.0', port=port)