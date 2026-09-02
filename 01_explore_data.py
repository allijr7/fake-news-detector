import pandas as pd

fake = pd.read_csv('data/Fake.csv')
real = pd.read_csv('data/True.csv')

print("Fake shape:", fake.shape)
print("Real shape:", real.shape)

fake.head()
