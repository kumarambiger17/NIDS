from app import app, DB_PATH
import sqlite3

client = app.test_client()
response = client.post('/register', data={
    'fullname': 'Test User',
    'email': 'test@example.com',
    'username': 'tester',
    'password': 'Test@1234',
    'confirm_password': 'Test@1234',
}, follow_redirects=False)

print('POST /register ->', response.status_code)
body = response.data.decode()
print(body)
if 'Registration failed' in body or '❌' in body:
    print('Error message found in response')
print('DB path (module):', DB_PATH)

for db in [DB_PATH, 'users_local.db']:
    try:
        conn = sqlite3.connect(db)
        row = conn.execute('SELECT username FROM users WHERE username = ?', ('tester',)).fetchone()
        print(f'{db}:', row)
        conn.close()
    except Exception as e:
        print(f'{db}: error ->', e)
conn.close()
