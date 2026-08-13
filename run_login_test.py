from app import app, DB_PATH
import sqlite3

# Ensure a user exists
conn = sqlite3.connect('users_local.db')
conn.execute('''CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fullname TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
)
''')
try:
    conn.execute('INSERT INTO users(fullname,email,username,password) VALUES(?,?,?,?)',
                 ('Login User','login@example.com','Vinu','Test@1234'))
    conn.commit()
except Exception:
    pass
conn.close()

with app.test_client() as client:
    # perform login
    resp = client.post('/login', data={'username':'Vinu','password':'Test@1234'}, follow_redirects=True)
    print('Login status:', resp.status_code)
    # get dashboard
    r2 = client.get('/dashboard')
    body = r2.data.decode()
    print('Dashboard status:', r2.status_code)
    # print greeting snippet
    start = body.find('<h1 class="greet">')
    if start!=-1:
        snippet = body[start:start+120]
        print('Greeting snippet:', snippet)
    else:
        print('Greeting not found')
