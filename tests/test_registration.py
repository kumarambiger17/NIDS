import os
import sqlite3
import sys

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import app as app_module
from app import app


def test_register_creates_user(tmp_path, monkeypatch):
    db_path = tmp_path / 'users.db'
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(app_module, 'DB_PATH', str(db_path))
    monkeypatch.setattr('app.app', app)
    app_module.init_db()

    client = app.test_client()
    response = client.post('/register', data={
        'fullname': 'Test User',
        'email': 'test@example.com',
        'username': 'tester',
        'password': 'Test@1234',
        'confirm_password': 'Test@1234',
    }, follow_redirects=False)

    assert response.status_code == 302
    assert db_path.exists()

    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute('SELECT username FROM users WHERE username = ?', ('tester',)).fetchone()
        assert row is not None
    finally:
        conn.close()


def test_register_allows_same_email_for_multiple_users(tmp_path, monkeypatch):
    db_path = tmp_path / 'users.db'
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(app_module, 'DB_PATH', str(db_path))
    app_module.init_db()

    client = app.test_client()

    first_response = client.post('/register', data={
        'fullname': 'First User',
        'email': 'shared@example.com',
        'username': 'firstuser',
        'password': 'Test@1234',
        'confirm_password': 'Test@1234',
    }, follow_redirects=False)

    second_response = client.post('/register', data={
        'fullname': 'Second User',
        'email': 'shared@example.com',
        'username': 'seconduser',
        'password': 'Test@1234',
        'confirm_password': 'Test@1234',
    }, follow_redirects=False)

    assert first_response.status_code == 302
    assert second_response.status_code == 302

    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute('SELECT username FROM users WHERE email = ?', ('shared@example.com',)).fetchall()
        assert len(rows) == 2
    finally:
        conn.close()
