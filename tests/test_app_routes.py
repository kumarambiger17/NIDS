import importlib
import sqlite3

import app as app_module


def test_app_imports_and_creates_settings_table():
    app_module = importlib.import_module("app")

    conn = sqlite3.connect(app_module.DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='settings'")
    row = cursor.fetchone()
    conn.close()

    assert row is not None
    assert hasattr(app_module, "change_username")


def test_forgot_password_flow_sets_session_and_verifies_otp(tmp_path, monkeypatch):
    db_path = tmp_path / "users.db"
    monkeypatch.setattr(app_module, "DB_PATH", str(db_path))
    app_module.init_db()

    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO users(fullname, email, username, password) VALUES(?,?,?,?)",
        ("Test User", "user@example.com", "testuser", "secret"),
    )
    conn.commit()
    conn.close()

    client = app_module.app.test_client()
    monkeypatch.setattr(app_module, "send_reset_otp_email", lambda email, otp: True)

    response = client.post(
        "/forgot_password",
        data={"email": "user@example.com"},
        follow_redirects=False,
    )

    assert response.status_code == 302

    with client.session_transaction() as sess:
        assert sess["reset_email"] == "user@example.com"
        assert sess["otp"]
        assert sess["otp_expiry"]
        otp = sess["otp"]

    verify_response = client.post(
        "/verify_otp",
        data={"otp": otp},
        follow_redirects=False,
    )

    assert verify_response.status_code == 302
