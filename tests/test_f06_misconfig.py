"""F06 Security Misconfiguration (CWE-16). Security headers set, secure session cookie, no Server."""
from tests.conftest import login


def test_security_headers_present(client):
    login(client)
    r = client.get("/invoices/1")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "Server" not in r.headers


def test_session_cookie_flags(app):
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SECURE"] is True
