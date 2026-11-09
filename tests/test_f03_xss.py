"""F03 XSS (CWE-79). User content is HTML-escaped; a CSP header limits any residual impact."""
from tests.conftest import login


def test_bio_is_escaped_not_rendered(client, app):
    # Inject a script-like bio directly into the store, then render the profile.
    app.config["_shared"].execute("UPDATE users SET bio = ? WHERE id = 1",
                                  ("<script>steal()</script>",))
    login(client)
    body = client.get("/profile/1").get_data(as_text=True)
    assert "<script>steal()</script>" not in body
    assert "&lt;script&gt;" in body


def test_csp_header_present(client):
    login(client)
    resp = client.get("/profile/1")
    assert "default-src 'self'" in resp.headers.get("Content-Security-Policy", "")
