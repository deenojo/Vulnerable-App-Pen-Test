"""F02 Broken Access Control / IDOR (CWE-639). Owners only, admins override."""
from tests.conftest import login


def test_user_cannot_read_another_users_invoice(client):
    login(client, "alice", "alice-pw")
    # Invoice 3 belongs to bob/admin, not alice.
    assert client.get("/invoices/3").status_code == 403


def test_user_can_read_own_invoice(client):
    login(client, "alice", "alice-pw")
    resp = client.get("/invoices/1")
    assert resp.status_code == 200 and resp.get_json()["owner_id"] == 1


def test_admin_can_read_any_invoice(client):
    login(client, "admin", "admin-pw")
    assert client.get("/invoices/1").status_code == 200


def test_unauthenticated_is_rejected(client):
    assert client.get("/invoices/1").status_code == 401
