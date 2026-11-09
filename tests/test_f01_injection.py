"""F01 Injection (CWE-89). The search term is bound as a parameter, so injection text is inert."""
from tests.conftest import login


def test_injection_string_is_treated_as_data(client):
    login(client)
    # A classic tautology/termination string must match nothing and must not error.
    resp = client.get("/invoices/search", query_string={"q": "' OR '1'='1"})
    assert resp.status_code == 200
    assert resp.get_json() == []  # bound as a literal customer name, matches no row


def test_search_still_works_for_real_terms(client):
    login(client)
    resp = client.get("/invoices/search", query_string={"q": "Acme"})
    assert resp.status_code == 200
    assert any(r["customer"] == "Acme Corp" for r in resp.get_json())


def test_injection_cannot_drop_table(client):
    login(client)
    client.get("/invoices/search", query_string={"q": "x'); DROP TABLE invoices;--"})
    # The table must still be there afterwards.
    resp = client.get("/invoices/search", query_string={"q": "Globex"})
    assert resp.status_code == 200 and len(resp.get_json()) == 1
