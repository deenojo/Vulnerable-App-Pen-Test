"""F04 SSRF (CWE-918). Outbound URLs need https, an allowlisted host, and a public address."""
import pytest
from app.security import validate_outbound_url
from tests.conftest import login

ALLOW = {"cdn.example-invoicing.com"}


@pytest.mark.parametrize("url", [
    "http://cdn.example-invoicing.com/logo.png",     # not https
    "https://169.254.169.254/latest/meta-data/",     # cloud metadata, not allowlisted
    "https://localhost/admin",                        # not allowlisted
    "https://evil.example.com/logo.png",             # not allowlisted
])
def test_dangerous_urls_are_rejected(url):
    with pytest.raises(ValueError):
        validate_outbound_url(url, ALLOW)


def test_endpoint_rejects_metadata_url(client):
    login(client)
    resp = client.post("/profile/logo", data={"url": "https://169.254.169.254/"})
    assert resp.status_code == 400
