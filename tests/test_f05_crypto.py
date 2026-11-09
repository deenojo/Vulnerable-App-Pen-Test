"""F05 Cryptographic Failures (CWE-256/916). Passwords are bcrypt-hashed and salted."""
from app.security import hash_password, verify_password


def test_hash_is_not_plaintext_and_is_salted():
    h1, h2 = hash_password("same-password"), hash_password("same-password")
    assert "same-password" not in h1
    assert h1 != h2  # per-password salt
    assert h1.startswith("$2b$")


def test_verify_round_trip():
    h = hash_password("correct horse")
    assert verify_password("correct horse", h)
    assert not verify_password("wrong", h)
