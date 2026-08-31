import pytest

from app.security.auth import (
    hash_password,
    verify_password,
    create_access_token,
    decode_token,
    ROLE_HIERARCHY,
)


def test_password_hash_and_verify():
    h = hash_password("secret123")
    assert h != "secret123"
    assert verify_password("secret123", h)
    assert not verify_password("wrong", h)


def test_token_roundtrip():
    token = create_access_token("user-1", "ANALYST", "alice")
    payload = decode_token(token)
    assert payload["sub"] == "user-1"
    assert payload["role"] == "ANALYST"
    assert payload["username"] == "alice"


def test_role_hierarchy():
    assert ROLE_HIERARCHY["VIEWER"] < ROLE_HIERARCHY["RESEARCHER"] < ROLE_HIERARCHY["ANALYST"] < ROLE_HIERARCHY["ADMIN"]


def test_invalid_token_rejected():
    with pytest.raises(Exception):
        decode_token("not.a.valid.token")
