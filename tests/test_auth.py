"""Tests for backend/auth/security.py"""
import pytest

from backend.auth.security import authenticate_user, create_access_token, decode_token


def test_authenticate_valid_user():
    user = authenticate_user("admin", "admin123")
    assert user is not None
    assert user.username == "admin"
    assert user.role == "admin"


def test_authenticate_wrong_password_returns_none():
    assert authenticate_user("admin", "wrong-password") is None


def test_authenticate_unknown_user_returns_none():
    assert authenticate_user("nonexistent", "whatever") is None


def test_token_roundtrip_preserves_username_and_role():
    user = authenticate_user("analyst", "analyst123")
    token = create_access_token(user)
    decoded = decode_token(token)
    assert decoded.username == "analyst"
    assert decoded.role == "analyst"


def test_decode_invalid_token_raises():
    from fastapi import HTTPException
    with pytest.raises(HTTPException):
        decode_token("not-a-real-token")
