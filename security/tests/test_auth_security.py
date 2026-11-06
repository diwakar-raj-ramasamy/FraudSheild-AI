import pytest
from app.core.security import validate_password_strength, decode_token
from app.core.rate_limiter import auth_rate_limiter
from fastapi import HTTPException

def test_password_complexity_validator():
    # Weak: too short
    valid, msg = validate_password_strength("Short1!")
    assert not valid
    assert "8 characters" in msg

    # Weak: no uppercase
    valid, msg = validate_password_strength("nouppercase1@pass")
    assert not valid
    assert "uppercase" in msg

    # Weak: no lowercase
    valid, msg = validate_password_strength("NOLOWERCASE1@PASS")
    assert not valid
    assert "lowercase" in msg

    # Weak: no digit
    valid, msg = validate_password_strength("NoDigitsHere!@#")
    assert not valid
    assert "digit" in msg

    # Weak: no special char
    valid, msg = validate_password_strength("NoSpecialChar1234")
    assert not valid
    assert "special character" in msg

    # Strong password passes
    valid, msg = validate_password_strength("StrongPass@2026!")
    assert valid
    assert msg == ""

def test_login_invalid_credentials(client):
    res = client.post("/api/auth/login", json={
        "email": "admin@fraudshield.ai",
        "password": "WrongPassword123!"
    })
    assert res.status_code == 401
    assert "Incorrect email or password" in res.json()["detail"]

def test_login_nonexistent_user(client):
    res = client.post("/api/auth/login", json={
        "email": "nonexistent_analyst@fraudshield.ai",
        "password": "SomePassword123!"
    })
    assert res.status_code == 401

def test_login_success(client):
    res = client.post("/api/auth/login", json={
        "email": "admin@fraudshield.ai",
        "password": "Admin@FraudShield2026!"
    })
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["role"] == "admin"

def test_unauthorized_registration_rejected(client):
    # Unauthenticated attempt to register a new user
    res = client.post("/api/auth/register", json={
        "email": "intruder@fraudshield.ai",
        "password": "ValidPassword@2026!",
        "full_name": "Intruder",
        "role": "admin"
    })
    assert res.status_code == 401

def test_analyst_cannot_register_user(client, analyst_headers):
    # Analyst (non-admin) attempt to register a new user
    res = client.post(
        "/api/auth/register",
        json={
            "email": "analyst_created@fraudshield.ai",
            "password": "ValidPassword@2026!",
            "full_name": "New User",
            "role": "analyst"
        },
        headers=analyst_headers
    )
    assert res.status_code == 403

def test_admin_registration_with_weak_password_rejected(client, admin_headers):
    res = client.post(
        "/api/auth/register",
        json={
            "email": "weak_user@fraudshield.ai",
            "password": "weak",
            "full_name": "Weak User",
            "role": "analyst"
        },
        headers=admin_headers
    )
    assert res.status_code == 400
    assert "8 characters" in res.json()["detail"]

def test_expired_token_rejected(client, expired_token):
    res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {expired_token}"})
    assert res.status_code == 401
    assert "Could not validate credentials" in res.json()["detail"]

def test_malformed_token_rejected(client):
    res = client.get("/api/auth/me", headers={"Authorization": "Bearer invalid.jwt.token"})
    assert res.status_code == 401

def test_auth_rate_limiting(client):
    auth_rate_limiter.reset()
    # Trigger repeated login requests to verify sliding-window rate limit
    responses = []
    for _ in range(12):
        r = client.post("/api/auth/login", json={
            "email": "admin@fraudshield.ai",
            "password": "WrongPassword!"
        })
        responses.append(r.status_code)

    assert 429 in responses
    auth_rate_limiter.reset()

