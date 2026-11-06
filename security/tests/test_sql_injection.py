import pytest
from unittest.mock import patch, AsyncMock
from app.schemas import ScanResponse

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "admin'--",
    "admin' #",
    "' UNION SELECT 1, 'admin', 'password', 'role'--",
    "'; DROP TABLE users;--",
    "1' OR 1=1--",
    "1' ORDER BY 1--",
    "\" OR \"1\"=\"1",
]

def test_sql_injection_in_authentication_fails(client):
    for payload in SQLI_PAYLOADS:
        res = client.post("/api/auth/login", json={
            "email": payload,
            "password": "Password123!"
        })
        # Must return 401 Unauthorized or 400 Bad Request; NEVER 200 or 500
        assert res.status_code in [401, 400], f"Vulnerability detected: payload '{payload}' produced {res.status_code}"

def test_sql_injection_in_scan_url_parameter(client):
    dummy_resp = ScanResponse(
        url="https://example.com",
        normalized_url="https://example.com",
        domain="example.com",
        risk_score=10,
        classification="SAFE",
        attack_types=[],
        xai_factors=[],
        summary="Safe site"
    )
    with patch("app.api.scan.scan_service.perform_scan", new_callable=AsyncMock) as mock_scan:
        mock_scan.return_value = dummy_resp
        for payload in SQLI_PAYLOADS:
            test_url = f"https://example.com/login?id={payload}"
            res = client.post("/api/scan/url", json={
                "url": test_url,
                "page_title": payload
            })
            assert res.status_code == 200
            data = res.json()
            assert "risk_score" in data

def test_sql_injection_in_device_pseudonym(client):
    for payload in SQLI_PAYLOADS:
        res = client.post("/api/devices/register", json={
            "installation_pseudonym": payload
        })
        # Schema validation rejects malicious injection
        assert res.status_code in [400, 422], f"SQL injection payload in device pseudonym was not validated: '{payload}'"
