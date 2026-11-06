import pytest
from unittest.mock import patch, AsyncMock
from app.core.rate_limiter import scan_rate_limiter
from app.schemas import ScanResponse

def test_security_headers_present_on_responses(client):
    res = client.get("/health")
    assert res.status_code == 200
    headers = res.headers

    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("X-XSS-Protection") == "1; mode=block"
    assert "max-age=" in headers.get("Strict-Transport-Security", "")
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "default-src 'self'" in headers.get("Content-Security-Policy", "")

def test_cors_allowed_origins(client):
    res = client.options(
        "/api/scan/url",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST"
        }
    )
    assert res.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert res.headers.get("access-control-allow-credentials") == "true"

def test_cors_chrome_extension_origin_allowed(client):
    res = client.options(
        "/api/scan/url",
        headers={
            "Origin": "chrome-extension://abcdefghijklmnopabcdefghijklmnop",
            "Access-Control-Request-Method": "POST"
        }
    )
    assert "chrome-extension://" in res.headers.get("access-control-allow-origin", "")

def test_scan_endpoint_requires_valid_url(client):
    res = client.post("/api/scan/url", json={"url": ""})
    assert res.status_code == 400
    assert "URL field is required" in res.json()["detail"]

def test_scan_rate_limiter(client):
    scan_rate_limiter.reset()
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
        responses = []
        for _ in range(125):
            r = client.post("/api/scan/url", json={"url": "https://example.com"})
            responses.append(r.status_code)
            if r.status_code == 429:
                break

        assert 429 in responses
    scan_rate_limiter.reset()
