import pytest
from unittest.mock import patch, AsyncMock
from app.schemas import ScanResponse

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(document.cookie)>",
    "javascript:alert(1)",
    "\"><script>alert(1)</script>",
    "<svg/onload=alert('XSS')>",
    "<iframe src='javascript:alert(1)'></iframe>"
]

def test_xss_payloads_in_url_scan_handled_safely(client):
    dummy_resp = ScanResponse(
        url="https://target-site.com",
        normalized_url="https://target-site.com",
        domain="target-site.com",
        risk_score=65,
        classification="CRITICAL",
        attack_types=["XSS_INDICATOR"],
        xai_factors=[],
        summary="Potential script injection detected"
    )
    with patch("app.api.scan.scan_service.perform_scan", new_callable=AsyncMock) as mock_scan:
        mock_scan.return_value = dummy_resp
        for payload in XSS_PAYLOADS:
            res = client.post("/api/scan/url", json={
                "url": f"https://target-site.com/search?q={payload}",
                "page_title": f"Test Page {payload}",
                "dom_signals": {
                    "claimed_brand": payload
                }
            })
            assert res.status_code == 200
            data = res.json()
            assert isinstance(data["risk_score"], (int, float))
            assert "xai_factors" in data

def test_xss_payload_in_event_reporting(client):
    for payload in XSS_PAYLOADS:
        res = client.post("/api/events/detection", json={
            "url": f"https://phish.example.com/login?param={payload}",
            "risk_score": 75,
            "classification": "CRITICAL",
            "attack_types": ["PHISHING", "FAKE_LOGIN_PAGE"],
            "page_title": payload
        })
        assert res.status_code == 200
        data = res.json()
        assert "id" in data
