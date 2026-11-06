import pytest

PROTECTED_ADMIN_ENDPOINTS = [
    ("GET", "/api/alerts"),
    ("GET", "/api/blocklist"),
    ("POST", "/api/blocklist", {"target": "malicious-test.xyz", "target_type": "DOMAIN", "reason": "Test", "severity": "HIGH"}),
    ("GET", "/api/campaigns"),
    ("GET", "/api/devices"),
    ("GET", "/api/downloads"),
    ("GET", "/api/files/analyses"),
]

PUBLIC_DEVICE_ENDPOINTS = [
    ("GET", "/health"),
    ("GET", "/api/blocklist/version"),
    ("POST", "/api/devices/register", {"installation_pseudonym": "test-device-uuid-12345"}),
    ("POST", "/api/downloads/check", {"file_name": "sample.pdf", "download_url": "https://example.com/sample.pdf"}),
]

def test_unauthenticated_requests_receive_401(client):
    for method, path, *data in PROTECTED_ADMIN_ENDPOINTS:
        payload = data[0] if data else None
        if method == "GET":
            res = client.get(path)
        elif method == "POST":
            res = client.post(path, json=payload)
        elif method == "DELETE":
            res = client.delete(path)

        assert res.status_code == 401, f"Expected 401 for unauthenticated {method} {path}, got {res.status_code}"

def test_analyst_role_forbidden_on_admin_operations(client, analyst_headers):
    # Analyst cannot modify blocklist
    res = client.post(
        "/api/blocklist",
        json={"target": "attacker-site.com", "target_type": "DOMAIN", "reason": "Test", "severity": "CRITICAL"},
        headers=analyst_headers
    )
    assert res.status_code == 403, f"Expected 403 for analyst modifying blocklist, got {res.status_code}"

    # Analyst cannot view device list
    res = client.get("/api/devices", headers=analyst_headers)
    assert res.status_code == 403

def test_admin_role_succeeds_on_protected_endpoints(client, admin_headers):
    res = client.get("/api/alerts", headers=admin_headers)
    assert res.status_code == 200

    res = client.get("/api/blocklist", headers=admin_headers)
    assert res.status_code == 200

    res = client.get("/api/campaigns", headers=admin_headers)
    assert res.status_code == 200

    res = client.get("/api/devices", headers=admin_headers)
    assert res.status_code == 200

    res = client.get("/api/downloads", headers=admin_headers)
    assert res.status_code == 200

    res = client.get("/api/files/analyses", headers=admin_headers)
    assert res.status_code == 200

def test_public_and_extension_endpoints_accessible_without_auth(client):
    for method, path, *data in PUBLIC_DEVICE_ENDPOINTS:
        payload = data[0] if data else None
        if method == "GET":
            res = client.get(path)
        elif method == "POST":
            res = client.post(path, json=payload)

        assert res.status_code in [200, 201], f"Expected success for extension endpoint {method} {path}, got {res.status_code}"

