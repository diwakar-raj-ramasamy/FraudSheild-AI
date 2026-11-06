import pytest

def test_liveness_probe_returns_200(client):
    res = client.get("/health/live")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "alive"
    assert "service" in data

def test_readiness_probe_returns_subsystem_health(client):
    res = client.get("/health/ready")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ready"
    assert "subsystems" in data
    assert "database" in data["subsystems"]
    assert data["subsystems"]["database"]["status"] == "healthy"
    assert "threat_intelligence_circuit_breakers" in data["subsystems"]
    assert "machine_learning_engine" in data["subsystems"]

def test_correlation_id_propagated_in_headers(client):
    custom_cid = "trace-test-uuid-12345"
    res = client.get("/health", headers={"X-Correlation-ID": custom_cid})
    assert res.status_code == 200
    assert res.headers.get("x-correlation-id") == custom_cid
    assert "x-response-time-ms" in res.headers

def test_auto_generated_correlation_id_when_missing(client):
    res = client.get("/health")
    assert res.status_code == 200
    cid = res.headers.get("x-correlation-id")
    assert cid is not None
    assert len(cid) > 0

def test_centralized_error_handler_structure(client):
    # Attempting to access non-existent route returns clean structured error without traceback
    res = client.get("/api/non_existent_endpoint_for_test")
    assert res.status_code == 404
    data = res.json()
    assert "error" in data
    assert "code" in data["error"]
    assert "correlation_id" in data["error"]
    assert "message" in data["error"]

def test_request_size_limit_middleware(client):
    # Generating payload over 30MB triggers 413
    huge_header = {"Content-Length": str(35 * 1024 * 1024)}
    res = client.post("/api/scan/url", headers=huge_header)
    assert res.status_code == 413
    data = res.json()
    assert data["error"]["code"] == "PAYLOAD_TOO_LARGE"

