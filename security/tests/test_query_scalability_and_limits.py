import pytest

def test_threats_endpoint_pagination_limits(client, admin_token):
    # Tests that threats endpoint honors limit parameter
    res = client.get("/api/threats?limit=5", headers={"Authorization": f"Bearer {admin_token}"})
    assert res.status_code == 200
    assert isinstance(res.json(), list)
    assert len(res.json()) <= 5

def test_events_endpoint_pagination(client, admin_token):
    res = client.get("/api/events?limit=10&skip=0", headers={"Authorization": f"Bearer {admin_token}"})
    assert res.status_code == 200
    assert isinstance(res.json(), list)
    assert len(res.json()) <= 10

def test_campaigns_endpoint_pagination(client, admin_token):
    res = client.get("/api/campaigns?limit=5&skip=0", headers={"Authorization": f"Bearer {admin_token}"})
    assert res.status_code == 200
    assert isinstance(res.json(), list)
    assert len(res.json()) <= 5

def test_devices_endpoint_pagination(client, admin_token):
    res = client.get("/api/devices?limit=5&skip=0", headers={"Authorization": f"Bearer {admin_token}"})
    assert res.status_code == 200
    assert isinstance(res.json(), list)
    assert len(res.json()) <= 5
