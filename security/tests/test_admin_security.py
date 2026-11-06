import pytest
from app.models import AdminAlert, FraudCampaign, BlocklistEntry

def test_blocklist_tampering_prevented(client, analyst_headers):
    # 1. Unauthenticated attempt
    res = client.post("/api/blocklist", json={
        "target": "unauth-blocked-domain.com",
        "target_type": "DOMAIN",
        "reason": "Tampering attempt",
        "severity": "CRITICAL"
    })
    assert res.status_code == 401

    # 2. Analyst attempt
    res = client.post("/api/blocklist", json={
        "target": "analyst-blocked-domain.com",
        "target_type": "DOMAIN",
        "reason": "Analyst attempt",
        "severity": "CRITICAL"
    }, headers=analyst_headers)
    assert res.status_code == 403

def test_admin_can_add_and_delete_blocklist_entry(client, admin_headers, db):
    test_domain = "verified-phishing-host-999.xyz"
    # Add
    res = client.post("/api/blocklist", json={
        "target": test_domain,
        "target_type": "DOMAIN",
        "reason": "Verified active phishing domain",
        "severity": "CRITICAL"
    }, headers=admin_headers)
    assert res.status_code == 200
    entry_id = res.json()["id"]

    # Delete
    del_res = client.delete(f"/api/blocklist/{entry_id}", headers=admin_headers)
    assert del_res.status_code == 200
    assert del_res.json()["status"] == "success"

def test_alert_resolution_requires_admin(client, admin_headers, db):
    # Create test alert in DB
    alert = AdminAlert(
        title="Test Alert",
        description="Suspicious activity detected",
        severity="HIGH",
        event_type="THREAT_SPIKE"
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)

    # Unauthenticated resolution attempt fails
    unauth_res = client.patch(f"/api/alerts/{alert.id}", json={"is_resolved": True})
    assert unauth_res.status_code == 401

    # Admin resolution succeeds
    admin_res = client.patch(f"/api/alerts/{alert.id}", json={"is_resolved": True}, headers=admin_headers)
    assert admin_res.status_code == 200
    assert admin_res.json()["is_resolved"] is True

def test_campaign_mitigation_requires_admin(client, admin_headers, db):
    # Create test campaign
    camp = FraudCampaign(
        campaign_name="Targeted Phishing Wave",
        domain="phish-bank-auth-2026.net",
        detection_count=5,
        affected_devices_count=3,
        status="ACTIVE"
    )
    db.add(camp)
    db.commit()
    db.refresh(camp)

    # Unauthenticated mitigation fails
    unauth = client.post(f"/api/campaigns/{camp.id}/block")
    assert unauth.status_code == 401

    # Admin mitigation succeeds
    res = client.post(f"/api/campaigns/{camp.id}/block", headers=admin_headers)
    assert res.status_code == 200
    assert res.json()["status"] == "success"

    # Verify domain was added to blocklist
    blocked = db.query(BlocklistEntry).filter(
        BlocklistEntry.target == "phish-bank-auth-2026.net",
        BlocklistEntry.is_active == True
    ).first()
    assert blocked is not None

