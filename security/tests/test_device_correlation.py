import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.models import Base, Device, DetectionEvent, FraudCampaign
from app.services.correlation_service import correlation_service

def test_device_privacy_schema_integrity(db):
    columns = [c.name for c in Device.__table__.columns]
    # Verify mandatory privacy posture
    assert "mac_address" not in columns
    assert "hardware_id" not in columns
    assert "serial_number" not in columns
    assert "ip_address" not in columns
    assert "installation_pseudonym" in columns

def test_device_pseudonym_validation(client):
    # Valid pseudonym (UUID format)
    res = client.post("/api/devices/register", json={
        "installation_pseudonym": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "extension_version": "1.0.0"
    })
    assert res.status_code == 200

    # Invalid: Too short (< 8 chars)
    res = client.post("/api/devices/register", json={
        "installation_pseudonym": "short",
        "extension_version": "1.0.0"
    })
    assert res.status_code == 422

    # Invalid: Contains illegal characters
    res = client.post("/api/devices/register", json={
        "installation_pseudonym": "bad!pseudonym@#$%^&*()",
        "extension_version": "1.0.0"
    })
    assert res.status_code == 422

def test_multi_device_correlation_triggers_campaign():
    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )
    Base.metadata.create_all(bind=test_engine)
    TestSession = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    mem_db = TestSession()

    domain = "campaign-testing-threat-2026.com"
    url = f"https://{domain}/login"

    # Detection 1: Device 1
    r1 = correlation_service.record_detection_event(
        raw_url=url,
        device_pseudonym="device-pseudo-alpha-1111",
        risk_score=85,
        classification="CRITICAL",
        attack_types=["PHISHING"],
        db=mem_db
    )
    assert r1["total_detections"] == 1

    # Detection 2: Device 2
    r2 = correlation_service.record_detection_event(
        raw_url=url,
        device_pseudonym="device-pseudo-beta-2222",
        risk_score=90,
        classification="CRITICAL",
        attack_types=["FAKE_LOGIN_PAGE"],
        db=mem_db
    )
    assert r2["unique_devices"] == 2

    # Detection 3: Device 1 again -> triggers campaign
    r3 = correlation_service.record_detection_event(
        raw_url=url,
        device_pseudonym="device-pseudo-alpha-1111",
        risk_score=88,
        classification="CRITICAL",
        attack_types=["PHISHING"],
        db=mem_db
    )
    assert r3["campaign_created"] is True
    assert r3["campaign_id"] is not None

    camp = mem_db.query(FraudCampaign).filter(FraudCampaign.domain == domain).first()
    assert camp is not None
    assert camp.status == "ACTIVE"
    assert camp.affected_devices_count == 2
    assert camp.detection_count == 3
