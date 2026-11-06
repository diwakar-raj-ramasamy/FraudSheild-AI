import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.models import Base, FraudCampaign, AdminAlert, DetectionEvent, URLRecord
from app.services.correlation_service import correlation_service

def test_multi_device_campaign_correlation():
    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )
    Base.metadata.create_all(bind=test_engine)
    TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    db = TestSessionLocal()

    domain = "test-distributed-phish.xyz"
    url = f"http://{domain}/login.php"

    # Device A detects threat
    res1 = correlation_service.record_detection_event(
        raw_url=url,
        device_pseudonym="test-device-alpha-1",
        risk_score=85,
        classification="CRITICAL",
        attack_types=["PHISHING"],
        page_title="Phishing Test",
        referrer="http://email.test",
        db=db
    )
    assert res1["total_detections"] >= 1

    # Device B detects same domain
    res2 = correlation_service.record_detection_event(
        raw_url=url,
        device_pseudonym="test-device-beta-2",
        risk_score=88,
        classification="CRITICAL",
        attack_types=["PHISHING"],
        page_title="Phishing Test",
        referrer="http://webmail.test",
        db=db
    )
    assert res2["unique_devices"] >= 2

    # Device A detects again (total 3 detections, 2 unique devices -> crosses CAMPAIGN threshold)
    res3 = correlation_service.record_detection_event(
        raw_url=url,
        device_pseudonym="test-device-alpha-1",
        risk_score=90,
        classification="CRITICAL",
        attack_types=["PHISHING"],
        page_title="Phishing Test",
        referrer=None,
        db=db
    )
    assert res3["total_detections"] >= 3
    assert res3["campaign_triggered"] is True

    # Verify FraudCampaign record in DB
    camp = db.query(FraudCampaign).filter(FraudCampaign.domain == domain).first()
    assert camp is not None
    assert camp.total_detections >= 3
    assert camp.unique_devices_count >= 2

    # Verify AdminAlert record in DB
    alert = db.query(AdminAlert).filter(AdminAlert.campaign_id == camp.id).first()
    assert alert is not None
    assert "REPEATED FRAUD URL DETECTED" in alert.title

    db.close()
