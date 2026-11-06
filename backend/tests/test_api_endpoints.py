import pytest
from app.main import health_check
from app.api.blocklist import get_blocklist_version
from app.api.metrics import get_security_overview
from app.core.database import SessionLocal

@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()

def test_health_endpoint():
    res = health_check()
    assert res["status"] == "healthy"
    assert res["service"] == "FraudShield AI"
    assert "version" in res

def test_blocklist_version_endpoint(db):
    from app.models import BlocklistEntry
    if not db.query(BlocklistEntry).filter(BlocklistEntry.is_active == True).first():
        db.add(BlocklistEntry(target="seed-test.com", target_type="DOMAIN", reason="Seed", severity="CRITICAL", added_by="TEST"))
        db.commit()
    res = get_blocklist_version(db=db)
    assert res.version >= 1
    assert len(res.entries) > 0

def test_admin_metrics_overview(db):
    res = get_security_overview(db=db)
    assert "metrics" in res
    assert "charts" in res
    assert res["metrics"]["total_scans"] >= 0
    assert len(res["charts"]["timeline"]) > 0
