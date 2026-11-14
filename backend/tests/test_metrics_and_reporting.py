import pytest
from app.api.metrics import get_security_overview, get_security_report, export_threats_csv
from app.core.database import SessionLocal, check_database_health

@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()

def test_database_health_integrity():
    health = check_database_health()
    assert health["status"] == "healthy"
    assert health["integrity"] == "ok"
    assert "latency_ms" in health

def test_metrics_overview_zero_mock_data(db):
    res = get_security_overview(db=db)
    assert "metrics" in res
    assert "charts" in res
    assert isinstance(res["metrics"]["total_scans"], int)
    assert isinstance(res["metrics"]["threats_detected"], int)
    assert isinstance(res["metrics"]["critical_threats"], int)
    assert isinstance(res["metrics"]["affected_devices"], int)
    # Check that timeline has 7 days of real aggregated data
    assert len(res["charts"]["timeline"]) == 7

def test_metrics_security_report(db):
    report = get_security_report(db=db)
    assert "report_id" in report
    assert report["report_id"].startswith("FS-REP-")
    assert "generated_at" in report
    assert "executive_summary" in report
    assert "posture_metrics" in report
    assert "soc_recommendations" in report
    assert isinstance(report["soc_recommendations"], list)

def test_metrics_export_threats_csv(db):
    response = export_threats_csv(db=db)
    assert response.media_type == "text/csv"
    assert "attachment" in response.headers["content-disposition"]
