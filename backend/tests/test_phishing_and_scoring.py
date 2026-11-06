import pytest
from app.engines.fake_login_detector import fake_login_detector
from app.engines.scoring_engine import scoring_engine
from app.engines.malicious_url_detector import malicious_url_detector
from app.engines.financial_scam_detector import financial_scam_detector
from app.engines.xss_indicator_detector import xss_indicator_detector
from app.engines.redirect_analyzer import redirect_analyzer

def test_fake_login_detector():
    # Phishing page spoofing PayPal login
    dom_signals = {
        "has_password_field": True,
        "has_otp_field": True,
        "form_actions": ["http://evil-collector.com/harvest.php"],
        "claimed_brand": "paypal"
    }
    res = fake_login_detector.analyze(
        current_url="http://paypa1-secure-auth.xyz/login.html",
        dom_signals=dom_signals,
        page_title="PayPal - Log In and Sign In"
    )
    assert res["is_fake_login"] is True
    assert res["brand_spoofed"] == "paypal"
    assert res["cross_domain_submission"] is True
    assert res["risk_contribution"] >= 35

def test_financial_scam_detector():
    text = "Double your BTC in 24 hours! Immediate payment required or account suspended. Complete your KYC."
    res = financial_scam_detector.analyze(text_content=text, url="http://crypto-double.top")
    assert res["is_scam"] is True
    assert len(res["patterns_matched"]) >= 2
    assert res["risk_contribution"] >= 30

def test_xss_indicator_detector():
    # URL injection pattern
    res = xss_indicator_detector.analyze("http://example.com/search?q=<script>alert(1)</script>")
    assert res["has_indicator"] is True
    assert "XSS INDICATOR" in res["classification"]

def test_redirect_analyzer():
    chain = [
        "http://bit.ly/fake34",
        "http://tracker.com/r?id=9",
        "http://redirector.net/out",
        "http://suspicious-login.top/account"
    ]
    res = redirect_analyzer.analyze_chain(chain)
    assert res["is_suspicious"] is True
    assert res["hop_count"] == 4
    assert res["cross_domain_hops"] >= 2

def test_scoring_engine_hybrid_aggregation():
    # Assemble realistic multi-signal payload
    url_analysis = {"is_suspicious": True, "risk_contribution": 15, "evidence": ["Suspicious TLD"]}
    typo_analysis = {"is_typosquatting": True, "technique": "Homoglyph", "risk_contribution": 30, "evidence": ["Impersonates PayPal"], "official_domain": "paypal.com"}
    fake_login_analysis = {"is_fake_login": True, "brand_spoofed": "paypal", "risk_contribution": 35, "evidence": ["Password field on spoofed domain"]}
    financial_analysis = {"is_scam": False, "risk_contribution": 0}
    xss_analysis = {"has_indicator": False, "risk_contribution": 0}
    redirect_analysis = {"is_suspicious": False, "risk_contribution": 0}
    infra_data = {"observed_infrastructure_ip": "104.21.1.1"}
    threat_intel = {"overall_match": False, "confidence": "low"}

    result = scoring_engine.calculate(
        url_analysis=url_analysis,
        typo_analysis=typo_analysis,
        fake_login_analysis=fake_login_analysis,
        financial_analysis=financial_analysis,
        xss_analysis=xss_analysis,
        redirect_analysis=redirect_analysis,
        infrastructure_analysis=infra_data,
        threat_intel=threat_intel,
        ml_prediction_score=0.88
    )

    assert result["risk_score"] >= 60
    assert result["classification"] == "CRITICAL"
    assert result["safe_exit_recommended"] is True
    assert "PHISHING" in result["attack_types"]
    assert len(result["xai_factors"]) >= 2

