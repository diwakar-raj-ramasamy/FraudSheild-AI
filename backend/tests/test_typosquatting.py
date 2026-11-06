import pytest
from app.engines.typosquatting_detector import typosquatting_detector, levenshtein_distance

def test_levenshtein_distance():
    assert levenshtein_distance("paypal", "paypal") == 0
    assert levenshtein_distance("paypal", "paypa1") == 1
    assert levenshtein_distance("google", "g00gle") == 2

def test_typosquatting_detection():
    # Legitimate brand should NOT be flagged
    legit = typosquatting_detector.analyze("paypal.com")
    assert legit["is_typosquatting"] is False

    legit_sub = typosquatting_detector.analyze("auth.paypal.com")
    assert legit_sub["is_typosquatting"] is False

    # Homoglyph character substitution (1 for l)
    fake1 = typosquatting_detector.analyze("paypa1.com")
    assert fake1["is_typosquatting"] is True
    assert fake1["target_brand"] == "paypal"
    assert fake1["risk_contribution"] >= 20

    # Combosquatting / unauthorized brand embedding
    fake2 = typosquatting_detector.analyze("paypal-verify-account.xyz")
    assert fake2["is_typosquatting"] is True
    assert fake2["target_brand"] == "paypal"

    # Punycode check
    puny = typosquatting_detector.analyze("xn--pple-43d.com")
    assert puny["is_punycode"] is True

