import re
import math
from typing import Dict, List, Any
from urllib.parse import urlparse
from app.utils.url_utils import is_ip_address

SUSPICIOUS_KEYWORDS = [
    "signin", "login", "logon", "verify", "verification", "account", "update",
    "security", "secure", "authenticate", "auth", "confirm", "recovery", "password",
    "credential", "banking", "wallet", "invoice", "refund", "suspend", "kyc",
    "billing", "payment", "support", "unauthorized", "urgent"
]

SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "cf", "gq", "work", "fit", "click", "rest", "surf",
    "country", "kim", "party", "bid", "vip", "buzz", "cc", "monster", "cam"
}

def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy of a string."""
    if not text:
        return 0.0
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

class MaliciousURLDetector:
    def analyze(self, url: str) -> Dict[str, Any]:
        results = {
            "is_suspicious": False,
            "risk_contribution": 0,
            "evidence": [],
            "features": {}
        }

        parsed = urlparse(url)
        hostname = (parsed.hostname or parsed.netloc).lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
        full_url = url.lower()

        # 1. IP address in hostname
        if is_ip_address(hostname):
            results["is_suspicious"] = True
            results["risk_contribution"] += 25
            results["evidence"].append(f"Hostname uses raw IP address instead of domain name: {hostname}")

        # 2. Suspicious TLD
        tld = hostname.split('.')[-1] if '.' in hostname else ""
        if tld in SUSPICIOUS_TLDS:
            results["is_suspicious"] = True
            results["risk_contribution"] += 15
            results["evidence"].append(f"Domain uses high-abuse/suspicious top-level domain (. {tld})")

        # 3. Excessive subdomains (e.g. secure.login.paypal.account.example.com)
        subdomain_parts = hostname.split('.')
        if len(subdomain_parts) >= 4 and not is_ip_address(hostname):
            results["is_suspicious"] = True
            results["risk_contribution"] += 15
            results["evidence"].append(f"Excessive subdomain depth ({len(subdomain_parts)} levels) often used to disguise real destination")

        # 4. Excessive URL length
        if len(url) > 120:
            results["is_suspicious"] = True
            results["risk_contribution"] += 15
            results["evidence"].append(f"Extremely long URL ({len(url)} characters) typical of obfuscated payloads")
        elif len(url) > 75:
            results["risk_contribution"] += 5
            results["evidence"].append(f"Unusually long URL ({len(url)} characters)")

        # 5. Shannon entropy (detects DGA / randomly generated domains)
        domain_entropy = calculate_entropy(hostname.replace('.', ''))
        if domain_entropy > 4.2 and len(hostname) > 12:
            results["is_suspicious"] = True
            results["risk_contribution"] += 15
            results["evidence"].append(f"High domain character entropy ({domain_entropy:.2f}), suggesting randomly generated / DGA hostname")

        # 6. Suspicious credential keywords in path or query
        matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in path or kw in query]
        if len(matched_keywords) >= 2:
            results["is_suspicious"] = True
            results["risk_contribution"] += 20
            results["evidence"].append(f"URL path/query contains multiple high-risk credential keywords: {', '.join(matched_keywords)}")
        elif len(matched_keywords) == 1:
            results["risk_contribution"] += 8
            results["evidence"].append(f"URL contains security-sensitive keyword: '{matched_keywords[0]}'")

        # 7. Obfuscation techniques (@ symbol, excessive encoding)
        if "@" in parsed.netloc:
            results["is_suspicious"] = True
            results["risk_contribution"] += 25
            results["evidence"].append("URL uses '@' symbol in authority section to deceive users regarding true destination")
        if "%25" in full_url or full_url.count("%") > 5:
            results["risk_contribution"] += 10
            results["evidence"].append("URL contains heavy percentage/hex encoding or double-encoding")

        results["features"] = {
            "length": len(url),
            "is_ip": is_ip_address(hostname),
            "subdomain_count": len(subdomain_parts),
            "domain_entropy": round(domain_entropy, 2),
            "tld": tld,
            "keyword_matches": len(matched_keywords)
        }

        return results

malicious_url_detector = MaliciousURLDetector()

