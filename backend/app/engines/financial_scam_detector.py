import re
from typing import Dict, Any, List

SCAM_PATTERNS = [
    (r"\b(double\s+your\s+(btc|bitcoin|eth|crypto|investment))\b", "Cryptocurrency Doubling Scheme", 30),
    (r"\b(complete\s+your\s+kyc|update\s+kyc|kyc\s+suspended)\b", "Fake KYC Phishing", 25),
    (r"\b(account\s+(has\s+been\s+)?suspended|account\s+blocked|access\s+restricted)\b", "Urgent Account Suspension Coercion", 20),
    (r"\b(unauthorized\s+transaction|fraudulent\s+activity\s+detected)\b", "Fake Security Alert Social Engineering", 20),
    (r"\b(claim\s+your\s+(refund|tax\s+refund|subsidy|lottery|prize))\b", "Fake Refund / Lottery Lure", 25),
    (r"\b(send\s+(usdt|eth|btc|crypto)\s+to\s+wallet)\b", "Direct Cryptocurrency Solicit", 25),
    (r"\b(connect\s+wallet|secret\s+recovery\s+phrase|seed\s+phrase|private\s+key)\b", "Cryptocurrency Seed Phrase / Wallet Drainer", 35),
    (r"\b(immediate\s+payment\s+required|within\s+24\s+hours\s+or\s+legal\s+action)\b", "High-Pressure Coercive Scam", 20),
    (r"\b(customer\s+support\s+toll\s*free|call\s+microsoft\s+support|call\s+apple\s+support)\b", "Tech Support Scam Lure", 25),
]

class FinancialScamDetector:
    def analyze(self, text_content: str, url: str) -> Dict[str, Any]:
        """
        Analyzes page text or metadata for financial scam & coercive social engineering markers.
        """
        results = {
            "is_scam": False,
            "patterns_matched": [],
            "risk_contribution": 0,
            "evidence": []
        }

        if not text_content:
            return results

        content_lower = text_content.lower()

        for pattern, name, weight in SCAM_PATTERNS:
            if re.search(pattern, content_lower, re.IGNORECASE):
                results["is_scam"] = True
                results["patterns_matched"].append(name)
                results["risk_contribution"] += weight
                results["evidence"].append(f"Detected scam pattern: {name}")

        # Cap total contribution to avoid runaway
        results["risk_contribution"] = min(results["risk_contribution"], 45)
        return results

financial_scam_detector = FinancialScamDetector()

