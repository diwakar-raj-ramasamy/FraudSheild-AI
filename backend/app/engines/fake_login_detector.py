from typing import Dict, Any, List
from urllib.parse import urlparse
from app.engines.typosquatting_detector import PROTECTED_BRANDS, typosquatting_detector
from app.utils.url_utils import extract_domain

class FakeLoginDetector:
    def analyze(self, current_url: str, dom_signals: Dict[str, Any], page_title: str = "") -> Dict[str, Any]:
        """
        Detects fake login and credential harvesting pages.
        Privacy Guarantee: NEVER inspects or handles actual password or credential text.
        Only metadata regarding field presence and form routing is analyzed.
        """
        results = {
            "is_fake_login": False,
            "has_login_form": False,
            "has_password_input": False,
            "has_otp_harvesting": False,
            "brand_spoofed": None,
            "official_domain": None,
            "cross_domain_submission": False,
            "risk_contribution": 0,
            "evidence": []
        }

        if not dom_signals:
            return results

        current_domain = extract_domain(current_url)
        has_password = dom_signals.get("has_password_field", False)
        has_otp = dom_signals.get("has_otp_field", False)
        form_actions: List[str] = dom_signals.get("form_actions", [])
        claimed_brand = (dom_signals.get("claimed_brand") or "").lower().strip()
        
        results["has_password_input"] = has_password
        results["has_otp_harvesting"] = has_otp

        # Check if page is asking for credentials
        if has_password or has_otp:
            results["has_login_form"] = True

        # Check claimed brand in page title or DOM signal
        title_lower = (page_title or "").lower()
        detected_brand = None
        for brand, official in PROTECTED_BRANDS.items():
            if brand in claimed_brand or brand in title_lower:
                detected_brand = brand
                break

        # Check if the current domain matches the brand's official domain
        if detected_brand:
            official = PROTECTED_BRANDS[detected_brand]
            results["brand_spoofed"] = detected_brand
            results["official_domain"] = official
            
            is_legit = (current_domain == official or current_domain.endswith("." + official))
            
            if not is_legit and (has_password or has_otp):
                results["is_fake_login"] = True
                results["risk_contribution"] += 35
                results["evidence"].append(
                    f"Page presents credential authentication for '{detected_brand}' but is hosted on illegitimate domain '{current_domain}' (Official: '{official}')"
                )

        # Check form actions for suspicious cross-domain posting or untrusted destination
        for action in form_actions:
            if not action or action.startswith("#") or action.startswith("javascript:"):
                if has_password:
                    results["risk_contribution"] += 15
                    results["evidence"].append("Login form uses javascript: or blank action instead of secure server endpoint")
                continue

            parsed_action = urlparse(action)
            action_host = parsed_action.hostname
            if action_host and action_host.lower() != current_domain and not action_host.lower().endswith("." + current_domain):
                results["cross_domain_submission"] = True
                results["risk_contribution"] += 20
                results["evidence"].append(f"Login form submits sensitive credentials cross-domain to external host: '{action_host}'")

        # OTP harvesting on unverified/suspicious domain
        if has_otp:
            results["risk_contribution"] += 15
            results["evidence"].append("Presence of One-Time Password (OTP/2FA) input field detected")

        # If password field is present on an already-flagged typosquatting domain
        typo_res = typosquatting_detector.analyze(current_domain)
        if typo_res["is_typosquatting"] and has_password:
            results["is_fake_login"] = True
            results["risk_contribution"] += 25
            results["evidence"].append(f"Password field active on domain identified as typosquatting ({typo_res['technique']})")

        return results

fake_login_detector = FakeLoginDetector()

