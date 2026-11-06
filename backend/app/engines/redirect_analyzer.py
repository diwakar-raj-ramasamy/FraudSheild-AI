from typing import Dict, Any, List
from urllib.parse import urlparse
from app.utils.url_utils import extract_domain

class RedirectAnalyzer:
    def analyze_chain(self, hops: List[str]) -> Dict[str, Any]:
        """
        Analyzes a redirect sequence for evasive multi-hop behaviors,
        cross-domain hopping, and suspicious terminus destinations.
        """
        results = {
            "is_suspicious": False,
            "hop_count": len(hops) if hops else 1,
            "unique_domains_count": 0,
            "cross_domain_hops": 0,
            "risk_contribution": 0,
            "evidence": []
        }

        if not hops or len(hops) <= 1:
            return results

        domains = [extract_domain(h) for h in hops]
        unique_domains = list(set(domains))
        results["unique_domains_count"] = len(unique_domains)

        cross_domain = 0
        for i in range(len(domains) - 1):
            if domains[i] != domains[i+1]:
                cross_domain += 1
        results["cross_domain_hops"] = cross_domain

        # 1. Excessive redirects (evasion tactic)
        if len(hops) >= 4:
            results["is_suspicious"] = True
            results["risk_contribution"] += 20
            results["evidence"].append(f"Excessive redirect chain detected ({len(hops)} hops), often employed to evade automated crawlers")
        elif len(hops) >= 3 and cross_domain >= 2:
            results["is_suspicious"] = True
            results["risk_contribution"] += 15
            results["evidence"].append(f"Multi-domain redirect hopping ({cross_domain} cross-domain transitions across {len(hops)} hops)")

        # 2. Final destination checks
        final_url = hops[-1].lower()
        if any(term in final_url for term in ["login", "signin", "auth", "verify", "account"]) and cross_domain > 0:
            results["is_suspicious"] = True
            results["risk_contribution"] += 15
            results["evidence"].append("Redirect chain terminates unexpectedly at an authentication/credential form")

        return results

redirect_analyzer = RedirectAnalyzer()

