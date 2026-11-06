from typing import Dict, Any, List
from app.schemas import XAIFactor

class FileScoringEngine:
    def score_analysis(self, raw_analysis: Dict[str, Any], file_type: str) -> Dict[str, Any]:
        """
        Aggregates structural indicators, text IOCs, and suspicious patterns
        into a finalized File Risk Score (0-100) with XAI explanations.
        """
        structural = raw_analysis.get("structural_indicators", [])
        iocs = raw_analysis.get("iocs", {})
        suspicious_patterns = iocs.get("suspicious_patterns", [])
        urls = iocs.get("urls", [])
        ips = iocs.get("ips", [])

        score = 0
        xai_factors: List[XAIFactor] = []

        # 1. Structural risks (macros, scripts, launch commands, DDE injection)
        for s in structural:
            sev = s.get("severity", "MEDIUM")
            if sev == "CRITICAL":
                pts = 40
            elif sev == "HIGH":
                pts = 25
            else:
                pts = 15
            score += pts
            xai_factors.append(XAIFactor(
                factor=s.get("type", "STRUCTURAL_RISK"),
                weight=pts,
                rationale=s.get("description", "Structural risk detected")
            ))

        # 2. Suspicious string / script patterns
        for p in suspicious_patterns:
            pts = min(p.get("weight", 20), 30)
            score += pts
            xai_factors.append(XAIFactor(
                factor=p.get("pattern", "Command String Artifact"),
                weight=pts,
                rationale=f"Found artifact pattern in document body: {p.get('pattern')}"
            ))

        # 3. URL count & IP presence
        if len(urls) > 5:
            score += 15
            xai_factors.append(XAIFactor(
                factor="High Outbound URL Density",
                weight=15,
                rationale=f"Document embeds {len(urls)} external web links"
            ))
        elif len(urls) > 0:
            score += 5
            xai_factors.append(XAIFactor(
                factor="External URL Links",
                weight=5,
                rationale=f"Document contains {len(urls)} external links"
            ))

        if len(ips) > 0:
            score += 15
            xai_factors.append(XAIFactor(
                factor="Hardcoded IPv4 Addresses",
                weight=15,
                rationale=f"Contains {len(ips)} raw IP addresses ({', '.join(ips[:3])})"
            ))

        final_score = min(max(score, 0), 100)
        
        if final_score >= 60:
            classification = "CRITICAL"
        elif final_score >= 25:
            classification = "CAUTION"
        else:
            classification = "SAFE"

        # If no risk factors detected
        if not xai_factors:
            xai_factors.append(XAIFactor(
                factor="No Malicious Indicators Detected",
                weight=0,
                rationale="Clean static extraction: No embedded macros, launch actions, or malicious URL payloads found."
            ))

        return {
            "risk_score": final_score,
            "classification": classification,
            "xai_factors": xai_factors
        }

file_scoring_engine = FileScoringEngine()

