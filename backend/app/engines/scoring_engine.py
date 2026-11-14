from typing import Dict, Any, List, Tuple
from app.core.config import settings
from app.schemas import FindingItem, XAIFactor, RecommendedAction

class ScoringEngine:
    """
    FraudShield AI Composite Risk Scoring Engine:
    Calculates final composite threat score using the documented formula:
      Final Score = min(100, 0.45 * Heuristic Score + 0.35 * ML Score + 0.20 * Intelligence Score)
    with deterministic hard override conditions for verified critical hazards (Score >= 95).
    """

    def __init__(self):
        # Component weights in documented composite formula
        self.WEIGHT_HEURISTIC_RATIO = 0.45
        self.WEIGHT_ML_RATIO = 0.35
        self.WEIGHT_INTEL_RATIO = 0.20

        # Heuristic sub-engine point contribution limits
        self.PTS_FAKE_LOGIN = 45
        self.PTS_TYPOSQUATTING = 35
        self.PTS_URL_SYNTAX = 25
        self.PTS_FINANCIAL_SCAM = 35
        self.PTS_REDIRECT = 25
        self.PTS_XSS = 20
        self.PTS_INFRASTRUCTURE = 25

    def calculate(
        self,
        url_analysis: Dict[str, Any],
        typo_analysis: Dict[str, Any],
        fake_login_analysis: Dict[str, Any],
        financial_analysis: Dict[str, Any],
        xss_analysis: Dict[str, Any],
        redirect_analysis: Dict[str, Any],
        infrastructure_analysis: Dict[str, Any],
        threat_intel: Dict[str, Any],
        ml_prediction_score: float = 0.0,
        is_blocklist_hit: bool = False,
        blocklist_reason: str = ""
    ) -> Dict[str, Any]:
        """
        Combines rule-based detection signals, machine learning risk probability,
        and threat intelligence into an aggregated hybrid score (0–100) with hard overrides
        and transparent feature contribution point accounting.
        """
        findings: List[FindingItem] = []
        xai_factors: List[XAIFactor] = []
        attack_types: List[str] = []
        recommended_actions: List[RecommendedAction] = []

        raw_heuristic_score = 0
        intel_score = 0
        hard_override = False
        override_reason = None

        # --- 0. BLOCKLIST OVERRIDE ---
        if is_blocklist_hit:
            hard_override = True
            override_reason = f"Target verified in Centralized Threat Blocklist: {blocklist_reason}"
            attack_types.append("BLOCKLISTED_THREAT")
            findings.append(FindingItem(
                rule_id="RULE-BLK-01",
                title="Centralized Threat Blocklist Match",
                description=f"Destination matches confirmed blocked target: {blocklist_reason}",
                severity="CRITICAL",
                contribution=100
            ))
            xai_factors.append(XAIFactor(
                factor="Global Blocklist Confirmation",
                weight=100,
                rationale="Matches known verified malicious destination recorded in global threat defense database"
            ))

        # --- 1. THREAT INTELLIGENCE COMPONENT (20% Weight) ---
        if threat_intel.get("overall_match"):
            conf = threat_intel.get("confidence", "low")
            if conf == "high":
                intel_score = 100
                hard_override = True
                override_reason = "Confirmed positive match in authoritative threat intelligence feed"
            elif conf == "medium":
                intel_score = 75
            else:
                intel_score = 50

            attack_types.append("KNOWN_MALICIOUS_URL")
            findings.append(FindingItem(
                rule_id="RULE-TI-01",
                title="Threat Intelligence Match",
                description=f"Flagged by external threat intelligence providers ({', '.join(threat_intel.get('matched_providers', []))})",
                severity="CRITICAL",
                contribution=int(intel_score * self.WEIGHT_INTEL_RATIO)
            ))
            xai_factors.append(XAIFactor(
                factor="External Threat Intel Match",
                weight=int(intel_score * self.WEIGHT_INTEL_RATIO),
                rationale=f"Reported by external threat feeds with {conf} confidence"
            ))

        # --- 2. HEURISTIC: FAKE LOGIN & CREDENTIAL HARVESTING ---
        if fake_login_analysis.get("is_fake_login"):
            points = self.PTS_FAKE_LOGIN + (15 if fake_login_analysis.get("cross_domain_submission") else 0)
            raw_heuristic_score += points
            attack_types.append("FAKE_LOGIN_PAGE")
            attack_types.append("PHISHING")
            for ev in fake_login_analysis.get("evidence", []):
                findings.append(FindingItem(
                    rule_id="RULE-FL-01",
                    title="Suspicious Credential Collection Form",
                    description=ev,
                    severity="CRITICAL",
                    contribution=points
                ))
            xai_factors.append(XAIFactor(
                factor="Impersonated Credential Harvesting Form",
                weight=int(points * self.WEIGHT_HEURISTIC_RATIO),
                rationale="Detected authentication inputs on a domain spoofing official services"
            ))
            # Hard override if both brand spoofing and password form coincide
            if fake_login_analysis.get("brand_spoofed") or typo_analysis.get("is_typosquatting"):
                hard_override = True
                target_brand = fake_login_analysis.get("brand_spoofed") or typo_analysis.get("spoofed_brand") or "monitored brand"
                override_reason = f"Credential form impersonating {str(target_brand).upper()}"

        elif fake_login_analysis.get("has_login_form"):
            raw_heuristic_score += 15
            findings.append(FindingItem(
                rule_id="RULE-FL-02",
                title="Authentication Form Detected",
                description="Webpage contains login or password entry fields",
                severity="LOW",
                contribution=15
            ))

        # --- 3. HEURISTIC: TYPOSQUATTING & BRAND IMPERSONATION ---
        if typo_analysis.get("is_typosquatting"):
            points = typo_analysis.get("risk_contribution", self.PTS_TYPOSQUATTING)
            raw_heuristic_score += points
            attack_types.append("TYPOSQUATTING")
            for ev in typo_analysis.get("evidence", []):
                findings.append(FindingItem(
                    rule_id="RULE-TS-01",
                    title=f"Brand Impersonation ({typo_analysis.get('technique', 'Typosquatting')})",
                    description=ev,
                    severity="HIGH",
                    contribution=points
                ))
            xai_factors.append(XAIFactor(
                factor=f"Typosquatting ({typo_analysis.get('technique')})",
                weight=int(points * self.WEIGHT_HEURISTIC_RATIO),
                rationale=f"Visual lookalike or brand embedding mimicking {typo_analysis.get('official_domain')}"
            ))

        # --- 4. HEURISTIC: MALICIOUS URL STRUCTURE ---
        if url_analysis.get("is_suspicious"):
            points = min(url_analysis.get("risk_contribution", self.PTS_URL_SYNTAX), 30)
            raw_heuristic_score += points
            attack_types.append("MALICIOUS_URL_SYNTAX")
            for ev in url_analysis.get("evidence", []):
                findings.append(FindingItem(
                    rule_id="RULE-URL-01",
                    title="Suspicious URL Architecture",
                    description=ev,
                    severity="MEDIUM",
                    contribution=points
                ))
            xai_factors.append(XAIFactor(
                factor="Heuristic URL Syntax Anomaly",
                weight=int(points * self.WEIGHT_HEURISTIC_RATIO),
                rationale="Structural anomalies such as raw IP hostname, excessive length, or credential keywords"
            ))

        # --- 5. HEURISTIC: FINANCIAL SCAM & SOCIAL ENGINEERING ---
        if financial_analysis.get("is_scam"):
            points = financial_analysis.get("risk_contribution", self.PTS_FINANCIAL_SCAM)
            raw_heuristic_score += points
            attack_types.append("FINANCIAL_SCAM")
            for ev in financial_analysis.get("evidence", []):
                findings.append(FindingItem(
                    rule_id="RULE-FIN-01",
                    title="Financial Scam Indicators",
                    description=ev,
                    severity="HIGH",
                    contribution=points
                ))
            xai_factors.append(XAIFactor(
                factor="Financial Scam Social Engineering",
                weight=int(points * self.WEIGHT_HEURISTIC_RATIO),
                rationale="Presence of high-pressure fraudulent patterns (e.g. crypto doubling, urgent KYC suspend)"
            ))

        # --- 6. HEURISTIC: MALICIOUS REDIRECT BEHAVIOR ---
        if redirect_analysis.get("is_suspicious"):
            points = redirect_analysis.get("risk_contribution", self.PTS_REDIRECT)
            raw_heuristic_score += points
            attack_types.append("MALICIOUS_REDIRECT")
            for ev in redirect_analysis.get("evidence", []):
                findings.append(FindingItem(
                    rule_id="RULE-RED-01",
                    title="Evasive Redirect Chain",
                    description=ev,
                    severity="MEDIUM",
                    contribution=points
                ))
            xai_factors.append(XAIFactor(
                factor="Multi-Hop Redirect Chain",
                weight=int(points * self.WEIGHT_HEURISTIC_RATIO),
                rationale="Complex or evasive redirect path preceding current landing page"
            ))

        # --- 7. HEURISTIC: XSS INDICATORS ---
        if xss_analysis.get("has_indicator"):
            points = xss_analysis.get("risk_contribution", self.PTS_XSS)
            raw_heuristic_score += points
            attack_types.append("XSS_INDICATOR")
            findings.append(FindingItem(
                rule_id="RULE-XSS-01",
                title=f"Potential Script Injection Indicator ({xss_analysis.get('classification')})",
                description="; ".join(xss_analysis.get("evidence", [])),
                severity="MEDIUM" if "HIGH" not in xss_analysis.get("classification") else "HIGH",
                contribution=points
            ))
            xai_factors.append(XAIFactor(
                factor=f"Script Injection Marker ({xss_analysis.get('classification')})",
                weight=int(points * self.WEIGHT_HEURISTIC_RATIO),
                rationale="Presence of injection patterns or unsafe DOM sink manipulation without verified exploitation"
            ))

        # --- 8. HEURISTIC: INFRASTRUCTURE & SSRF RISK ---
        if infrastructure_analysis.get("is_restricted_network"):
            points = self.PTS_INFRASTRUCTURE
            raw_heuristic_score += points
            attack_types.append("RESTRICTED_INFRASTRUCTURE")
            findings.append(FindingItem(
                rule_id="RULE-INFRA-01",
                title="Restricted Internal Infrastructure Target",
                description=infrastructure_analysis.get("forensic_note", "Target resolves to a restricted loopback, private, or metadata IP"),
                severity="HIGH",
                contribution=points
            ))
            xai_factors.append(XAIFactor(
                factor="Restricted Infrastructure Target",
                weight=int(points * self.WEIGHT_HEURISTIC_RATIO),
                rationale="Target resolves to internal or cloud metadata network infrastructure"
            ))

        # --- 9. COMPOSITE HYBRID SCORE CALCULATION ---
        # Formula: Final Score = min(100, 0.45 * Heuristic + 0.35 * ML + 0.20 * Intel)
        norm_heuristic = min(max(raw_heuristic_score, 0), 100)
        norm_ml = min(max(ml_prediction_score * 100.0, 0.0), 100.0)
        norm_intel = min(max(float(intel_score), 0.0), 100.0)

        composite_score = round(
            (self.WEIGHT_HEURISTIC_RATIO * norm_heuristic) +
            (self.WEIGHT_ML_RATIO * norm_ml) +
            (self.WEIGHT_INTEL_RATIO * norm_intel)
        )

        # Append ML Factor attribution if probability is substantial
        if norm_ml >= 40:
            ml_points = round(self.WEIGHT_ML_RATIO * norm_ml)
            xai_factors.append(XAIFactor(
                factor="Machine Learning Classifier Model",
                weight=ml_points,
                rationale=f"Model classified lexical & structural URL vectors with {ml_prediction_score:.0%} threat probability"
            ))

        # --- 9. FINAL SCORE AGGREGATION & OVERRIDE HANDLING ---
        if is_blocklist_hit:
            final_score = 100
        elif hard_override:
            final_score = min(max(composite_score, 95), 100)
        else:
            final_score = min(max(composite_score, 0), 100)

        # Classification mapping (CRITICAL >= 60, CAUTION >= 25, SAFE < 25)
        if final_score >= settings.RISK_THRESHOLD_CRITICAL:
            classification = "CRITICAL"
        elif final_score >= settings.RISK_THRESHOLD_SAFE:
            classification = "CAUTION"
        else:
            classification = "SAFE"

        # Deduplicate attack types
        unique_attack_types = list(dict.fromkeys(attack_types))
        if not unique_attack_types and classification != "SAFE":
            unique_attack_types.append("SUSPICIOUS_ACTIVITY")

        # --- 10. GENERATE ACTIONABLE SAFETY RECOMMENDATIONS ---
        if classification == "CRITICAL":
            recommended_actions.append(RecommendedAction(
                action="LEAVE THIS WEBSITE IMMEDIATELY",
                urgency="IMMEDIATE",
                description="Do not interact with the page. Use the FraudShield Safe Exit button to depart immediately."
            ))
            if "PHISHING" in unique_attack_types or "FAKE_LOGIN_PAGE" in unique_attack_types:
                recommended_actions.append(RecommendedAction(
                    action="DO NOT ENTER CREDENTIALS",
                    urgency="IMMEDIATE",
                    description="Never enter passwords, PINs, or One-Time Passwords (OTPs) on this page."
                ))
            if "FINANCIAL_SCAM" in unique_attack_types:
                recommended_actions.append(RecommendedAction(
                    action="DO NOT AUTHORIZE TRANSACTIONS",
                    urgency="IMMEDIATE",
                    description="Do not transfer funds, share bank numbers, or connect crypto wallets."
                ))
        elif classification == "CAUTION":
            recommended_actions.append(RecommendedAction(
                action="PROCEED WITH CAUTION",
                urgency="RECOMMENDED",
                description="Verify the destination website URL manually before sharing any personal information."
            ))
        else:
            recommended_actions.append(RecommendedAction(
                action="STANDARD BROWSING",
                urgency="ADVISORY",
                description="No malicious indicators observed during real-time multi-signal analysis."
            ))

        return {
            "risk_score": final_score,
            "classification": classification,
            "hard_override": hard_override,
            "override_reason": override_reason,
            "attack_types": unique_attack_types,
            "findings": findings,
            "xai_factors": xai_factors,
            "recommended_actions": recommended_actions,
            "safe_exit_recommended": (classification == "CRITICAL")
        }

scoring_engine = ScoringEngine()
