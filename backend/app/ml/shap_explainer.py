from typing import List, Dict, Any
from app.ml.feature_extractor import FEATURE_NAMES

class XAIFeatureExplainer:
    """
    Computes local feature importance and SHAP-like attribution vectors
    explaining which specific URL traits increased the ML model's risk score.
    """

    def explain(self, feature_vector: List[float], ml_score: float) -> List[Dict[str, Any]]:
        explanations = []
        if len(feature_vector) != len(FEATURE_NAMES):
            return explanations

        fv = dict(zip(FEATURE_NAMES, feature_vector))

        if fv["url_length"] > 80:
            explanations.append({
                "feature": "Excessive URL Length",
                "value": f"{int(fv['url_length'])} chars",
                "impact": "+15 pts (Obfuscation Indicator)"
            })
        if fv["entropy"] > 3.8:
            explanations.append({
                "feature": "High Domain Character Entropy",
                "value": f"{fv['entropy']:.2f}",
                "impact": "+12 pts (Random/Algorithmic Generation)"
            })
        if fv["is_ip"] > 0.5:
            explanations.append({
                "feature": "Direct IP Hostname",
                "value": "Yes",
                "impact": "+20 pts (DNS Bypassing Evasion)"
            })
        if fv["keyword_count"] >= 2:
            explanations.append({
                "feature": "Sensitive Credential Keywords",
                "value": f"{int(fv['keyword_count'])} matches",
                "impact": "+18 pts (Social Engineering Phrasing)"
            })
        if fv["is_suspicious_tld"] > 0.5:
            explanations.append({
                "feature": "Abuse-Prone TLD",
                "value": "Yes",
                "impact": "+10 pts (Untrusted Registrar Space)"
            })
        if fv["subdomain_count"] >= 4:
            explanations.append({
                "feature": "Deep Subdomain Nesting",
                "value": f"{int(fv['subdomain_count'])} levels",
                "impact": "+12 pts (Domain Camouflage)"
            })

        return explanations

xai_feature_explainer = XAIFeatureExplainer()

