from typing import Dict, Any, List
from app.schemas import FindingItem, XAIFactor, RecommendedAction

class ExplainabilityEngine:
    """
    Translates raw algorithmic metrics, detection rules, and feature vectors
    into transparent, human-understandable XAI summaries.
    Ensures that security decisions are never a 'black box'.
    """

    def generate_summary(
        self,
        risk_score: int,
        classification: str,
        attack_types: List[str],
        findings: List[FindingItem],
        xai_factors: List[XAIFactor]
    ) -> Dict[str, Any]:
        
        # Sort factors by highest weight contribution
        sorted_factors = sorted(xai_factors, key=lambda x: x.weight, reverse=True)
        
        bullet_reasons = []
        for factor in sorted_factors:
            sign = "+" if factor.weight > 0 else ""
            bullet_reasons.append(f"{sign}{factor.weight} {factor.factor} ({factor.rationale})")

        return {
            "headline": f"Risk Score: {risk_score}/100 [{classification}]",
            "primary_threat": attack_types[0] if attack_types else "BENIGN",
            "all_threats": attack_types,
            "score_breakdown": [
                {
                    "factor": f.factor,
                    "points": f.weight,
                    "explanation": f.rationale
                }
                for f in sorted_factors
            ],
            "plain_text_summary": "\n".join(bullet_reasons)
        }

explainability_engine = ExplainabilityEngine()

