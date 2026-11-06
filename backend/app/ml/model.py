import os
import hashlib
import joblib
import numpy as np
from typing import Tuple, List, Dict, Any
from app.ml.feature_extractor import extract_url_features, FEATURE_NAMES
from app.ml.shap_explainer import xai_feature_explainer

MODEL_PATH = os.path.join(os.path.dirname(__file__), "fraud_model.joblib")
EXPECTED_MODEL_SHA256 = os.getenv(
    "FRAUD_MODEL_SHA256",
    "7dc93a904d2f27a740b98392908f504346aeff267e7c541d29a913ccdae277a6"
)

class MLThreatClassifier:
    def __init__(self):
        self.model = None
        self._load_or_init()

    def _load_or_init(self):
        if os.path.exists(MODEL_PATH):
            try:
                # Cryptographic model artifact integrity verification
                with open(MODEL_PATH, "rb") as f:
                    content = f.read()
                    actual_hash = hashlib.sha256(content).hexdigest()

                if EXPECTED_MODEL_SHA256 and actual_hash != EXPECTED_MODEL_SHA256:
                    print(f"SECURITY ALERT: Model artifact hash mismatch! Expected {EXPECTED_MODEL_SHA256}, got {actual_hash}. Refusing to unpickle untrusted model.")
                    self.model = None
                    return

                self.model = joblib.load(MODEL_PATH)
            except Exception:
                self.model = None

    def predict_risk(self, url: str) -> Tuple[float, List[Dict[str, Any]]]:
        """
        Returns (ml_probability_score [0.0 - 1.0], xai_attributions).
        Resilient: works with trained scikit-learn model or calibrated fallback.
        """
        features = extract_url_features(url)
        
        if self.model is not None:
            try:
                X = np.array([features])
                # Predict probability of malicious class (class 1)
                prob = float(self.model.predict_proba(X)[0][1])
                attributions = xai_feature_explainer.explain(features, prob)
                return round(prob, 3), attributions
            except Exception:
                pass

        # Fallback calibrated heuristic weighting for zero-downtime reliability
        score = 0.0
        fv = dict(zip(FEATURE_NAMES, features))
        
        if fv["is_ip"] > 0.5:
            score += 0.35
        if fv["is_suspicious_tld"] > 0.5:
            score += 0.20
        if fv["keyword_count"] >= 2:
            score += 0.25
        elif fv["keyword_count"] == 1:
            score += 0.10
        if fv["url_length"] > 90:
            score += 0.15
        if fv["entropy"] > 4.0:
            score += 0.15
        if fv["subdomain_count"] >= 4:
            score += 0.15

        prob = min(max(score, 0.05), 0.99)
        attributions = xai_feature_explainer.explain(features, prob)
        return round(prob, 3), attributions

ml_threat_classifier = MLThreatClassifier()

