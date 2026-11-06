import os
import sys
# Ensure backend directory is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from app.ml.feature_extractor import extract_url_features

# Curated dataset of benign and phishing URL samples
BENIGN_URLS = [
    "https://www.google.com/search?q=cybersecurity",
    "https://github.com/torvalds/linux",
    "https://en.wikipedia.org/wiki/Transport_Layer_Security",
    "https://stackoverflow.com/questions/tagged/python",
    "https://aws.amazon.com/products/",
    "https://www.apple.com/iphone-15-pro/",
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://fastapi.tiangolo.com/tutorial/",
    "https://news.ycombinator.com/",
    "https://www.nytimes.com/section/technology",
    "https://www.microsoft.com/en-us/windows",
    "https://developer.mozilla.org/en-US/docs/Web/API",
    "https://pypi.org/project/scikit-learn/",
    "https://reddit.com/r/netsec/",
    "https://www.netflix.com/browse",
    "https://www.linkedin.com/feed/",
    "https://medium.com/@infosec/phishing-tactics",
    "https://kaggle.com/datasets",
    "https://huggingface.co/models",
    "https://www.bbc.com/news"
]

MALICIOUS_URLS = [
    "http://192.168.1.105/paypal/account/signin-verify.php?session=92847",
    "http://paypa1-security-verification.xyz/login.html?token=x83j10",
    "https://secure-login.chase.com.fraud-domain.top/auth/login",
    "http://g00gle-account-verification-support.click/recover-account",
    "http://update-kyc-binance-portal.work/verify?uid=82839201",
    "http://metamask-seedphrase-restore.vip/connect-wallet.html",
    "http://netflix-billing-update-required.monster/update-payment.php",
    "http://apple-id-locked-action-required.cf/verify.php?cmd=auth",
    "http://bankofamerica-urgent-unauthorized.bid/signon/screen.action",
    "http://185.220.101.5/invoice_pdf_download.php?token=9382109283",
    "http://microsoft-onedrive-document-review.fit/auth?user=victim",
    "http://irs-tax-refund-claim-portal.country/claim?amount=1200",
    "http://secure.wellsfargo.com.suspicious-host.xyz/auth/login",
    "http://coinbase-two-factor-auth-confirm.party/kyc",
    "http://instagram-copyright-infringement-appeal.cam/appeal.php",
    "http://103.21.244.0/wp-admin/includes/paypal_harvest.php",
    "http://usps-tracking-delivery-reschedule-fee.rest/redelivery.php",
    "http://double-your-btc-giveaway-elon.top/free-crypto",
    "http://dhl-express-package-held-customs.buzz/pay-duty.html",
    "http://citibank-card-suspended-reactivate.kim/portal/auth"
]

def train_and_save_model():
    print("Extracting features for training dataset...")
    X = []
    y = []

    for u in BENIGN_URLS:
        X.append(extract_url_features(u))
        y.append(0)

    for u in MALICIOUS_URLS:
        X.append(extract_url_features(u))
        y.append(1)

    X = np.array(X)
    y = np.array(y)

    print(f"Training RandomForestClassifier on {len(X)} samples...")
    clf = RandomForestClassifier(n_estimators=50, random_state=42, max_depth=5)
    clf.fit(X, y)

    model_path = os.path.join(os.path.dirname(__file__), "fraud_model.joblib")
    joblib.dump(clf, model_path)
    
    import hashlib
    with open(model_path, "rb") as f:
        new_sha256 = hashlib.sha256(f.read()).hexdigest()
        
    print(f"Model saved successfully to {model_path}")
    print(f"Model SHA-256 Digest: {new_sha256}")
    print("If deploying this model, ensure FRAUD_MODEL_SHA256 matches this digest.")
    return model_path

if __name__ == "__main__":
    train_and_save_model()
