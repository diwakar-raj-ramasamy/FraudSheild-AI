import re
import math
from urllib.parse import urlparse
from app.utils.url_utils import is_ip_address
from app.engines.malicious_url_detector import calculate_entropy, SUSPICIOUS_KEYWORDS, SUSPICIOUS_TLDS

FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "path_length",
    "query_length",
    "entropy",
    "dot_count",
    "hyphen_count",
    "subdomain_count",
    "is_ip",
    "keyword_count",
    "is_suspicious_tld",
    "digit_count",
    "special_char_count"
]

def extract_url_features(url: str) -> list[float]:
    """
    Extracts a fixed-length numeric feature vector from a given URL for ML inference.
    """
    parsed = urlparse(url if "://" in url else "http://" + url)
    hostname = (parsed.hostname or parsed.netloc).lower()
    path = parsed.path.lower()
    query = parsed.query.lower()
    full_url = url.lower()

    # 1. Length features
    url_len = float(len(full_url))
    domain_len = float(len(hostname))
    path_len = float(len(path))
    query_len = float(len(query))

    # 2. Entropy
    entropy = calculate_entropy(hostname.replace('.', ''))

    # 3. Structural counts
    dot_count = float(full_url.count('.'))
    hyphen_count = float(full_url.count('-'))
    subdomain_parts = hostname.split('.')
    subdomain_count = float(len(subdomain_parts))

    # 4. IP address
    is_ip_val = 1.0 if is_ip_address(hostname) else 0.0

    # 5. Keywords
    kw_count = float(sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in path or kw in query))

    # 6. TLD risk
    tld = hostname.split('.')[-1] if '.' in hostname else ""
    suspicious_tld_val = 1.0 if tld in SUSPICIOUS_TLDS else 0.0

    # 7. Digit and special chars
    digit_count = float(sum(1 for c in full_url if c.isdigit()))
    special_chars = float(sum(1 for c in full_url if c in "@%&_=?~/"))

    return [
        url_len,
        domain_len,
        path_len,
        query_len,
        entropy,
        dot_count,
        hyphen_count,
        subdomain_count,
        is_ip_val,
        kw_count,
        suspicious_tld_val,
        digit_count,
        special_chars
    ]

