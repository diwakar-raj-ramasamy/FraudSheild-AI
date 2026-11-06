import re
import idna
import hashlib
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

def normalize_url(url: str) -> str:
    """
    Normalizes a URL by:
    - Trimming whitespace
    - Adding scheme if missing (defaults to http:// for parsing)
    - Lowercasing host
    - Removing default ports (:80, :443)
    - Decoding Punycode where applicable
    - Normalizing path (collapsing slashes)
    - Sorting query parameters
    - Removing trailing fragment
    """
    url = url.strip()
    if not re.match(r'^[a-zA-Z]+://', url):
        url = "http://" + url
    
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    
    # Strip default ports
    if netloc.endswith(":80") and scheme == "http":
        netloc = netloc[:-3]
    elif netloc.endswith(":443") and scheme == "https":
        netloc = netloc[:-4]

    # Convert Punycode to unicode for internal inspection if needed, or maintain ASCII
    try:
        decoded_host = idna.decode(netloc.split(":")[0])
    except Exception:
        decoded_host = netloc.split(":")[0]

    # Clean path
    path = parsed.path
    if not path:
        path = "/"
    else:
        path = re.sub(r'/+', '/', path)
        if len(path) > 1 and path.endswith("/"):
            path = path.rstrip("/")

    # Sort query params
    query_params = parse_qsl(parsed.query, keep_blank_values=True)
    query_params.sort(key=lambda x: x[0])
    query = urlencode(query_params)

    normalized = urlunparse((scheme, netloc, path, parsed.params, query, ""))
    return normalized

def extract_domain(url: str) -> str:
    """Extracts lowercase domain/hostname without port."""
    if not re.match(r'^[a-zA-Z]+://', url):
        url = "http://" + url
    parsed = urlparse(url)
    hostname = parsed.hostname or parsed.netloc
    if hostname:
        return hostname.lower()
    return url.lower()

def compute_url_hash(url: str) -> str:
    """Generates SHA-256 hash of normalized URL."""
    norm = normalize_url(url)
    return hashlib.sha256(norm.encode('utf-8')).hexdigest()

def is_ip_address(domain: str) -> bool:
    """Checks if the domain is a raw IPv4 or IPv6 address."""
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ipv4_pattern, domain):
        parts = domain.split('.')
        return all(0 <= int(p) <= 255 for p in parts)
    if ":" in domain:
        return True
    return False
