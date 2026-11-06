import re
from typing import Dict, List, Set, Any
from urllib.parse import urlparse
from app.utils.url_utils import extract_domain

URL_REGEX = re.compile(
    r'(?:https?://|ftp://|www\.)[^\s<>"\'{}|\\^`\[\]]+',
    re.IGNORECASE
)

EMAIL_REGEX = re.compile(
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
)

IPV4_REGEX = re.compile(
    r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
)

SUSPICIOUS_STRINGS = [
    (r"\b(powershell|cmd\.exe|wscript|cscript|mshta|rundll32)\b", "Command Line Execution Artifact", 25),
    (r"\b(autoopen|workbook_open|document_open)\b", "VBA Auto-Execution Macro Trigger", 35),
    (r"\b(ddeexec|dde\(|cmd\|\'|\=cmd\|\')\b", "DDE (Dynamic Data Exchange) Injection", 40),
    (r"\b(base64_decode|frombase64string|gzipstream)\b", "Obfuscated Binary/Payload Stream", 20),
    (r"\b(eval\(|unescape\(|string\.fromcharcode)\b", "Script Deobfuscation Construct", 25),
    (r"\b(downloadfile|downloaddata|invoke-webrequest|urldownloadtofile)\b", "Payload Stager Download Pattern", 35)
]

def extract_indicators_from_text(text: str) -> Dict[str, Any]:
    """
    Extracts Indicators of Compromise (IOCs): URLs, Domains, IP addresses,
    Email addresses, and suspicious command/obfuscation strings from raw text.
    """
    if not text:
        return {
            "urls": [],
            "domains": [],
            "ips": [],
            "emails": [],
            "suspicious_patterns": []
        }

    # Extract URLs
    raw_urls = URL_REGEX.findall(text)
    urls = list(dict.fromkeys([u.rstrip(".,;!?:") for u in raw_urls]))

    # Extract domains from URLs
    domains: Set[str] = set()
    for u in urls:
        d = extract_domain(u)
        if d:
            domains.add(d)

    # Extract IPs
    raw_ips = IPV4_REGEX.findall(text)
    valid_ips = []
    for ip in raw_ips:
        parts = ip.split('.')
        if all(0 <= int(p) <= 255 for p in parts) and not ip.startswith("127.") and not ip.startswith("0."):
            valid_ips.append(ip)
    ips = list(dict.fromkeys(valid_ips))

    # Extract Emails
    emails = list(dict.fromkeys(EMAIL_REGEX.findall(text)))

    # Match suspicious patterns
    suspicious_patterns = []
    for pattern, name, weight in SUSPICIOUS_STRINGS:
        if re.search(pattern, text, re.IGNORECASE):
            suspicious_patterns.append({
                "pattern": name,
                "weight": weight
            })

    return {
        "urls": urls[:50],  # cap to top 50
        "domains": list(domains)[:50],
        "ips": ips[:30],
        "emails": emails[:30],
        "suspicious_patterns": suspicious_patterns
    }
