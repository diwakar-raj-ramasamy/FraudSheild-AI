import idna
from typing import Dict, List, Optional, Tuple

PROTECTED_BRANDS: Dict[str, str] = {
    "paypal": "paypal.com",
    "google": "google.com",
    "apple": "apple.com",
    "microsoft": "microsoft.com",
    "amazon": "amazon.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "whatsapp": "whatsapp.com",
    "chase": "chase.com",
    "bankofamerica": "bankofamerica.com",
    "wellsfargo": "wellsfargo.com",
    "citibank": "citi.com",
    "binance": "binance.com",
    "coinbase": "coinbase.com",
    "metamask": "metamask.io",
    "dropbox": "dropbox.com",
    "twitter": "twitter.com",
    "linkedin": "linkedin.com",
    "adobe": "adobe.com",
    "irs": "irs.gov",
    "usps": "usps.com"
}

HOMOGLYPH_MAP: Dict[str, str] = {
    '0': 'o',
    '1': 'l',
    'l': 'i',
    'i': 'l',
    '5': 's',
    '8': 'b',
    '@': 'a',
    'vv': 'w',
    'rn': 'm',
    'cl': 'd',
    # Common Cyrillic lookalikes
    '\u0430': 'a',  # Cyrillic small letter a
    '\u0441': 'c',  # Cyrillic small letter es
    '\u0435': 'e',  # Cyrillic small letter ie
    '\u043e': 'o',  # Cyrillic small letter o
    '\u0440': 'p',  # Cyrillic small letter er
    '\u0455': 's',  # Cyrillic small letter dze
    '\u0443': 'y',  # Cyrillic small letter u
    '\u0445': 'x',  # Cyrillic small letter ha
    '\u0456': 'i',  # Cyrillic small letter byelorussian-ukrainian i
}

def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculates Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]

def normalize_substitutions(text: str) -> str:
    """Replaces common character substitutions and homoglyphs with standard Latin equivalents."""
    normalized = text.lower()
    for lookalike, standard in HOMOGLYPH_MAP.items():
        normalized = normalized.replace(lookalike, standard)
    return normalized

def extract_base_domain(domain: str) -> Tuple[str, str]:
    """
    Extracts second-level domain name and TLD.
    e.g. 'secure.paypa1.co.uk' -> ('paypa1', 'co.uk')
    """
    parts = domain.lower().split('.')
    if len(parts) <= 1:
        return domain, ""
    
    # Handle two-part TLDs like co.uk, com.au, org.uk
    two_part_tlds = {"co.uk", "com.au", "co.nz", "org.uk", "gov.uk", "ac.uk", "com.br", "co.in"}
    if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in two_part_tlds:
        base_name = parts[-3]
        tld = f"{parts[-2]}.{parts[-1]}"
    else:
        base_name = parts[-2]
        tld = parts[-1]
    return base_name, tld

class TyposquattingDetector:
    def __init__(self, brands: Optional[Dict[str, str]] = None):
        self.brands = brands or PROTECTED_BRANDS

    def analyze(self, domain: str) -> Dict[str, any]:
        """
        Analyzes a domain for typosquatting, Punycode tricks, and brand impersonation.
        Returns detection signals and risk contribution.
        """
        results = {
            "is_typosquatting": False,
            "is_punycode": False,
            "decoded_punycode": None,
            "target_brand": None,
            "official_domain": None,
            "technique": None,
            "similarity_score": 0.0,
            "risk_contribution": 0,
            "evidence": []
        }

        domain_clean = domain.lower().strip()
        
        # 1. Punycode check
        if "xn--" in domain_clean:
            results["is_punycode"] = True
            try:
                decoded = idna.decode(domain_clean)
                results["decoded_punycode"] = decoded
                results["evidence"].append(f"Domain uses Punycode encoding: '{domain_clean}' resolves to '{decoded}'")
                domain_clean = decoded.lower()
            except Exception:
                results["evidence"].append(f"Domain contains malformed Punycode: '{domain_clean}'")

        base_name, tld = extract_base_domain(domain_clean)
        normalized_base = normalize_substitutions(base_name)

        # 2. Check against protected brands
        for brand, official_domain in self.brands.items():
            # If it is the legitimate official domain, it's not typosquatting!
            if domain.lower() == official_domain or domain.lower().endswith("." + official_domain):
                return results

            # A. Exact brand match in unauthorized domain (e.g. paypal-security.xyz or paypal-login.net)
            if brand in base_name and official_domain not in domain_clean:
                results["is_typosquatting"] = True
                results["target_brand"] = brand
                results["official_domain"] = official_domain
                results["technique"] = "Combosquatting / Brand Embedding"
                results["risk_contribution"] = 25
                results["evidence"].append(f"Contains brand '{brand}' outside official domain '{official_domain}'")
                return results

            # B. Character substitution / Homoglyph (e.g. 'paypa1', 'g00gle', 'micr0soft')
            if normalized_base == brand:
                results["is_typosquatting"] = True
                results["target_brand"] = brand
                results["official_domain"] = official_domain
                results["technique"] = "Homoglyph / Character Substitution"
                results["risk_contribution"] = 30
                results["evidence"].append(f"Domain '{base_name}' visually impersonates protected brand '{brand}' via character substitution")
                return results

            # C. Levenshtein edit distance check (1 or 2 edits away)
            dist = levenshtein_distance(base_name, brand)
            max_len = max(len(base_name), len(brand))
            similarity = 1.0 - (dist / max_len)

            # High edit distance match for typical brand lengths
            if dist == 1 or (dist == 2 and len(brand) >= 6):
                results["is_typosquatting"] = True
                results["target_brand"] = brand
                results["official_domain"] = official_domain
                results["technique"] = f"Typosquatting (Edit Distance: {dist})"
                results["similarity_score"] = round(similarity * 100, 1)
                results["risk_contribution"] = 25 if dist == 1 else 20
                results["evidence"].append(f"Domain '{base_name}' is suspiciously close to brand '{brand}' (Levenshtein distance: {dist})")
                return results

        return results

typosquatting_detector = TyposquattingDetector()

