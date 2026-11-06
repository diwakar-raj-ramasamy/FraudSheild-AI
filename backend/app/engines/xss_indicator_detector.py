import re
from typing import Dict, Any, List

XSS_URL_PATTERNS = [
    (r"<script[\s>]", "Raw script tag in parameter", "HIGH"),
    (r"javascript:\s*", "javascript: URI scheme injection", "HIGH"),
    (r"onerror\s*=", "Inline event handler onerror", "HIGH"),
    (r"onload\s*=", "Inline event handler onload", "HIGH"),
    (r"onclick\s*=", "Inline event handler onclick", "MEDIUM"),
    (r"onmouseover\s*=", "Inline event handler onmouseover", "MEDIUM"),
    (r"<svg[\s/].*?onload", "SVG onload vector", "HIGH"),
    (r"<img[\s/].*?onerror", "Image onerror vector", "HIGH"),
    (r"document\.cookie", "DOM cookie access attempt", "HIGH"),
    (r"document\.location", "DOM redirection injection", "MEDIUM"),
    (r"eval\(", "Dynamic script evaluation sink", "HIGH"),
    (r"String\.fromCharCode", "Obfuscated character vector", "HIGH"),
]

class XSSIndicatorDetector:
    def analyze(self, url: str, dom_signals: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Analyzes URL parameters and DOM characteristics for potential Cross-Site Scripting indicators.
        Strict Forensics Rule: Flags indicator levels (LOW, MEDIUM, HIGH) without claiming confirmed exploitation.
        """
        results = {
            "has_indicator": False,
            "classification": "NO XSS INDICATOR",
            "risk_contribution": 0,
            "indicators": [],
            "evidence": []
        }

        matched_high = 0
        matched_med = 0

        # 1. URL Parameter Inspection
        for pattern, name, severity in XSS_URL_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                results["has_indicator"] = True
                results["indicators"].append({"name": name, "severity": severity, "source": "URL_PARAMETER"})
                results["evidence"].append(f"Suspicious payload marker in URL: {name}")
                if severity == "HIGH":
                    matched_high += 1
                else:
                    matched_med += 1

        # 2. DOM Signals Inspection (if provided by browser content script)
        if dom_signals:
            suspicious_inline = dom_signals.get("suspicious_inline_scripts", 0)
            unsafe_dom_sinks = dom_signals.get("unsafe_dom_sinks", 0)
            eval_occurrences = dom_signals.get("eval_occurrences", 0)

            if eval_occurrences > 0:
                results["has_indicator"] = True
                matched_high += 1
                results["indicators"].append({"name": "Dynamic Code Evaluation (eval/Function)", "severity": "HIGH", "source": "DOM"})
                results["evidence"].append(f"Detected {eval_occurrences} dynamic eval() script execution sinks")

            if unsafe_dom_sinks > 0:
                results["has_indicator"] = True
                matched_med += 1
                results["indicators"].append({"name": "Unsafe DOM Sinks (innerHTML / outerHTML)", "severity": "MEDIUM", "source": "DOM"})
                results["evidence"].append(f"Detected {unsafe_dom_sinks} unsafe innerHTML sink assignments with external input")

            if suspicious_inline > 2:
                results["has_indicator"] = True
                matched_med += 1
                results["indicators"].append({"name": "Excessive Obfuscated Inline Scripts", "severity": "MEDIUM", "source": "DOM"})
                results["evidence"].append(f"Found {suspicious_inline} obfuscated inline script blocks")

        # Classify indicator severity
        if matched_high >= 2 or (matched_high >= 1 and matched_med >= 1):
            results["classification"] = "HIGH XSS INDICATOR"
            results["risk_contribution"] = 25
        elif matched_high == 1 or matched_med >= 2:
            results["classification"] = "MEDIUM XSS INDICATOR"
            results["risk_contribution"] = 15
        elif matched_med == 1:
            results["classification"] = "LOW XSS INDICATOR"
            results["risk_contribution"] = 8
        else:
            results["classification"] = "NO XSS INDICATOR"
            results["risk_contribution"] = 0

        return results

xss_indicator_detector = XSSIndicatorDetector()

