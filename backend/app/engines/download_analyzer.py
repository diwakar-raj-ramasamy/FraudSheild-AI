import os
from typing import Dict, Any, List

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".hta", ".cpl", ".msi", ".msp", ".jar", ".iso", ".img",
    ".lnk", ".pif", ".reg"
}

DOUBLE_EXTENSION_PATTERNS = [
    ".pdf.exe", ".pdf.scr", ".docx.exe", ".xlsx.exe", ".jpg.exe", ".png.exe",
    ".doc.scr", ".xls.scr", ".zip.exe", ".rar.exe", ".txt.vbs", ".pdf.bat"
]

class DownloadAnalyzer:
    def analyze(self, filename: str, mime_type: str = "", download_url: str = "") -> Dict[str, Any]:
        """
        Statically evaluates downloaded file metadata to identify high-risk binaries,
        spoofed extensions, and dangerous wrappers.
        Strict Safety Rule: Never executes or interprets any binary.
        """
        results = {
            "is_dangerous": False,
            "risk_score": 0,
            "classification": "SAFE",
            "reasons": [],
            "evidence": []
        }

        clean_name = filename.strip().lower()
        base_name, ext = os.path.splitext(clean_name)

        # 1. Double extension detection
        for pattern in DOUBLE_EXTENSION_PATTERNS:
            if clean_name.endswith(pattern):
                results["is_dangerous"] = True
                results["risk_score"] = 95
                results["classification"] = "CRITICAL"
                results["reasons"].append(f"Deceptive double-extension detected ({pattern}) attempting to disguise executable")
                results["evidence"].append(f"File '{filename}' uses dual extensions to conceal real executable nature")
                return results

        # Check for multiple dots ending with an executable
        parts = clean_name.split('.')
        if len(parts) > 2 and f".{parts[-1]}" in DANGEROUS_EXTENSIONS:
            results["is_dangerous"] = True
            results["risk_score"] = 90
            results["classification"] = "CRITICAL"
            results["reasons"].append(f"Multiple-extension masking detected with dangerous executable payload (.{parts[-1]})")
            results["evidence"].append(f"Trailing extension '.{parts[-1]}' follows earlier decoy extension '.{parts[-2]}'")
            return results

        # 2. Standalone dangerous extension
        if ext in DANGEROUS_EXTENSIONS:
            results["is_dangerous"] = True
            results["risk_score"] = 75
            results["classification"] = "CRITICAL"
            results["reasons"].append(f"Dangerous executable/script file type detected ({ext})")
            results["evidence"].append(f"File extension '{ext}' allows arbitrary code execution if launched by user")

        # 3. MIME type discrepancy
        mime_clean = (mime_type or "").lower().strip()
        if mime_clean:
            if "application/x-msdownload" in mime_clean or "application/x-dosexec" in mime_clean:
                if ext not in [".exe", ".dll"]:
                    results["is_dangerous"] = True
                    results["risk_score"] = 90
                    results["classification"] = "CRITICAL"
                    results["reasons"].append(f"MIME type indicates Windows executable, but extension is '{ext}'")

            if ("pdf" in ext and "pdf" not in mime_clean and "octet-stream" not in mime_clean) or \
               ("doc" in ext and "word" not in mime_clean and "officedocument" not in mime_clean and "octet-stream" not in mime_clean):
                results["risk_score"] = max(results["risk_score"], 45)
                results["reasons"].append(f"MIME type mismatch: extension is '{ext}' but Content-Type is '{mime_clean}'")

        if results["risk_score"] >= 60:
            results["classification"] = "CRITICAL"
        elif results["risk_score"] >= 25:
            results["classification"] = "CAUTION"
        else:
            results["classification"] = "SAFE"

        return results

download_analyzer = DownloadAnalyzer()

