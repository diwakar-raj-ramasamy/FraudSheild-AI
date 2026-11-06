"""
FraudShield AI - Secret and Credential Scanner
Scans the codebase for hardcoded secrets, private keys, API credentials, and tokens.
Excludes safe paths (.git, node_modules, venv, test mocks, .env.example).
"""

import os
import re
import sys
from pathlib import Path

# High-risk credential patterns
PATTERNS = [
    ("Private Key Header", re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub Personal Access Token", re.compile(r"\bghp_[0-9a-zA-Z]{36}\b")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Slack Webhook URL", re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+")),
    ("Hardcoded Database URI with Password", re.compile(r"(postgres|postgresql|mysql|mongodb)://[a-zA-Z0-9_]+:(?!(?:password|changeme|\$\{))[a-zA-Z0-9_\-\.\$\!\#\%]{3,}@")),
    ("Hardcoded JWT / Secret assignment", re.compile(r"""(?i)(jwt_secret_key|secret_key|admin_password)\s*=\s*["'](?![^"']*(?:change-me|changeme|testsecret|devsecret|change_this|your-|YOUR_|placeholder|fake|REPLACE))[a-zA-Z0-9_\-!@#$%^&*]{16,}["']""")),
    ("VirusTotal Hardcoded Key", re.compile(r"""(?i)(virustotal_api_key|vt_api_key)\s*=\s*["'][a-fA-F0-9]{64}["']""")),
]

EXCLUDED_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", ".pytest_cache"
}

EXCLUDED_FILES = {
    ".env.example", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"
}

def scan_repository(root_dir: Path):
    findings = []
    scanned_count = 0

    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Exclude directories in-place
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]

        for filename in filenames:
            if filename in EXCLUDED_FILES:
                continue

            file_path = Path(dirpath) / filename
            ext = file_path.suffix.lower()
            if ext in {".png", ".jpg", ".jpeg", ".ico", ".bin", ".joblib", ".pkl", ".woff", ".woff2", ".ttf", ".eot"}:
                continue

            scanned_count += 1
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            # Don't flag this script itself
            if "FraudShield AI - Secret and Credential Scanner" in content:
                continue

            for label, pattern in PATTERNS:
                matches = pattern.finditer(content)
                for m in matches:
                    line_no = content[:m.start()].count("\n") + 1
                    # Redact matched text
                    matched_snippet = m.group(0)
                    if len(matched_snippet) > 8:
                        redacted = matched_snippet[:4] + "*" * (len(matched_snippet) - 8) + matched_snippet[-4:]
                    else:
                        redacted = "****"

                    findings.append({
                        "file": str(file_path.relative_to(root_dir)),
                        "line": line_no,
                        "type": label,
                        "match": redacted
                    })

    return scanned_count, findings

def main():
    root_dir = Path(__file__).resolve().parent.parent.parent
    print(f"Scanning codebase at: {root_dir}")
    scanned_count, findings = scan_repository(root_dir)

    print(f"Scanned {scanned_count} files.")
    if findings:
        print(f"\n[!] ALERT: {len(findings)} potential secret(s) detected:")
        for f in findings:
            print(f"  - [{f['type']}] {f['file']}:{f['line']} -> {f['match']}")
        sys.exit(1)
    else:
        print("\n[V] Secret Scan PASSED: No hardcoded credentials or API keys found in codebase.")
        sys.exit(0)

if __name__ == "__main__":
    main()
