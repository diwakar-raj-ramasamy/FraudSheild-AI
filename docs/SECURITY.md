# 🔒 Security Policy — FraudShield AI

The FraudShield AI team is committed to ensuring the security, integrity, and privacy of our software and users. We appreciate and welcome the responsible disclosure of security vulnerabilities by security researchers, developers, and users.

---

## 📦 Supported Versions

Only the latest active release and supported maintenance branch receive security updates and vulnerability patches.

| Version | Supported | Security Maintenance Status |
| :--- | :--- | :--- |
| `1.0.x` | ✅ Yes | Active Security Maintenance |
| `< 1.0.0` | ❌ No | End of Life (Deprecated) |

---

## 🚨 Reporting a Vulnerability

If you discover a potential vulnerability, bug, or security risk in any component of **FraudShield AI** (FastAPI backend, React admin dashboard, Chrome browser extension, ML engines, or forensics modules), please report it following our coordinated vulnerability disclosure process.

### Disclosure Instructions
1. **DO NOT** disclose the issue publicly in GitHub issues, pull requests, or public forums.
2. Submit a confidential report via:
   - **Email:** `security@fraudshield.ai` (or via private GitHub Security Advisory)
   - **PGP Fingerprint (Optional):** `F3A2 9B1C 4E8D 76A0 2B5E  8C1D 9E4F 3A2B 1C0E 7D5F`
3. Please include the following in your report:
   - Type of vulnerability (e.g., SSRF, XSS, BOLA, Auth Bypass, Deserialization).
   - Component affected (`backend`, `browser-extension`, `admin-dashboard`, `file_analysis`).
   - Step-by-step reproduction instructions or a minimal Proof of Concept (PoC).
   - Potential impact if exploited in production environments.
   - Any proposed remediation or patch.

---

## ⏱️ Response Timelines & SLAs

Our dedicated application security team operates under the following service level objectives:

- **Initial Acknowledgment:** Within **24 hours** of submission.
- **Triage & Classification:** Within **48 hours** (severity assignment via CVSS v3.1).
- **Remediation & Patch Deployment:**
  - **CRITICAL (CVSS >= 9.0):** Within **72 hours**.
  - **HIGH (CVSS 7.0 - 8.9):** Within **7 calendar days**.
  - **MEDIUM (CVSS 4.0 - 6.9):** Within **14 calendar days**.
  - **LOW / INFORMATIONAL:** Next scheduled minor release.
- **Public Disclosure:** Following coordinated verification and production deployment of the patch.

---

## 🛡️ Secure Development & Deployment Guidelines

### 1. Environment Secrets & Credentials
- **Never commit `.env` files or secret tokens.**
- Always copy from `.env.example` and set cryptographic secrets with high entropy:
  ```bash
  openssl rand -hex 32
  ```
- Exclude development database files (`*.db`, `*.sqlite`) from version control.

### 2. Automated Security Verification Pipeline
Before submitting any pull request or deploying to staging/production, run the automated verification suite:

```bash
# On Windows (PowerShell)
powershell -ExecutionPolicy Bypass -File security/scripts/security_check.ps1

# On Linux / macOS (Bash)
./security/scripts/security_check.sh
```

### 3. API Authorization & RBAC
- All administrative endpoints must enforce `Depends(require_admin)`.
- All analyst endpoints must enforce `Depends(get_current_user_payload)`.
- Never rely solely on frontend view-level routing for access control.

### 4. Input Validation & Egress Safety
- Validate all incoming URLs and domain lookups with `SSRFGuard` before dispatching network sockets.
- Clamping and sanitization must be applied to all scoring outputs ($0 \le \text{Risk Score} \le 100$).
- All file uploads must undergo MIME magic-byte verification, filename basename extraction, and size limit checks ($< 25\text{MB}$).

