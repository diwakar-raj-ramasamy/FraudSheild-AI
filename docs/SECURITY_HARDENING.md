# 🛡️ FraudShield AI — Security Hardening Guide & Implementation Reference

This document provides a technical reference for all security hardening measures implemented across the FraudShield AI ecosystem.

---

## 1. Backend API & Infrastructure Hardening

### A. Broken Object-Level Authorization (BOLA / IDOR) Defense
- **Enforced RBAC on All Sensitive Routes:** Every investigative endpoint (`/api/investigation/{id}`), threat management endpoint (`/api/threats`), detection event inspection (`/api/events`), and administration panel route enforces JWT authentication via FastAPI dependency injection:
  ```python
  @router.get("/{id}", response_model=InvestigationDetail)
  def get_investigation_dossier(
      id: str,
      db: Session = Depends(get_db),
      current_user: dict = Depends(get_current_user_payload)
  ):
      ...
  ```
- **Administrative Role Isolation:** Critical actions (such as blocklist updates, alert resolution, user creation, and campaign mitigation) strictly verify `current_user.get("role") == "admin"`. Analyst roles are prevented from performing privileged state modifications.

### B. Anti-Spoofing Rate Limiting
- **Client IP Resolution Hardening:** Previously, the rate limiter directly trusted `X-Forwarded-For`, allowing rate limit evasion by rotating spoofed headers.
- **Configurable Reverse Proxy Trust:** The IP resolver now inspects `TRUST_PROXY_HEADERS`:
  ```python
  def get_client_ip(request: Request) -> str:
      if settings.TRUST_PROXY_HEADERS:
          forwarded = request.headers.get("X-Forwarded-For")
          if forwarded:
              return forwarded.split(",")[0].strip()
      return request.client.host if request.client else "unknown"
  ```
- Endpoints are protected with token-bucket or sliding-window rate limiters:
  - `/api/auth/login`: 5 requests / minute
  - `/api/scan`: 60 requests / minute
  - `/api/files/upload`: 10 requests / minute

### C. CORS Hardening
- **Strict Origin Whitelist:** Removed wildcard origins (`*`).
- Configured explicit origins in `app.core.config.Settings`:
  - `http://localhost:5173` (Admin Dashboard Development)
  - `http://localhost:3000` (Production Dashboard)
  - Approved Chrome Extension UUID origins (`chrome-extension://<id>`).

### D. Security Response Headers
Every HTTP response carries enterprise security headers via middleware:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains` (Production)
- `Referrer-Policy: strict-origin-when-cross-origin`

---

## 2. Chrome Extension (Manifest V3) Hardening

### A. Permission Minimization
- **Downgraded from `tabs` to `activeTab`:** Removed broad `"tabs"` permission that allowed silent inspection of all open browser tabs and history. Replaced with least-privilege `"activeTab"` and `"webNavigation"`.
- **Manifest Configuration:**
  ```json
  "permissions": [
    "storage",
    "activeTab",
    "webNavigation",
    "declarativeNetRequest"
  ]
  ```

### B. Content Security Policy (CSP)
- Enforced strict MV3 extension pages CSP:
  ```json
  "content_security_policy": {
    "extension_pages": "script-src 'self'; object-src 'self'"
  }
  ```
- Prevents loading of remote scripts or execution of inline `eval()` statements within extension background or popup contexts.

### C. Safe Exit & Warning Redirection
- **Safe Exit Protocol:** High-risk phishing or scam sites are halted. The extension redirects the active tab to an internal, trusted warning interface (`chrome-extension://<id>/warning.html`).
- **URL Parameter Sanitization:** Target URLs passed to the warning page are URL-encoded and validated against strict `http://` or `https://` schemes before display or navigation options are rendered.

---

## 3. Database Security & Privacy Architecture

### A. SQL Injection Elimination
- **Parameterized Queries via SQLAlchemy ORM:** All database queries utilize SQLAlchemy parameterized bindings. Direct string concatenation or raw SQL execution is prohibited.
- **Input Sanitization on Text Queries:** Text fields, search queries, and domain lookups are strictly type-validated via Pydantic v2 schemas before execution.

### B. Device Pseudonymity & Privacy Protection
- **No Hardware Identifiers:** The platform prohibits collection of MAC addresses, hardware serial numbers, IMEI, or device fingerprints.
- **Client-Generated Pseudonyms:** Endpoints identify themselves via client-generated UUIDs (`installation_pseudonym`), constrained to `^[a-zA-Z0-9_\-]{8,64}$`.
- **Database Indexing & Constraints:** Added unique constraints on pseudonym mappings to prevent collision attacks or enumeration.

---

## 4. Machine Learning & Risk Engine Hardening

### A. Cryptographic Model Weight Verification
- **Anti-Tampering SHA-256 Verification:** To prevent arbitrary code execution via untrusted `pickle` / `joblib` deserialization (CWE-502), the model loading routine computes the SHA-256 hash of `fraud_model.joblib` and verifies it against an embedded cryptographic digest before unpickling:
  ```python
  def load_model(path: str, expected_sha256: str = EXPECTED_HASH):
      file_hash = hashlib.sha256(Path(path).read_bytes()).hexdigest()
      if file_hash != expected_sha256:
          raise SecurityException("ML Model weights integrity verification failed! Refusing to load.")
      return joblib.load(path)
  ```

### B. Score Invariant Clamping
- **Strict Bounded Risk Scores:** Enforced invariant guarantees:
  $$0 \le \text{Risk Score} \le 100$$
  ```python
  clamped_score = min(max(raw_score, 0), 100)
  ```
- Ensures external consumers, security dashboards, and alert triggers cannot receive out-of-bound values (e.g. 140/100).

---

## 5. Digital Forensics & File Upload Security

### A. Multi-Layer File Validation
1. **Magic Bytes (MIME) Verification:**
   - PDF: Requires `%PDF-` (`0x25 0x50 0x44 0x46 0x2D`) at offset 0.
   - DOCX / XLSX: Requires PKZIP magic bytes (`0x50 0x4B 0x03 0x04`).
2. **File Size Hard Limits:** Uploads strictly capped at 25 MB (`MAX_FILE_SIZE_MB = 25`).
3. **Storage Sanitization:** Uploaded files are stored in a dedicated directory outside the webroot, with randomized UUID names to eliminate directory traversal risks (`os.path.basename` enforcement).

### B. PDF Parsing Hardening
- **Full-Content Byte Inspection:** Removed arbitrary 1MB search limits. The scanner performs full byte-stream analysis using PyMuPDF for:
  - `/JavaScript` / `/JS`
  - `/Launch`
  - `/EmbeddedFiles`
  - `/OpenAction` / `/AA`

### C. Spreadsheet Formula Injection Defense (CSV / DDE)
- **Cell Sanitization & Prefix Escaping:** Any cell starting with `=, +, -, @, \t, \r` is identified as a potential formula.
- **Dangerous Token Inspection:** Cells containing suspicious commands or exfiltration functions (`cmd`, `powershell`, `certutil`, `wscript`, `cscript`, `hyperlink`, `importxml`, `webservice`) are flagged with high-severity findings and neutralized.

### E. XML External Entity (XXE) Injection Defense (DOCX & XLSX)
- **Container Pre-Expansion Inspection:** OpenXML formats (`.docx`, `.xlsx`) are zip archives containing XML files. To block malicious external DTD entities, external system identifiers, and XML entity expansion bombs ("Billion Laughs"), the forensic analyzers inspect all internal `.xml` and `.rels` streams before passing them to XML parsers.
- **Forbidden Constructs:** Any occurrence of `<!ENTITY`, `<!DOCTYPE`, or `SYSTEM` triggers an immediate `SUSPICIOUS_XML_DECLARATION` critical forensic finding and halts further entity parsing.

---

## 7. Middleware & Infrastructure Resilience Hardening

### A. Request Size Limiting Middleware
- Enforces an absolute 30MB limit (`RequestSizeLimitMiddleware`) on all incoming HTTP request bodies. Requests exceeding this threshold are rejected immediately with `413 Request Entity Too Large` before buffering into application memory.

### B. Request Tracing & Correlation IDs
- `CorrelationIdMiddleware` propagates an `X-Correlation-ID` header across every request and response lifecycle.
- Logs are emitted in structured JSON format via `StructuredJsonFormatter`, binding timestamps, log levels, messages, client IPs, endpoints, and correlation IDs for centralized SIEM ingestion.

### C. Database Query Scalability & Pagination
- High-volume endpoints (`/api/threats`, `/api/events`, `/api/campaigns`, `/api/devices`) enforce strict `limit` (max 500) and `skip` query parameters.
- N+1 query patterns have been eliminated via SQLAlchemy eager loading (`joinedload`), and composite indexes accelerate range and equality lookups.

### D. Production Error Sanitization
- Centralized exception handlers catch all unhandled exceptions and return structured JSON responses. Internal server paths, Python stack traces, and database driver error details are never exposed to clients in production mode.


### A. SSRF Egress Filtering
- The infrastructure resolver (`SSRFGuard`) validates all resolved target IP addresses before socket connection or HTTP dispatch:
  - Rejects Loopback: `127.0.0.0/8`, `::1`
  - Rejects Private Subnets (RFC 1918): `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
  - Rejects Link-Local & Cloud Metadata: `169.254.169.254`, `169.254.0.0/16`
  - Rejects Multicast & Reserved: `224.0.0.0/4`, `240.0.0.0/4`

### B. Fail-Safe External Intelligence Fallback
- If VirusTotal, PhishTank, or URLhaus APIs fail, timeout, or return rate-limit errors, the engine defaults to local heuristics and ML scoring without returning a false "SAFE" verdict.
- External responses are strictly sanitized to prevent injection of malicious strings into XAI explanations.

