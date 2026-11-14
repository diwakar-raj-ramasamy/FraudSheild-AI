# 📡 FraudShield AI — REST API & WebSocket Documentation

Base URL: `http://localhost:8000/api`  
Swagger UI (Interactive): `http://localhost:8000/docs`  
ReDoc: `http://localhost:8000/redoc`

---

## 1. Authentication Endpoints

### 1.1 Generate Admin Access Token
`POST /auth/token`  
Content-Type: `application/x-www-form-urlencoded`

#### Request:
```bash
curl -X POST http://localhost:8000/api/auth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin@fraudshield.ai&password=Admin@FraudShield2026!"
```

#### Response (200 OK):
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

---

## 2. Real-Time Threat Scanning Endpoints

### 2.1 Scan Target URL
`POST /scan/url`  
Content-Type: `application/json`

#### Request Body:
```json
{
  "url": "http://secure-login-paypa1.top/auth/verify.php",
  "device_pseudonym": "fs-ep-9a8b7c6d",
  "page_title": "PayPal Security Verification",
  "dom_signals": {
    "has_password_field": true,
    "has_otp_field": true,
    "claimed_brand": "paypal",
    "form_actions": [
      "http://untrusted-credential-drop.xyz/post.php"
    ],
    "redirect_hops": [
      "http://bit.ly/paypal-login",
      "http://secure-login-paypa1.top/auth/verify.php"
    ]
  }
}
```

#### Response (200 OK):
```json
{
  "url": "http://secure-login-paypa1.top/auth/verify.php",
  "domain": "secure-login-paypa1.top",
  "risk_score": 96,
  "classification": "CRITICAL",
  "attack_types": [
    "PHISHING",
    "FAKE_LOGIN_PAGE",
    "TYPOSQUATTING",
    "CROSS_DOMAIN_FORM"
  ],
  "safe_exit_recommended": true,
  "findings": [
    {
      "rule_id": "RULE-TYPO-01",
      "title": "Typosquatting Brand Impersonation Detected",
      "description": "Domain 'secure-login-paypa1.top' closely mimics legitimate brand 'paypal' using character substitution (1 -> l).",
      "severity": "CRITICAL",
      "contribution": 35
    },
    {
      "rule_id": "RULE-FL-01",
      "title": "Deceptive Credential Harvesting Form",
      "description": "Password and OTP input fields detected on unauthorized third-party domain.",
      "severity": "CRITICAL",
      "contribution": 35
    },
    {
      "rule_id": "RULE-FL-02",
      "title": "Cross-Domain Form Action Target",
      "description": "Form submits credentials to remote untrusted destination 'untrusted-credential-drop.xyz'.",
      "severity": "HIGH",
      "contribution": 20
    }
  ],
  "xai_factors": [
    {
      "factor": "Typosquatting Homoglyph Substitution",
      "weight": 35,
      "rationale": "paypa1 substitutes number 1 for letter l, targeting paypal.com users."
    },
    {
      "factor": "Sensitive Password & OTP Field Collection",
      "weight": 35,
      "rationale": "High-risk credential harvesting forms on non-official domain."
    },
    {
      "factor": "Machine Learning Vector Probability",
      "weight": 30,
      "rationale": "RandomForestClassifier assigned 98.4% malicious probability based on structural entropy and token ratios."
    }
  ],
  "recommendation": {
    "headline": "CRITICAL PHISHING THREAT DETECTED",
    "action_summary": "Do NOT enter passwords or personal data. Leave this website immediately.",
    "bullet_points": [
      "FraudShield has blocked interactive input on this page to prevent credential theft.",
      "Click 'LEAVE THIS WEBSITE' to safely disconnect and isolate your browser session.",
      "If you entered credentials, proceed immediately to the Post-Exposure Containment Guide."
    ]
  },
  "scanned_at": "2026-11-03T04:25:24Z"
}
```

---

## 3. Detection Telemetry & Multi-Device Correlation Endpoints

### 3.1 Report Endpoint Threat Detection
`POST /events/detection`  
Content-Type: `application/json`

#### Request Body:
```json
{
  "url": "http://secure-login-paypa1.top/auth/verify.php",
  "device_pseudonym": "fs-ep-9a8b7c6d",
  "risk_score": 96,
  "classification": "CRITICAL",
  "attack_types": ["PHISHING", "FAKE_LOGIN_PAGE"],
  "page_title": "PayPal Security Verification",
  "referrer": "http://mail.example.com"
}
```

#### Response (200 OK):
```json
{
  "status": "success",
  "event_id": "e4f5a6b7-8901-2345-6789-abcdef012345",
  "campaign_triggered": true,
  "campaign_info": {
    "campaign_id": "c7a8b9d0-1234-4567-8901-abcdef123456",
    "domain": "secure-login-paypa1.top",
    "total_detections": 3,
    "unique_devices": 2
  }
}
```

---

## 4. Attack Investigation & Infrastructure Dossier

### 4.1 Retrieve Full Forensics Dossier
`GET /investigation/{url_id}`

#### Response (200 OK):
```json
{
  "id": "u1a2b3c4-5678-90ab-cdef-1234567890ab",
  "url": "http://secure-login-paypa1.xyz/auth/login.php",
  "domain": "secure-login-paypa1.xyz",
  "risk_score": 96,
  "classification": "CRITICAL",
  "attack_types": ["PHISHING", "FAKE_LOGIN_PAGE", "TYPOSQUATTING"],
  "first_seen": "2026-11-02T16:30:00Z",
  "last_seen": "2026-11-03T04:25:00Z",
  "detection_count": 6,
  "unique_device_count": 3,
  "findings": [...],
  "xai_factors": [...],
  "infrastructure": {
    "domain": "secure-login-paypa1.xyz",
    "observed_ip": "104.21.44.182",
    "resolved_ips": ["104.21.44.182", "172.67.189.22"],
    "asn": "AS13335",
    "asn_org": "Cloudflare Inc.",
    "country": "US",
    "reverse_dns": "104.21.44.182.cloudflare.com",
    "dns_records": {
      "A": ["104.21.44.182", "172.67.189.22"]
    },
    "ssl_info": {
      "has_ssl": true,
      "issuer": "Let's Encrypt Authority X3",
      "grade": "Active TLS"
    },
    "observed_at": "2026-11-03T04:25:24Z",
    "forensic_disclaimer": "Observed Infrastructure IP Address indicates routing node, not confirmed threat actor identity."
  },
  "threat_intelligence": {
    "overall_match": true,
    "confidence": "high",
    "matched_providers": ["URLhaus", "PhishTank"]
  },
  "related_events": [
    {
      "id": "e1...",
      "device_id": "dev-01",
      "risk_score": 96,
      "classification": "CRITICAL",
      "detected_at": "2026-11-03T04:25:00Z",
      "page_title": "PayPal Login"
    }
  ]
}
```

---

## 5. Threat Blocklist Management

### 5.1 Query Current Blocklist Version (Used by Extensions)
`GET /blocklist/version`

#### Response (200 OK):
```json
{
  "version": 1,
  "last_updated": "2026-11-03T04:25:24Z",
  "entries_count": 4,
  "entries": [
    "phishing-login-paypa1.top",
    "g00gle-security-update.xyz",
    "update-kyc-binance-portal.work",
    "185.220.101.5"
  ]
}
```

### 5.2 Add Entry to Central Blocklist
`POST /blocklist`  
Content-Type: `application/json`

#### Request Body:
```json
{
  "target": "malicious-crypto-drainer.xyz",
  "target_type": "DOMAIN",
  "reason": "Confirmed wallet draining script targeting Ethereum users",
  "severity": "CRITICAL"
}
```

---

## 6. Zero-Execution Digital File Forensics

### 6.1 Upload Document for Static Analysis
`POST /files/analyze`  
Content-Type: `multipart/form-data`

#### Parameters:
- `file`: Binary file upload (`.pdf`, `.docx`, `.csv`, `.xlsx`, max 25MB)

#### Response (200 OK):
```json
{
  "id": "f8a9b0c1-2345-6789-0123-abcdef456789",
  "file_name": "urgent_wire_transfer_memo.csv",
  "file_type": "CSV",
  "file_size": 4210,
  "sha256": "3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b",
  "risk_score": 90,
  "classification": "CRITICAL",
  "metadata_extracted": {
    "total_rows": 48,
    "total_columns": 6,
    "encoding": "utf-8"
  },
  "indicators_found": [
    {
      "type": "CSV Formula Injection",
      "severity": "CRITICAL",
      "description": "Cell [Row 14, Col 2] contains command execution formula: =cmd|'/c powershell -enc...'!A1"
    }
  ],
  "extracted_urls": [
    "http://c2-dropzone.su/payload.exe"
  ],
  "extracted_domains": [
    "c2-dropzone.su"
  ],
  "extracted_ips": [
    "185.220.101.5"
  ],
  "extracted_emails": [
    "billing@legit-payroll.com"
  ],
  "xai_factors": [
    {
      "factor": "Dynamic Formula Injection Payload",
      "weight": 45,
      "rationale": "Spreadsheet contains executable DDE command string designed to trigger on export."
    },
    {
      "factor": "Malicious Command-and-Control Drop URL",
      "weight": 35,
      "rationale": "Contains unvetted remote executable URL pointing to high-risk .su TLD."
    }
  ],
  "created_at": "2026-11-03T04:25:24Z"
}
```

---

## 8. Observability, Health Probes & Error Specifications

### 8.1 Liveness Probe
`GET /health/live`  
Returns `200 OK` when the ASGI server process is alive and accepting connections. Used by Kubernetes/Docker liveness checks.

```json
{
  "status": "alive",
  "service": "FraudShield AI"
}
```

### 8.2 Readiness Probe
`GET /health/ready`  
Returns `200 OK` only when critical dependencies (PostgreSQL database, ML model, circuit breakers) are healthy.

```json
{
  "status": "ready",
  "service": "FraudShield AI",
  "dependencies": {
    "database": "connected",
    "circuit_breakers": {
      "VirusTotal": { "state": "CLOSED", "failure_count": 0, "short_circuits": 0 },
      "URLhaus": { "state": "CLOSED", "failure_count": 0, "short_circuits": 0 },
      "PhishTank": { "state": "CLOSED", "failure_count": 0, "short_circuits": 0 }
    },
    "ml_model": "loaded"
  }
}
```

### 8.3 Standardized Error Schema
All error responses return both a legacy `"detail"` key (ensuring backward compatibility with existing clients) and an enterprise `"error"` payload:

```json
{
  "detail": "Campaign not found",
  "error": {
    "code": "HTTP_404_NOT_FOUND",
    "message": "Campaign not found",
    "status_code": 404,
    "timestamp": "2026-11-06T08:14:25.123456Z"
  }
}
```

### 8.4 Request Tracing Headers
Every HTTP response carries enterprise tracing headers:
- `X-Correlation-ID`: Unique UUIDv4 assigned to each request for end-to-end distributed tracing.
- `X-Response-Time-MS`: Precise server-side latency in milliseconds (e.g. `12.4ms`).

### 8.5 Global Pagination Protocol
All collection endpoints (`/api/threats`, `/api/events`, `/api/campaigns`, `/api/devices`) support standardized pagination parameters:
- `limit`: Number of records to return (Default: `50`, Min: `1`, Max: `500`).
- `skip`: Number of records to offset (Default: `0`, Min: `0`).


