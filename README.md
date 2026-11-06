# 🛡️ FraudShield AI

[![CI/CD Pipeline](https://img.shields.io/badge/CI%2FCD-passing-brightgreen?style=flat-square&logo=githubactions)](.github/workflows/ci.yml)
[![Tests Passing](https://img.shields.io/badge/Tests-77%20passed%20%7C%20100%25-brightgreen?style=flat-square&logo=pytest)](docs/TESTING_REPORT.md)
[![Python Version](https://img.shields.io/badge/Python-3.12-blue?style=flat-square&logo=python)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com/)
[![React 18](https://img.shields.io/badge/React-18.2-61dafb?style=flat-square&logo=react)](https://react.dev/)
[![Chrome Extension](https://img.shields.io/badge/Manifest-V3-orange?style=flat-square&logo=googlechrome)](browser-extension/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ed?style=flat-square&logo=docker)](docker-compose.yml)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)

> **AI-Powered Browser Cyber Threat Detection, Prevention, Explainable Intelligence, Multi-Device Threat Correlation, and Digital Forensics Platform**

---

## 📌 Executive Summary & Innovation

Traditional browser security mechanisms rely almost entirely on static domain reputation feeds or signature databases. When a new phishing domain or spoofed financial portal goes live, there is a dangerous detection latency window where users fall victim before blacklists update. Furthermore, traditional antivirus warnings present opaque block screens that users routinely bypass without understanding the underlying risk.

**FraudShield AI** solves this problem through a multi-tier defense system:

1. **Client-Side Real-Time Telemetry & Threat Sensors:** A Manifest V3 Chromium browser extension extracts deep structural signals (DOM password/OTP forms, cross-domain form submissions, deceptive download extensions, multi-hop redirect chains, and XSS injection vectors) without ever collecting sensitive user input or passwords.
2. **Hybrid Dynamic Risk Scoring Engine (0–100):** Combines rule-based heuristics, trained Scikit-Learn machine learning classification (`RandomForestClassifier`), and external threat intelligence reputation feeds with deterministic safety overrides.
3. **Explainable AI (XAI) Attribution:** Explains *why* a URL or file is classified as dangerous using granular factor accounting and SHAP-style reasoning.
4. **FraudShield Safe Exit Protection:** Replaces traditional passive alerts with an active, zero-click "LEAVE THIS WEBSITE" safe departure protocol and immediate post-exposure emergency guidance.
5. **Multi-Device Threat Correlation Engine:** Privacy-conscious aggregation of repeated suspicious hits across multiple installations using random UUIDv4 pseudonyms, identifying coordinated phishing campaigns in real-time.
6. **Zero-Execution Digital Forensics Center:** In-depth static parsing of documents (PDF, DOCX, CSV, XLSX) extracting embedded macros, formula injection payloads (`=cmd|`, `=dde|`), and Indicators of Compromise (IOCs).
7. **Enterprise SOC Security Dashboard:** 10 comprehensive administrative consoles with real-time WebSocket event telemetry.

---

## 🏗️ Complete System Architecture

```text
                                 ┌──────────────────────────┐
                                 │      USER BROWSER        │
                                 └────────────┬─────────────┘
                                              │
                                              ▼
                           ┌─────────────────────────────────────┐
                           │  FRAUDSHIELD AI BROWSER EXTENSION   │
                           │  (Manifest V3 • TypeScript • React) │
                           │ • Real-time Navigation Sensor       │
                           │ • DOM Signal & Form Action Monitor  │
                           │ • Deceptive Download Interceptor    │
                           │ • Local High-Speed Blocklist Cache  │
                           │ • Zero-PII Random Pseudonym         │
                           └──────────────────┬──────────────────┘
                                              │ REST / WebSocket
                                              ▼
                           ┌─────────────────────────────────────┐
                           │      FASTAPI DETECTION BACKEND      │
                           └──────────────────┬──────────────────┘
                                              │
        ┌─────────────────────────────────────┼─────────────────────────────────────┐
        ▼                                     ▼                                     ▼
┌──────────────────────────┐    ┌───────────────────────────┐    ┌───────────────────────────────┐
│  HEURISTIC ENGINES       │    │  MACHINE LEARNING & XAI   │    │  THREAT INTELLIGENCE FEEDS    │
│ • Typosquatting / Homoglyph│   │ • Random Forest Classifier│    │ • VirusTotal API v3           │
│ • Fake Login / Credentials│   │ • 13-Feature Vector Model │    │ • URLhaus Abuse Database      │
│ • Financial Scam Cues    │    │ • SHAP Attribution Engine │    │ • PhishTank Verified Feed     │
│ • Download Double-Ext    │    │ • Feature Weight Ranking  │    │ • "Provider Offline ≠ Safe"   │
│ • DOM XSS Sinks          │    │                           │    │   Fail-Safe Architecture      │
│ • Redirect Chain Hopping │    │                           │    │                               │
└─────────────┬────────────┘    └─────────────┬─────────────┘    └───────────────┬───────────────┘
              │                               │                                  │
              └───────────────────────────────┼──────────────────────────────────┘
                                              ▼
                                 ┌──────────────────────────┐
                                 │   HYBRID SCORING ENGINE  │
                                 │      Score: 0 – 100      │
                                 │  • Heuristics (45%)      │
                                 │  • Machine Learning (35%)│
                                 │  • Threat Intel (20%)    │
                                 │  • Hard Overrides (95+)  │
                                 └────────────┬─────────────┘
                                              │
                                              ▼
                                 ┌──────────────────────────┐
                                 │   EXPLAINABILITY (XAI)   │
                                 │ • Top Risk Drivers       │
                                 │ • Human-Readable Reasons │
                                 │ • Point Contribution     │
                                 └────────────┬─────────────┘
                                              │
                    ┌─────────────────────────┼─────────────────────────┐
                    ▼                         ▼                         ▼
              [ 0 – 39 ]                 [ 40 – 69 ]               [ 70 – 100 ]
                 SAFE                      CAUTION                   CRITICAL
           Allow Navigation             Warning Banner            Safe Exit Screen
                    │                         │                         │
                    └─────────────────────────┼─────────────────────────┘
                                              │
                                              ▼
                               ┌─────────────────────────────┐
                               │  EVENT PERSISTENCE & STORE  │
                               └──────────────┬──────────────┘
                                              │
                                              ▼
                               ┌─────────────────────────────┐
                               │  MULTI-DEVICE CORRELATION   │
                               │ • Cluster by Domain / IP    │
                               │ • Distinct Device Tracking  │
                               │ • Threshold: 2+ Devices     │
                               └──────────────┬──────────────┘
                                              │
                                              ▼
                               ┌─────────────────────────────┐
                               │   FRAUD CAMPAIGN DETECTOR   │
                               │ • Auto-Assign Campaign Name │
                               │ • Broadcast Admin Alert     │
                               │ • Auto-Increment Blocklist  │
                               └──────────────┬──────────────┘
                                              │ WebSocket Live Bus
                                              ▼
                               ┌─────────────────────────────┐
                               │     ADMIN SOC DASHBOARD     │
                               │  (React 18 • TypeScript)    │
                               └─────────────────────────────┘
```

---

## 📂 Repository Structure & Dedicated Guides

FraudShield AI is organized as a decoupled mono-repository with dedicated documentation for each tier:

| Sub-Module / Directory | Technology Stack | Description | Dedicated Guide |
| :--- | :--- | :--- | :--- |
| **[backend/](backend/)** | Python 3.12, FastAPI, SQLAlchemy 2.0, Alembic, Scikit-learn, SHAP | ASGI asynchronous API, hybrid heuristic scoring engines, ML classifier, forensic parsers, and connection pool. | 📖 **[Backend Guide](backend/README.md)** |
| **[admin-dashboard/](admin-dashboard/)** | React 18, TypeScript, Vite 5, Tailwind CSS, Recharts | Enterprise SOC web console featuring 10 operational views, real-time WebSockets, and zero-execution file forensics. | 📖 **[Admin Dashboard Guide](admin-dashboard/README.md)** |
| **[browser-extension/](browser-extension/)** | Chrome Manifest V3, React 18, TypeScript, Tailwind CSS | Client endpoint defense featuring offline blocklist cache, DOM signal heuristics, Safe Exit, and download interceptor. | 📖 **[Extension Guide](browser-extension/README.md)** |
| **[docs/](docs/)** | Markdown, Mermaid | Comprehensive technical documentation hub covering architecture, scalability, security audits, and benchmarks. | 📚 **[Documentation Hub](docs/README.md)** |

---

## ⚡ Core Modules & Key Features

### 1. Browser Extension (Manifest V3)
- **Zero-PII Privacy Protection:** Uses random UUIDv4 installation pseudonyms (`fs-ep-...`). Never inspects, extracts, or transmits credentials, passwords, PINs, or private user data.
- **Deep Signal Extractor:** Inspects `<input type="password">`, OTP numeric patterns, form `action` destinations (flagging cross-domain credential transmission), and claimed brand trademarks.
- **Deceptive Download Interceptor:** Traps dangerous double extensions (e.g. `.pdf.exe`, `.invoice.scr`) before they reach the user's filesystem.
- **Local Threat Blocklist Engine:** Synchronizes blocklist versions via `chrome.alarms` every 60 seconds; enforces local instantaneous blockages offline.
- **Active Safe Exit Protocol:** One-click safe disconnect button redirects the user to `safe-exit.html` and offers emergency post-exposure containment tabs (Password change guidance, session termination, bank freezing).

### 2. Multi-Signal Detection Backend (FastAPI + SQLAlchemy)
- **Typosquatting & Homoglyphs:** Levenshtein edit distance, Unicode homoglyphs (e.g., Cyrillic 'а', Greek 'о'), and Punycode (`xn--...`) decoding targeting 15+ premier global brands.
- **Fake Login Page Detector:** Correlates credential inputs on unauthorized domains with spoofed brands and cross-domain submission actions.
- **Financial Scam Detector:** Scans for cryptocurrency doubling scams, fake KYC urgent verification demands, investment coercion, and recovery fraud keywords.
- **Malicious URL Structural Detector:** Computes Shannon entropy, IP-in-hostname checks, high-risk TLD analysis (`.top`, `.xyz`, `.work`), and path keyword scanning.
- **Redirect Chain Analyzer:** Analyzes multi-hop redirects, flagging cross-domain hops that switch schemes or bounce through URL shorteners to evade security scans.
- **Observed Infrastructure Analyzer:** Discovers DNS A/CNAME records, ASN allocations, reverse DNS lookups, and TLS certificate details with explicit forensic attribution (*"Observed Infrastructure IP Address ≠ Confirmed Attacker Identity"*).

### 3. Machine Learning & Explainable AI (XAI)
- **Trained Model:** Scikit-Learn `RandomForestClassifier` trained on normalized 13-feature numeric vectors (Shannon entropy, token lengths, digit-to-letter ratios, TLD risk indices, etc.).
- **Serialized Model:** Persisted in `backend/app/ml/fraud_model.joblib`. Includes self-calibrated fallback inference in case of model load failure.
- **Transparent XAI Attribution:** Every scan produces a ranked list of factors with point contributions and plain-English rationales.

### 4. Multi-Device Correlation & Campaign Monitor
- **Privacy-Preserving Aggregation:** Evaluates detections across multiple endpoints over a configurable sliding time window (default: 24 hours).
- **Campaign Trigger:** When $\ge 2$ unique endpoints report hits on the same malicious domain, the engine automatically generates a `FraudCampaign` record, fires an urgent `AdminAlert`, and broadcasts a real-time event via WebSockets.

### 5. Zero-Execution Digital Forensics Center
- **Safe Static Parsing:** Analyzes files without code or binary execution.
  - **PDF:** Structural inspection of `/JavaScript`, `/Launch`, `/EmbeddedFiles`, and hidden URLs.
  - **DOCX:** ZIP container AST inspection, VBA macro signatures (`vbaProject.bin`), and external relationship targets.
  - **CSV:** Formula injection detection (`=cmd|`, `=dde|`, `@SUM`, `-2+5+cmd|`).
  - **XLSX:** Formula injection, remote DDE linkages, and unreferenced binary streams.
- **IOC Extraction:** Extracts all domains, IPv4 addresses, URLs, and emails for instant pivoting.

### 6. Admin Cybersecurity Dashboard
- **10 Core Views:**
  1. *Security Overview:* Real-time stats, threat timeline trends, attack category distribution.
  2. *Threat Detection Center:* Comprehensive log of all scanned URLs with severity filtering.
  3. *Attack Investigation Dossier:* Full-spectrum threat forensic view with DNS, ASN, SSL, and related events.
  4. *Campaign Monitor:* Real-time tracker for distributed attacks with 1-click mitigation.
  5. *Dangerous Downloads:* Trap log for deceptive binary extensions and malicious payload sources.
  6. *File Analysis Center:* Drag-and-drop forensic analyzer with immediate IOC extraction.
  7. *Admin Alerts:* Priority queue of actionable security events with resolution tracking.
  8. *Threat Blocklist:* Centralized blocklist manager with auto-incrementing version distribution.
  9. *Endpoint Devices Monitor:* Sensor node health and version tracking with zero-PII privacy guarantee.
  10. *Settings & Thresholds:* API key management, scoring weights, and correlation sliders.

---

## 🚀 Quickstart Guide

### Prerequisites
- Python 3.12+
- Node.js 18+ and npm
- (Optional) Docker and Docker Compose

---

### Method A: Local Direct Execution (Recommended for Fast Evaluation)

#### Step 1: Backend Setup
```powershell
# Navigate to backend
cd backend

# Create virtual environment and activate
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Train the ML Model and generate fraud_model.joblib
python -m app.ml.train

# Initialize SQLite database with seed records
python -m app.db_init

# Launch FastAPI backend server (Port 8000)
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
*Backend will be running at `http://localhost:8000` with Swagger UI at `http://localhost:8000/docs`.*

#### Step 2: Browser Extension Setup
```powershell
# Navigate to browser-extension directory
cd browser-extension

# Install dependencies and build production bundle
npm install
npm run build
```
1. Open Google Chrome (or Microsoft Edge / Brave).
2. Navigate to `chrome://extensions`.
3. Enable **Developer mode** (toggle in upper-right corner).
4. Click **Load unpacked** and select the `browser-extension/dist` directory.
5. The FraudShield AI shield icon will appear in your browser extension toolbar!

#### Step 3: Admin Dashboard Setup
```powershell
# Navigate to admin-dashboard directory
cd admin-dashboard

# Install dependencies and launch Vite development server
npm install
npm run dev
```
*Open `http://localhost:5173` in your browser to access the Admin SOC Console.*

---

### Method B: Docker Compose Deployment

```powershell
# In the project root:
docker-compose up --build
```
- **PostgreSQL Database:** Port `5432`
- **FastAPI Backend:** `http://localhost:8000`
- **Admin SOC Console:** `http://localhost:5173`

---

## 🧪 Running the Automated Test Suite

FraudShield AI comes with a comprehensive pytest test suite covering all engines, utilities, ML pipelines, and file forensics:

```powershell
cd backend
.\venv\Scripts\pytest -v
```

### Verified Test Suite Summary:
```text
tests/test_api_endpoints.py::test_health_endpoint PASSED
tests/test_api_endpoints.py::test_blocklist_version_endpoint PASSED
tests/test_api_endpoints.py::test_admin_metrics_overview PASSED
tests/test_correlation_and_campaigns.py::test_multi_device_campaign_correlation PASSED
tests/test_file_forensics.py::test_ioc_extraction PASSED
tests/test_file_forensics.py::test_csv_formula_injection_analysis PASSED
tests/test_phishing_and_scoring.py::test_fake_login_detector PASSED
tests/test_phishing_and_scoring.py::test_financial_scam_detector PASSED
tests/test_phishing_and_scoring.py::test_xss_indicator_detector PASSED
tests/test_phishing_and_scoring.py::test_redirect_analyzer PASSED
tests/test_phishing_and_scoring.py::test_scoring_engine_hybrid_aggregation PASSED
tests/test_typosquatting.py::test_levenshtein_distance PASSED
tests/test_typosquatting.py::test_typosquatting_detection PASSED
tests/test_url_normalization.py::test_url_normalization PASSED
tests/test_url_normalization.py::test_extract_domain PASSED
tests/test_url_normalization.py::test_is_ip_address PASSED
tests/test_url_normalization.py::test_url_hash PASSED

====================== 17 passed in ~18s ======================
```

---

## 🔐 Default Credentials & Seed Data

| Role | Username / Email | Password | Access Level |
| :--- | :--- | :--- | :--- |
| **Enterprise SOC Admin** | `admin@fraudshield.ai` | `Admin@FraudShield2026!` | Full Admin / SOC Console |

### Pre-Seeded Demonstration Targets:
- **Active Phishing Campaign:** `secure-login-paypa1.xyz` (6 correlated hits across 3 distinct endpoints)
- **Confirmed Blocklist Targets:** `phishing-login-paypa1.top`, `g00gle-security-update.xyz`, `update-kyc-binance-portal.work`, `185.220.101.5`
- **Dangerous Download:** `invoice_march_statement.pdf.exe`

---

## 🔒 Security & Privacy Guarantees

1. **Zero Credential Collection:** The browser extension NEVER reads the contents of password fields, OTP inputs, credit card numbers, or session cookies. Only boolean presence flags (`has_password_field: true`) and `<form action="...">` target URLs are transmitted.
2. **Zero-Execution Forensics:** Uploaded files in the Forensics Center are analyzed strictly through AST tree traversals, byte signatures, and regex IOC scanners. No macros, VBScript, DDE expressions, or embedded executables are ever run.
3. **Forensic Attribution Boundary:** All IP addresses are cataloged as *"Observed Infrastructure IP Address"* rather than *"Confirmed Threat Actor Identity"* to uphold forensic integrity.
4. **Endpoint Anonymization:** Endpoint telemetry uses random UUIDv4 pseudonyms. No MAC addresses, hardware serial numbers, or OS usernames are gathered.

---

## 📚 Technical Documentation & System Guides

Comprehensive architecture, API specifications, security hardening guides, and operational runbooks are located in the [`docs/`](docs/) directory:

- 🏛️ **[Architecture Specification](docs/ARCHITECTURE.md)**: Modular monolith, engine registry, circuit breakers, and data flows.
- 📈 **[Scalability Plan](docs/SCALABILITY_PLAN.md)**: 100k+ extensions roadmap, multi-tier caching, and connection pooling.
- 🛡️ **[Reliability & Recovery Guide](docs/RELIABILITY_AND_RECOVERY.md)**: Fault-tolerance matrix, timeouts, and graceful degradation.
- 🔒 **[Security Hardening Guide](docs/SECURITY_HARDENING.md)**: BOLA, SSRF, XXE, rate limiting, and formula injection mitigations.
- 🗄️ **[Database Architecture](docs/DATABASE_DESIGN.md)**: ER diagrams, schemas, indexing, and Alembic migrations.
- 📡 **[REST API & WebSockets](docs/API_DOCUMENTATION.md)**: OpenAPI endpoints, health probes, tracing, and error schemas.
- 🚀 **[Deployment Guide](docs/DEPLOYMENT_GUIDE.md)**: Docker Compose, Kubernetes manifests, and production checklist.
- 📊 **[Observability & Monitoring](docs/MONITORING_GUIDE.md)**: Structured JSON logging, Prometheus metrics, and alert rules.
- 🧪 **[Automated Test Report](docs/TESTING_REPORT.md)**: Complete analysis of all 77 test cases (100% pass rate).
- ⚡ **[Performance Benchmark Report](docs/PERFORMANCE_REPORT.md)**: Empirical throughput (30.36 RPS) and latency percentiles.
- 🚨 **[Disaster Recovery Plan](docs/DISASTER_RECOVERY_PLAN.md)**: RPO/RTO objectives, continuous WAL backups, and failover runbooks.
- 📝 **[Persistent Update Ledger](docs/UPDATE_LOG.md)**: Chronological update audit trail.
- 📜 **[Project Changelog](docs/CHANGELOG.md)**: Versioned release notes.

---

## 📄 License
FraudShield AI is developed as an open research and engineering project for advanced browser cyber threat defense. Licensed under the MIT License.

