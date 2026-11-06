# 🛡️ FraudShield AI — Backend Detection Engine

[![FastAPI](https://img.shields.io/badge/FastAPI-0.110-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com/)
[![Python 3.12](https://img.shields.io/badge/Python-3.12-blue?style=flat-square&logo=python)](https://www.python.org/)
[![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-2.0-red?style=flat-square)](https://www.sqlalchemy.org/)
[![Alembic](https://img.shields.io/badge/Alembic-Migrations-purple?style=flat-square)](https://alembic.sqlalchemy.org/)
[![Tests Passing](https://img.shields.io/badge/Tests-77%20passed-brightgreen?style=flat-square&logo=pytest)](../docs/TESTING_REPORT.md)

High-performance, fault-tolerant Python ASGI backend powering real-time URL scanning, explainable machine learning threat scoring, multi-device campaign correlation, and zero-execution digital forensics.

---

## 🏗️ Architecture & Component Overview

```text
backend/
├── alembic/                # Alembic database migration revisions
├── app/
│   ├── api/                # REST & WebSocket route handlers
│   │   ├── auth.py         # JWT authentication & role-based access control (RBAC)
│   │   ├── scan.py         # Real-time URL threat scanning endpoint
│   │   ├── events.py       # Detection event ingestion & multi-device correlation
│   │   ├── threats.py      # SOC threat feed & batch-loaded query endpoints
│   │   ├── campaigns.py    # Correlated phishing campaign management
│   │   ├── blocklist.py    # Incremental threat blocklist synchronization
│   │   ├── file_analysis.py# Zero-execution digital forensics upload & parsing
│   │   ├── downloads.py    # Download monitoring & double-extension interception
│   │   ├── investigation.py# Forensic threat dossier generation
│   │   ├── metrics.py      # Aggregated SOC metrics & chart time-series
│   │   └── ws.py           # Authenticated WebSocket real-time event bus
│   ├── core/               # Enterprise resilience, security & infrastructure
│   │   ├── config.py       # Centralized Pydantic v2 application settings
│   │   ├── database.py     # SQLAlchemy pooled engine (20+10, pre-ping)
│   │   ├── circuit_breaker.py # Tri-state Circuit Breaker (CLOSED/OPEN/HALF_OPEN)
│   │   ├── exceptions.py   # Centralized domain exceptions & error formatting
│   │   ├── logging_config.py # Structured JSON logging & X-Correlation-ID middleware
│   │   ├── network_security.py # SSRF egress filtering & DNS rebinding guards
│   │   ├── rate_limiter.py # Sliding-window rate limiters
│   │   └── security.py     # Argon2/BCrypt hashing & JWT token verification
│   ├── engines/            # Pluggable Threat Detection Engines
│   │   ├── base.py         # BaseDetectionEngine & ScanContext abstract interfaces
│   │   ├── registry.py     # DetectionEngineRegistry with timeout protection (3.0s)
│   │   ├── malicious_url_detector.py # Heuristic URL structure analysis
│   │   ├── typosquatting_detector.py # Levenshtein & homoglyph brand impersonation
│   │   ├── fake_login_detector.py    # DOM credential harvesting form detection
│   │   ├── financial_scam_detector.py# Crypto giveaway & urgent wire fraud NLP
│   │   ├── xss_indicator_detector.py # DOM script sink & payload analysis
│   │   ├── redirect_analyzer.py      # Multi-hop evasion chain tracking
│   │   ├── infrastructure_analyzer.py# Safe DNS, ASN, SSL, and reverse IP lookup
│   │   ├── threat_intelligence.py    # Decoupled VT, URLhaus, and PhishTank providers
│   │   ├── scoring_engine.py         # Hybrid weighted risk score aggregation (0-100)
│   │   └── explainability_engine.py  # XAI feature attribution rationale
│   ├── file_analysis/      # Static document parsers (PDF, DOCX, XLSX, CSV)
│   ├── ml/                 # Machine learning models & SHAP explainers
│   │   ├── feature_extractor.py # 13-feature lexical & structural URL vectorizer
│   │   ├── fraud_model.joblib   # Trained RandomForestClassifier artifact
│   │   ├── model.py        # MLThreatClassifier with cryptographic SHA-256 validation
│   │   ├── shap_explainer.py # Feature attribution & SHAP contribution weights
│   │   └── train.py        # Offline training script with auto-digest logging
│   ├── models/             # SQLAlchemy ORM declarative models (12 tables)
│   ├── schemas/            # Pydantic request/response validation contracts
│   ├── services/           # Decoupled business logic & transaction managers
│   └── main.py             # FastAPI ASGI application factory & lifespan manager
├── load_tests/             # Load testing harness
│   ├── async_load_runner.py# Pure in-process high-concurrency benchmark runner
│   └── locustfile.py       # Distributed Locust synthetic load simulation profile
├── tests/                  # Backend unit & integration test suite (17 tests)
├── Dockerfile              # Production Python 3.12 multi-stage container
├── requirements.txt        # Pinned production dependencies
└── pytest.ini              # Pytest configuration
```

---

## 🚀 Running the Backend

### Prerequisites
- Python 3.12+ installed
- PostgreSQL 16+ (or local SQLite for zero-config runs)
- Redis 7+ (optional, fallback supported)

### 1. Activate Environment & Install Dependencies
```bash
cd backend
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
```

### 2. Apply Database Migrations
```bash
alembic upgrade head
```

### 3. Initialize Seed Records (Optional Default Admin & Seed Data)
```bash
python -m app.db_init
```

### 4. Start Development Server
```bash
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 5. Access Endpoints
- **Interactive Swagger UI**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **ReDoc Documentation**: [http://localhost:8000/redoc](http://localhost:8000/redoc)
- **Liveness Probe**: [http://localhost:8000/health/live](http://localhost:8000/health/live)
- **Readiness Probe**: [http://localhost:8000/health/ready](http://localhost:8000/health/ready)

---

## 🧪 Testing & Verification

Run the full automated verification suite:
```bash
# Run all backend & security tests (77 tests)
pytest ../security/tests tests/ -v

# Run with test coverage
pytest tests/ --cov=app --cov-report=term-missing

# Run high-concurrency performance benchmark (30+ RPS)
python load_tests/async_load_runner.py
```

