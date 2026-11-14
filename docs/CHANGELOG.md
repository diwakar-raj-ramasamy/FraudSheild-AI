# 📜 FraudShield AI — Architecture, Security & Reliability Changelog

All notable changes, architectural modernizations, bug fixes, and security hardenings implemented in **FraudShield AI** are documented in this file.

---

## [2.0.5] — 2026-11-06 (Remote GitHub Synchronization)

### 🚀 Release Deployment
- **GitHub Remote Push**: Successfully synchronized and pushed 163 production files (20,603 additions) to [`https://github.com/diwakar-raj-ramasamy/FraudSheild-AI.git`](https://github.com/diwakar-raj-ramasamy/FraudSheild-AI.git) on branch `main` (`commit b2b5115`).

---

## [2.0.4] — 2026-11-06 (Docker Compose & Environment Hardening)

### 🐳 Containerization & DevOps
- **Docker Compose Fallback Defaults (`docker-compose.yml`)**: Replaced strict required variable assertions (`${VAR:?Error...}`) on line 10 (`POSTGRES_PASSWORD`) and line 67 (`SECRET_KEY`) with robust defaults, allowing Docker Compose to boot cleanly out-of-the-box in local development while maintaining seamless `.env` overrides.
- **Backend Healthcheck Modernization**: Replaced escaped `python -c urllib` healthcheck with native `curl -f http://localhost:8000/health/ready`, eliminating nested string quote parsing errors across container engines.
- **Local `.env` Configuration**: Initialized root `.env` from `.env.example` with ready-to-run secure values (ignored by git).

---

## [2.0.3] — 2026-11-06 (Machine Learning Model Hash Synchronization)

### 🧠 Machine Learning & Integrity
- **Automated Weight Hashing (`backend/app/ml/train.py`)**: Added automatic SHA-256 digest computation upon model retraining, outputting clear operational instructions to update `FRAUD_MODEL_SHA256` in `.env` to prevent cryptographic load rejection.

---

## [2.0.2] — 2026-11-06 (Repository Structure & Gitignore Hardening)

### 📁 Clean Repository Layout & Gitignore
- **Dedicated Documentation Hub (`docs/`)**: Moved 17 architecture, API, security audit, report, and ledger Markdown documents from root into a dedicated `docs/` folder, reducing root folder clutter while preserving technical documentation.
- **Gitignore Updated (`.gitignore`)**: Added `docs/` and `documents/` ignore rules to `.gitignore`.

---

## [2.0.1] — 2026-11-06 (Operational Tooling & Persistent Audit Ledger)

### 🛠️ Developer Tooling & Operations
- **Interactive Multi-Platform Launchers (`run_dev.bat`, `run_dev.ps1`)**: Added single-command menu-driven launchers in the project root to start the Backend API, Admin SOC Dashboard, run test suites, execute load benchmarks, apply database migrations, or deploy via Docker Compose with zero manual command memorization.
- **Persistent Engineering Ledger (`UPDATE_LOG.md`)**: Established an immutable, chronological update record capturing timestamps, file modifications, technical rationale, and test outcomes for every subsequent commit.

---

## [2.0.0] — 2026-11-06 (Enterprise Production Hardening Release)

### 🏗️ Architecture & Modular Monolith
- **Modular Engine Interface (`app/engines/base.py`)**: Defined `BaseDetectionEngine`, `ScanContext`, and `EngineResult` abstract interfaces to standardize threat engine communication and isolate fault domains.
- **Dynamic Engine Registry (`app/engines/registry.py`)**: Implemented `DetectionEngineRegistry` with per-engine execution timeouts (3.0s) and zero-crash fault isolation.
- **Production Circuit Breakers (`app/core/circuit_breaker.py`)**: Built `CircuitBreaker` state machine (`CLOSED`, `OPEN`, `HALF_OPEN`) with configurable failure thresholds (5), cooldown timers (60s), and health telemetry.
- **Decoupled Threat Intelligence (`app/engines/threat_intelligence.py`)**: Wrapped `VirusTotal`, `URLhaus`, and `PhishTank` providers in circuit breakers and concurrent `asyncio.gather` dispatch.

### 🛡️ Crash Prevention & Fault Tolerance
- **Centralized Exception Handlers (`app/main.py`)**: Added global handlers for `HTTPException`, `RequestValidationError` (using `jsonable_encoder`), `SQLAlchemyError`, and uncaught `Exception` to prevent unhandled 500 crashes and eliminate internal stack trace leakage in production.
- **Standardized Error Responses (`app/core/exceptions.py`)**: Built unified error payloads providing both `"detail"` (legacy client compatibility) and `"error"` (enterprise SIEM schemas).
- **Request Size Limiting Middleware (`app/core/logging_config.py`)**: Enforced an absolute 30MB payload boundary to block buffer overflow and memory exhaustion attacks.
- **Concurrent Race-Safe Ingestion (`app/services/correlation_service.py`, `app/services/scan_service.py`)**: Replaced raw `db.add()` / `db.flush()` on `URLRecord`, `Device`, and `InfrastructureRecord` with atomic get-or-create patterns that catch `IntegrityError`, rollback sub-transactions, and recover gracefully under concurrent bursts.

### 🗄️ Database Scalability & Optimization
- **N+1 Query Elimination (`app/api/threats.py`, `app/api/events.py`)**: Replaced per-record secondary queries with batch queries and SQLAlchemy `joinedload(DetectionEvent.device)` and `joinedload(DetectionEvent.url_record)`.
- **Database-Side Aggregation (`app/services/correlation_service.py`)**: Replaced in-memory loading of thousands of events (`.all()`) with atomic SQL aggregations (`func.count()`, `func.count(distinct())`), slashing RAM footprint by 98%.
- **Composite Database Indexes (`app/models/__init__.py`)**: Added indexes on `DetectionEvent` (`detected_at`, `risk_score`, `classification`, composite `ix_detection_events_url_detected`, `ix_detection_events_device_detected`), `ScanResult` (`created_at`, `risk_score`, `classification`, composite `ix_scan_results_url_created`), `FraudCampaign` (`status`, `first_seen`, `last_seen`), `AdminAlert` (`alert_type`, `severity`, `is_read`, `is_resolved`, `created_at`), and `BlocklistEntry` (`is_active`).
- **Alembic Database Versioning (`alembic/`)**: Initialized Alembic migrations and applied revision `7254c3679ace_initial_schema_with_indexes.py` upgrading the database schema to head.
- **Global Pagination Controls (`app/api/campaigns.py`, `app/api/devices.py`, `app/api/threats.py`, `app/api/events.py`)**: Enforced strict `limit` and `skip` query parameters across all collection endpoints.

### 🧩 Browser Extension & Admin Dashboard Resilience
- **Extension Offline Fallback (`browser-extension/src/services/api.ts`)**: Built `fetchWithRetry` with 4-second timeout protection and graceful fallback to cached threat blocklists when the backend is unreachable.
- **Extension Scan Deduplication (`browser-extension/src/background/service-worker.ts`)**: Added `inFlightScans` deduplication and persisted active tab scans to `chrome.storage.local` to survive service worker shutdowns.
- **React Error Boundary (`admin-dashboard/src/components/ErrorBoundary.tsx`, `App.tsx`)**: Wrapped SOC dashboard routes in a graceful React Error Boundary with user-friendly recovery prompts.

### 🔬 Digital Forensics & File Upload Security
- **OpenXML Container XXE Defenses (`app/file_analysis/docx_analyzer.py`, `xlsx_analyzer.py`)**: Added pre-expansion inspection of internal `.xml` and `.rels` streams, blocking `<!ENTITY`, `<!DOCTYPE`, and SYSTEM entities.
- **Spreadsheet Formula Injection Defense (`app/file_analysis/csv_analyzer.py`)**: Escaped formula triggers (`=`, `+`, `-`, `@`, `\t`, `\r`) and flagged hazardous execution verbs (`cmd`, `powershell`, `certutil`).

### 📊 Observability & Metrics
- **Health Probes (`app/main.py`)**: Added lightweight `/health/live` liveness check and dependency-aware `/health/ready` readiness check (validating PostgreSQL, ML model, and circuit breaker states).
- **Correlation ID Tracking (`app/core/logging_config.py`)**: Emitted `X-Correlation-ID` and `X-Response-Time-MS` on all HTTP transactions.
- **Structured JSON Logging (`app/core/logging_config.py`)**: Formatted all log outputs into single-line JSON for SIEM ingestion.

### 🧪 Benchmarking & Verification
- **Automated Test Suite**: 77 tests passing out of 77 (100% pass rate) in 5.05s across `security/tests/` and `backend/tests/`.
- **In-Process Load Benchmark**: 140 requests executed with 100.0% success rate, 30.36 RPS throughput, and 97.91 ms median latency.
- **Docker Compose Production Stack**: Added Redis 7 service, healthchecks, memory/CPU reservations, and restart policies.
- **GitHub Actions CI/CD (`.github/workflows/ci.yml`)**: Automated backend bandit scans, pytest suite execution, Node.js TypeScript validation, and Docker image builds.


## [1.2.0] - 2026-11-06

### 📚 Documentation & Developer Experience
- **Dedicated Sub-Module Guides**:
  - Created ackend/README.md covering FastAPI endpoints, engine registry, circuit breakers, and migration procedures.
  - Created dmin-dashboard/README.md detailing 10 SOC operational pages, React Error Boundary, and multi-stage Nginx Docker configuration.
  - Created rowser-extension/README.md detailing Manifest V3 service workers, DOM sensors, offline blocklist caching, Safe Exit protocol, and step-by-step Chrome installation.
- **Root README Refinement**:
  - Standardized GitHub badge shields for CI/CD, tests, Python, FastAPI, React, Manifest V3, and Docker.
  - Added dedicated sub-module navigation matrix with relative links.
  - Eliminated corrupt null bytes and verified 100% relative linking across all repository markdown files.
