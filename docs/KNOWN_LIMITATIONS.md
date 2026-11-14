# ⚠️ FraudShield AI — Known Technical Limitations & Scaling Boundaries

**Document Version**: 2.0.0  
**Last Updated**: November 14, 2026  
**Auditor / Maintainer**: Principal Software Architect & Site Reliability Engineer  

---

## 1. Browser Extension Manifest V3 Boundaries

### Service Worker Lifespan & State Persistence
- **Chrome MV3 Lifecycle**: In accordance with Chrome Manifest V3 specifications, the background service worker terminates after approximately 30 seconds of inactivity.
- **Mitigation Implemented**: The extension avoids holding in-memory session state. Tab scan outcomes are persisted to `chrome.storage.local` with associated tab IDs and rehydrated on demand.
- **Limitation**: Timers created with `setTimeout()` or `setInterval()` within the service worker do not persist across worker termination. All recurring background tasks (e.g. blocklist synchronization) must strictly use `chrome.alarms`.

### Pre-Navigation Interception Timing
- **Limitation**: Chrome Manifest V3 does not permit blocking arbitrary network requests synchronously via `webRequestBlocking` (unless using enterprise-managed policies).
- **Behavior**: Fast local blocklist checking uses `chrome.webNavigation.onBeforeNavigate`. This reliably redirects known blocklisted domains before document rendering begins, but initial DNS resolution may occur before navigation completes.

### DOM Signal Visibility
- **Limitation**: Content scripts operate in an isolated JavaScript world. While they can passively inspect form elements, brand keywords, and DOM structure, they cannot access closed Shadow DOM trees created with `{ mode: 'closed' }` or cross-origin iframes without explicit child frame permissions.
- **Privacy Boundary**: In compliance with strict zero-trust privacy standards, FraudShield AI intentionally **does not** log, store, or transmit form input contents, passwords, session tokens, or browser cookies.

---

## 2. Threat Intelligence Provider Boundaries

### External API Quotas & Rate Limits
- **Google Safe Browsing API**: Free tier limits enforcement to 10,000 queries per day.
- **VirusTotal v3 API**: Public API limits requests to 4 requests per minute and 500 requests per day.
- **URLScan.io API**: Public search rate limits apply based on community API keys.
- **Mitigation Implemented**: FraudShield AI wraps each external provider in an independent, stateful `CircuitBreaker` (5 consecutive failures trip to `OPEN` for 60 seconds). If a provider experiences latency or exhausts quota, the backend gracefully falls back to internal heuristics and machine learning without blocking the scan pipeline.

---

## 3. Database Engine & Concurrency Boundaries

### SQLite Embedded Database Mode
- **Concurrency Model**: SQLite with Write-Ahead Logging (`PRAGMA journal_mode = WAL;`) supports multiple simultaneous readers with a single serialized writer.
- **Throughput Boundary**: Under high-volume ingestion (>100 write transactions per second), SQLite lock contention may trigger busy timeouts.
- **Mitigation Implemented**: Configured `PRAGMA busy_timeout = 5000;`, connection pooling with `check_same_thread = False`, and atomic transaction scopes.
- **Production Recommendation**: For multi-node containerized deployments with horizontal backend scaling, transition to managed **PostgreSQL** by configuring `DATABASE_URL=postgresql://user:pass@host:5432/fraudshield`. The SQLAlchemy models and Alembic migrations are 100% PostgreSQL-compatible.

---

## 4. File Forensic Parser Boundaries

### Archive Decompression Constraints
- **Zip Bomb Defense Limits**:
  - Maximum uncompressed archive size: **50 MB**
  - Maximum archive entry count: **1,000 files**
  - Maximum compression ratio: **100:1**
- **Encrypted / Password-Protected Archives**: Password-encrypted DOCX/XLSX or ZIP archives cannot be statically unpacked without credentials and are flagged as `ENCRYPTED_ARCHIVE_UNINSPECTED` with caution-level scoring.

### Macro & Embedded Script Neutralization
- **Static Analysis Only**: File forensic parsers perform **static parsing** exclusively. They extract VBA macro code streams, external relationship URLs, and DTD entity injections, but **never execute** macros, formulas, or binary payloads in a sandbox environment.

---

## 5. Machine Learning Classifier Boundaries

### Lexical Feature Scope
- **Lexical Vector Limitations**: The scikit-learn classifier operates on 13 lexical URL features (lengths, entropy, character counts, keyword densities, TLD classifications). It does not dynamically render client-side JavaScript before inference.
- **Mitigation Implemented**: The client-side browser content script supplements lexical ML predictions by extracting live DOM structural indicators (login forms, brand strings, suspicious script counts) and passing them as `dom_signals` to the hybrid scoring pipeline.

---

## 6. Recommended Infrastructure Scaling Roadmap

| Tier | Concurrent Users | Database Destination | Cache / Bus | Deployment Target |
|---|---|---|---|---|
| **Development / Single Node** | 1 – 50 | Embedded SQLite (WAL) | In-Memory Async EventBus | Local / Single Docker Container |
| **Enterprise SOC (Standard)** | 50 – 1,000 | PostgreSQL 16 (RDS / Cloud SQL) | Redis 7 Sentinel / PubSub | Docker Compose / ECS |
| **Global High-Throughput** | 1,000 – 100,000+ | Distributed PostgreSQL (CockroachDB / Citus) | Redis Cluster + Celery / Kafka | Kubernetes (EKS / GKE) with HPA |

