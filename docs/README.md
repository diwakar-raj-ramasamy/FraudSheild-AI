# 📚 FraudShield AI — Documentation & Technical Library

Welcome to the FraudShield AI documentation hub. All technical specifications, security audit findings, architectural diagrams, and operational runbooks are organized here.

---

## 🗂️ Table of Contents

### 1. Architecture & Design
- 🏛️ **[Architecture Specification](ARCHITECTURE.md)**: Modular monolith architecture, `BaseDetectionEngine` interface, `DetectionEngineRegistry`, and `CircuitBreaker` states.
- 📈 **[Scalability Plan](SCALABILITY_PLAN.md)**: Capacity modeling for 100,000+ extensions, 3-tier caching (client, Redis, PostgreSQL), connection pooling, and partitioning.
- 🛡️ **[Reliability & Recovery Guide](RELIABILITY_AND_RECOVERY.md)**: Fault-tolerance principles, layered timeout matrix, failure tracking, and graceful degradation strategies.
- 🗄️ **[Database Architecture](DATABASE_DESIGN.md)**: Complete Entity-Relationship (ER) model, 12 table schemas, composite indexing strategy, and Alembic migration procedures.

### 2. Security & Compliance
- 🔒 **[Security Hardening Guide](SECURITY_HARDENING.md)**: In-depth technical reference for all BOLA/IDOR, anti-spoofing, SSRF, XXE, and formula injection defenses.
- 🛡️ **[Security Policy](SECURITY.md)**: Vulnerability reporting protocols and responsible disclosure terms.
- 📋 **[Security Audit Report](SECURITY_AUDIT_REPORT.md)**: Comprehensive findings from the initial full-system cybersecurity audit.
- 🧪 **[Security Test Results](SECURITY_TEST_RESULTS.md)**: Granular verification results across 60 automated security regression tests.
- 🗃️ **[Vulnerability Register](VULNERABILITY_REGISTER.md)**: Historical tracking register of all identified and resolved vulnerabilities.

### 3. API & Developer Guides
- 📡 **[REST API & WebSockets](API_DOCUMENTATION.md)**: Complete OpenAPI 3.0 specification, health probes (`/health/live`, `/health/ready`), tracing headers, error formats, and pagination.
- 🚀 **[Deployment Guide](DEPLOYMENT_GUIDE.md)**: Instructions for running with Docker Compose or Kubernetes, secrets configuration, and deployment checklists.
- 📊 **[Observability & Monitoring](MONITORING_GUIDE.md)**: Structured JSON logging format, Prometheus metrics scraping, KPI definitions, and alerting thresholds.
- 🚨 **[Disaster Recovery Plan](DISASTER_RECOVERY_PLAN.md)**: RPO/RTO targets, continuous WAL replication, Point-In-Time Recovery (PITR) procedures, and failover runbooks.

### 4. Quality Assurance, Benchmarks & Ledgers
- 🧪 **[Automated Test Report](TESTING_REPORT.md)**: Complete breakdown and coverage report for the 77 automated test cases (100% pass rate).
- ⚡ **[Performance Benchmark Report](PERFORMANCE_REPORT.md)**: Empirical concurrency benchmarks, throughput metrics (30.36 req/sec), and latency distributions.
- 📝 **[Persistent Update Ledger](UPDATE_LOG.md)**: Chronological update audit trail.
- 📜 **[Project Changelog](CHANGELOG.md)**: Semver release notes.
