# 🛡️ FraudShield AI — Reliability, Fault Tolerance & Recovery Guide

This document defines the resilience engineering, circuit breakers, degradation matrix, and automated recovery procedures that ensure **FraudShield AI** maintains continuous operational availability under adverse network conditions, partial dependency outages, and resource contention.

---

## 1. Reliability Architecture Principles

No complex cybersecurity platform is immune to failure. FraudShield AI is designed around **graceful degradation, fault isolation, and automated self-healing**:

1. **Zero-Crash Request Isolation**: An unhandled exception or crash in an individual detection engine, external API, or forensic parser never terminates the ASGI application process or fails the overall scan pipeline.
2. **Defensive Timeouts Everywhere**: Every socket, database query, and external HTTP interaction is bound by an immutable timeout.
3. **Fail-Fast Downstream Circuit Breakers**: If an upstream threat feed is sluggish or down, circuit breakers trip immediately to prevent thread exhaustion.
4. **Offline Edge Autonomy**: The browser extension continues providing baseline phishing and blocklist protection even if the backend API or internet connectivity is completely lost.

---

## 2. Layered Timeout Matrix

To prevent hung threads, connection leaks, and latency cascades, timeouts are strictly enforced across all system layers:

| Layer | Component | Timeout | Behavior on Expiry |
| :--- | :--- | :--- | :--- |
| **API Ingress** | ASGI Worker | 30.0s | Returns `504 Gateway Timeout` with correlation ID |
| **Detection Engine** | `DetectionEngineRegistry` | 3.0s | Drops slow engine, marks finding as partial, continues scan |
| **Threat Intel** | `httpx.AsyncClient` (VT, URLhaus) | 2.0s | Records circuit breaker failure, returns `unavailable` |
| **DNS Resolution** | `InfrastructureAnalyzer` | 1.5s | Defaults to unverified DNS status, proceeds with heuristic scoring |
| **Database Pool** | SQLAlchemy Connection Acquisition | 30.0s | Raises `DatabaseConnectionError`, triggers pooled retry |
| **Forensic Parser** | File Analysis Task | 15.0s | Terminates parsing process, flags file as `UNPROCESSABLE` |
| **Extension API** | `fetchWithRetry` | 4.0s | Falls back to local cached threat blocklist and offline heuristics |

---

## 3. Circuit Breaker Mechanics

External threat intelligence providers are guarded by dedicated `CircuitBreaker` instances (`app/core/circuit_breaker.py`):

```
                        ┌───────────────────────────────┐
                        │      CLOSED (Normal)          │
                        │  All requests pass to remote  │
                        └──────────────┬────────────────┘
                                       │
                         5 Consecutive Failures/Timeouts
                                       │
                                       ▼
                        ┌───────────────────────────────┐
                        │        OPEN (Tripped)         │
                        │  Fails fast (<0.1ms), returns │
                        │  fallback telemetry data      │
                        └──────────────┬────────────────┘
                                       │
                                 60s Cooldown
                                       │
                                       ▼
                        ┌───────────────────────────────┐
                        │     HALF_OPEN (Testing)       │
                        │  Allows single canary probe   │
                        └───────┬───────────────▲───────┘
                                │               │
                    2 Successes │               │ 1 Failure
                                ▼               │
                        ┌───────────────────────┴───────┐
                        │ Back to CLOSED / Reset Count  │
                        └───────────────────────────────┘
```

### Circuit Breaker Diagnostics API
The health status of all circuit breakers is continuously exposed at `/health/ready`:
```json
{
  "status": "ready",
  "dependencies": {
    "database": "connected",
    "circuit_breakers": {
      "VirusTotal": {"state": "CLOSED", "failure_count": 0, "short_circuits": 0},
      "URLhaus": {"state": "OPEN", "failure_count": 5, "short_circuits": 42},
      "PhishTank": {"state": "CLOSED", "failure_count": 0, "short_circuits": 0}
    },
    "ml_model": "loaded"
  }
}
```

---

## 4. Graceful Degradation Matrix

When individual system components fail or degrade, FraudShield AI activates calibrated fallback modes rather than presenting error pages to users:

| Failed Component | Impacted Feature | Fallback Behavior | System Impact |
| :--- | :--- | :--- | :--- |
| **VirusTotal API Down** | Multi-vendor threat feed | Circuit breaker trips; ML + Heuristic engines score URL independently | Zero user impact; risk score marked with `threat_intel: unavailable` |
| **URLhaus API Down** | Malware URL database | Circuit breaker trips; local rule-based heuristic patterns detect payload URLs | Sub-millisecond scan response; no user disruption |
| **PostgreSQL Read Failure** | Threat history & SOC tables | In-memory Redis cache serves read queries; write endpoints queue to Redis buffer | SOC dashboard displays cached telemetry with "Degraded" banner |
| **Redis Cache Down** | Query caching & task queue | Application falls back to direct PostgreSQL queries and synchronous execution | Latency increases by ~15ms; zero data loss |
| **ML Model File Corrupt** | Statistical inference | System falls back to Calibrated Weighted Heuristic Scoring (0–100 scale) | Scoring remains fully functional; XAI outputs heuristic weights |
| **Backend API Unreachable** | Real-time URL scan | Browser extension executes client-side regexes + local LRU threat blocklist | User protected from known threats; notification indicates "Offline Mode" |

---

## 5. Exponential Backoff & Retry Protocol

Client and inter-service HTTP communications utilize **Full Jitter Exponential Backoff**:

$$\text{Delay} = \text{random}(0, \min(M, B \times 2^{\text{attempt}}))$$

Where:
- $B$ (Base delay) = 1.0 second
- $M$ (Max delay) = 30.0 seconds
- Max retry attempts = 3

### Retry Policy Rules:
1. **Idempotent Only**: Retries are permitted only on idempotent requests (`GET`, `PUT`, `DELETE`) or on pre-flight connection failures.
2. **Never Retry on 4xx**: Client errors (`400 Bad Request`, `401 Unauthorized`, `403 Forbidden`, `422 Unprocessable Entity`) fail immediately without retry.
3. **Retry on 5xx & TCP Drops**: Server errors (`502 Bad Gateway`, `503 Service Unavailable`, `504 Gateway Timeout`) trigger backoff retries.

