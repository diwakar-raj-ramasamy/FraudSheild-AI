# 📊 FraudShield AI — Observability, Logging & Monitoring Guide

This guide defines the observability architecture, structured JSON logging format, health probe contracts, metric instrumentation, and alerting thresholds for **FraudShield AI**.

---

## 1. Observability Architecture

```mermaid
flowchart LR
    subgraph App ["FraudShield AI Application"]
        LOG[Structured JSON Logs contextvars]
        LIVE[/health/live Liveness Probe]
        READY[/health/ready Readiness Probe]
        METRIC[Prometheus Metric Collector]
    end

    subgraph Ingestion ["Log & Metric Collectors"]
        PROM[Prometheus Server]
        FLUENT[Vector / Fluentbit]
    end

    subgraph Visualization ["Observability & SOC Alerting"]
        GRAF[Grafana Dashboards]
        SIEM[SIEM Splunk / Elastic]
        PAGER[PagerDuty / OpsGenie]
    end

    LOG -->|stdout| FLUENT
    FLUENT --> SIEM
    READY & LIVE -->|HTTP Scrape 10s| PROM
    METRIC -->|HTTP Scrape 15s| PROM
    PROM --> GRAF
    PROM -->|Alert Trigger| PAGER
```

---

## 2. Structured JSON Logging Specification

Every log line is formatted as a single-line JSON string (`app.core.logging_config.StructuredJsonFormatter`), facilitating zero-transformation ingestion into Splunk, Elasticsearch, or Datadog.

### Standard Log Schema:
```json
{
  "timestamp": "2026-11-06T08:14:25.102Z",
  "level": "INFO",
  "name": "fraudshield.scan_service",
  "message": "Hybrid scan completed for target url: https://secure-login-portal-auth.com",
  "correlation_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "duration_ms": 118.4,
  "client_ip": "192.0.2.45",
  "method": "POST",
  "path": "/api/scan/url",
  "status_code": 200
}
```

### Key Log Fields:
- `timestamp`: ISO 8601 UTC timestamp with millisecond resolution.
- `level`: RFC 5424 standard severity (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`).
- `correlation_id`: Unique transaction identifier propagated via `X-Correlation-ID`.
- `duration_ms`: Execution time in milliseconds.

---

## 3. Health & Readiness Probe Contracts

### 1. Liveness Probe (`GET /health/live`)
- **Intent**: Checks whether the Python process and ASGI event loop are responsive.
- **Fail Scenario**: Thread deadlock, event loop freeze, out of memory.
- **Orchestrator Action**: Container restart.
- **Expected Response**: `200 OK`
```json
{
  "status": "alive",
  "service": "FraudShield AI"
}
```

### 2. Readiness Probe (`GET /health/ready`)
- **Intent**: Verifies downstream connectivity to PostgreSQL database, ML model loading, and circuit breaker status before routing ingress traffic to the pod.
- **Fail Scenario**: Database unreachable, unmigrated schema, corrupt ML weights.
- **Orchestrator Action**: Pod removed from load balancer pool (traffic redirected to healthy replicas).
- **Expected Response**: `200 OK` (or `503 Service Unavailable` on degraded dependencies).
```json
{
  "status": "ready",
  "dependencies": {
    "database": "connected",
    "circuit_breakers": {
      "VirusTotal": { "state": "CLOSED", "failure_count": 0, "short_circuits": 0 },
      "URLhaus": { "state": "OPEN", "failure_count": 5, "short_circuits": 12 },
      "PhishTank": { "state": "CLOSED", "failure_count": 0, "short_circuits": 0 }
    },
    "ml_model": "loaded"
  }
}
```

---

## 4. Key Performance Indicators (KPIs) & Alerting Rules

| Metric | Target / SLO | Warning Threshold | Critical Alert Threshold |
| :--- | :--- | :--- | :--- |
| **API Availability** | $\ge 99.95\%$ | $< 99.9\%$ for 5 min | $< 99.5\%$ for 2 min |
| **Median Scan Latency (p50)** | $< 150\text{ ms}$ | $> 300\text{ ms}$ for 5 min | $> 500\text{ ms}$ for 3 min |
| **95th Percentile Latency (p95)**| $< 400\text{ ms}$ | $> 800\text{ ms}$ for 5 min | $> 1,200\text{ ms}$ for 3 min |
| **Database Connection Pool** | $< 70\%$ | $> 75\%$ capacity | $> 90\%$ capacity |
| **Circuit Breakers Tripped** | 0 OPEN | 1 provider OPEN | 2+ providers OPEN |
| **HTTP 5xx Error Rate** | $< 0.1\%$ | $> 0.5\%$ of requests | $> 2.0\%$ of requests |
| **Disk Space (DB / Storage)** | $> 30\%$ free | $< 20\%$ free | $< 10\%$ free |

---

## 5. Prometheus Scraping Configuration

Add to `prometheus.yml`:
```yaml
scrape_configs:
  - job_name: 'fraudshield-backend'
    scrape_interval: 15s
    metrics_path: '/metrics'
    static_configs:
      - targets: ['backend:8000']
    metric_relabel_configs:
      - source_labels: [__name__]
        regex: '(http_requests_total|http_request_duration_seconds|db_pool_active_connections|circuit_breaker_trips_total)'
        action: keep
```

