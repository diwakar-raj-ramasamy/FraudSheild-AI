# 🗄️ FraudShield AI — Database Architecture & Schema Specification

This document provides the complete database design, Entity-Relationship (ER) model, indexing strategy, Alembic migration workflow, and query optimization guidelines for **FraudShield AI**.

---

## 1. Entity-Relationship Diagram (ERD)

```mermaid
erDiagram
    USERS {
        uuid id PK
        string email UK
        string hashed_password
        string full_name
        string role
        boolean is_active
        timestamp created_at
    }

    DEVICES {
        uuid id PK
        string installation_pseudonym UK
        string extension_version
        string user_agent
        timestamp created_at
        timestamp last_seen
    }

    URL_RECORDS {
        uuid id PK
        string normalized_url
        string domain
        string url_hash UK
        string classification
        integer current_risk_score
        timestamp first_seen
        timestamp last_seen
    }

    SCAN_RESULTS {
        uuid id PK
        uuid url_id FK
        uuid device_id FK
        integer risk_score
        string classification
        json attack_types
        json findings
        json recommended_actions
        float ml_score
        json threat_intel_data
        json xai_factors
        timestamp created_at
    }

    DETECTION_EVENTS {
        uuid id PK
        uuid url_id FK
        uuid device_id FK
        integer risk_score
        string classification
        json attack_types
        string page_title
        string referrer
        timestamp detected_at
    }

    FRAUD_CAMPAIGNS {
        uuid id PK
        string campaign_name
        string domain
        integer total_detections
        integer affected_devices_count
        string status
        timestamp first_seen
        timestamp last_seen
    }

    ADMIN_ALERTS {
        uuid id PK
        string alert_type
        string severity
        string message
        json details
        boolean is_read
        boolean is_resolved
        timestamp created_at
    }

    BLOCKLIST_ENTRIES {
        uuid id PK
        string target UK
        string target_type
        string reason
        string severity
        string added_by
        boolean is_active
        timestamp created_at
    }

    BLOCKLIST_META {
        integer id PK
        integer version
        timestamp updated_at
    }

    INFRASTRUCTURE_RECORDS {
        uuid id PK
        string domain UK
        string observed_ip
        json resolved_ips
        string asn
        string asn_org
        string reverse_dns
        json dns_records
        json ssl_info
        timestamp observed_at
    }

    DANGEROUS_DOWNLOADS {
        uuid id PK
        uuid device_id FK
        string file_name
        string file_hash_sha256
        string download_url
        string source_domain
        integer file_size_bytes
        string mime_type
        integer risk_score
        string classification
        json detected_threats
        timestamp detected_at
    }

    FILE_ANALYSES {
        uuid id PK
        string original_filename
        string file_hash_sha256 UK
        string mime_type
        integer file_size_bytes
        integer risk_score
        string classification
        json static_indicators
        json extracted_urls
        json extracted_ips
        json xai_explanations
        string analyst_notes
        timestamp created_at
    }

    URL_RECORDS ||--o{ SCAN_RESULTS : "evaluated in"
    DEVICES ||--o{ SCAN_RESULTS : "submitted"
    URL_RECORDS ||--o{ DETECTION_EVENTS : "triggered by"
    DEVICES ||--o{ DETECTION_EVENTS : "reported from"
    DEVICES ||--o{ DANGEROUS_DOWNLOADS : "intercepted on"
```

---

## 2. Table Specifications & Indexing Strategy

To support high-throughput scans, low-latency search, and time-series aggregations, indexes are placed on equality lookups, foreign keys, and sorting fields:

### A. `detection_events`
- `ix_detection_events_detected_at` (`detected_at` DESC): Accelerates dashboard time-series queries.
- `ix_detection_events_risk_score` (`risk_score`): Filters high-severity events.
- `ix_detection_events_classification` (`classification`): Accelerates categorical queries (`CRITICAL`, `CAUTION`, `SAFE`).
- `ix_detection_events_url_detected` (`url_id`, `detected_at`): Composite index for domain-level event aggregation.
- `ix_detection_events_device_detected` (`device_id`, `detected_at`): Composite index for unique device correlation.

### B. `scan_results`
- `ix_scan_results_created_at` (`created_at` DESC): Accelerates recent scan feeds.
- `ix_scan_results_risk_score` (`risk_score`): Fast threshold filtering.
- `ix_scan_results_classification` (`classification`): Fast classification filtering.
- `ix_scan_results_url_created` (`url_id`, `created_at`): Composite index for URL scan history.

### C. `fraud_campaigns`
- `ix_fraud_campaigns_status` (`status`): Fast lookup for `ACTIVE` campaigns.
- `ix_fraud_campaigns_first_seen` / `ix_fraud_campaigns_last_seen`: Time-range queries for SOC reports.

### D. `admin_alerts`
- `ix_admin_alerts_alert_type` / `ix_admin_alerts_severity`: Filtering by threat category and impact.
- `ix_admin_alerts_is_read` / `ix_admin_alerts_is_resolved`: Fast unread queue indexing.
- `ix_admin_alerts_created_at` (`created_at` DESC): Timeline ordering.

### E. `blocklist_entries`
- `ix_blocklist_entries_is_active` (`is_active`): Accelerates client blocklist synchronization (`/api/blocklist/version`).

### F. `infrastructure_records`
- `ix_infrastructure_records_observed_at`: Timeline tracking of IP and ASN migration.
- `ix_infrastructure_records_observed_ip`: Correlation across multiple phishing domains sharing the same hosting IP.

---

## 3. Query Optimization Guidelines

### 1. Eliminating N+1 Query Patterns
Never query child relationships inside an iteration loop. Use SQLAlchemy `joinedload` or batch `IN` queries:
```python
# HIGH PERFORMANCE: Single SQL query with JOIN
events = db.query(DetectionEvent)\
    .options(joinedload(DetectionEvent.device))\
    .options(joinedload(DetectionEvent.url_record))\
    .order_by(DetectionEvent.detected_at.desc())\
    .offset(skip).limit(limit).all()
```

### 2. Paginating All Record Collections
Every collection endpoint MUST enforce `limit` and `skip` query parameters:
```python
@router.get("", response_model=List[ThreatOut])
def list_threats(
    limit: int = Query(50, ge=1, le=500),
    skip: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    return db.query(ScanResult).offset(skip).limit(limit).all()
```

### 3. Database-Side Aggregations
Avoid loading records into Python memory to compute metrics. Let the database engine execute aggregations:
```python
# Database-Side Count and Distinct Aggregation
total_count = db.query(func.count(DetectionEvent.id)).filter(...).scalar()
unique_devices = db.query(func.count(func.distinct(DetectionEvent.device_id))).filter(...).scalar()
```

---

## 4. Alembic Database Migration Management

The repository uses Alembic for declarative schema versioning:

### Initializing and Applying Migrations:
```bash
# Apply pending migrations to database head
cd backend
venv\Scripts\alembic upgrade head

# Generate a new auto-detected migration
venv\Scripts\alembic revision --autogenerate -m "Add composite index on detection events"

# Inspect migration history
venv\Scripts\alembic history --verbose

# Roll back by one migration revision
venv\Scripts\alembic downgrade -1
```

### Migration Integrity Rules:
- All schema alterations MUST be executed through Alembic revisions; never alter production database tables manually via raw SQL.
- Migration scripts must include both `upgrade()` and clean `downgrade()` methods.
- Column additions must provide nullable defaults or server defaults to prevent locking large tables.

