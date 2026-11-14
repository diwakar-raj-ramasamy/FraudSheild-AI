# 🚀 FraudShield AI — Production Deployment & Operations Guide

This guide provides step-by-step instructions for deploying, configuring, and operating **FraudShield AI** across Docker Compose and Kubernetes environments.

---

## 1. System Requirements & Prerequisites

### Minimum Hardware Specifications
- **CPU**: 2 vCPUs (4+ vCPUs recommended for enterprise scale)
- **RAM**: 4 GB (8+ GB recommended for concurrent file forensic tasks)
- **Disk**: 40 GB SSD (NVMe storage recommended for PostgreSQL indexes)

### Software Prerequisites
- Docker Engine 24.0+ and Docker Compose v2.20+
- PostgreSQL 16+
- Redis 7+
- Node.js 20+ (for building dashboard assets)
- Python 3.12+ (for local development)

---

## 2. Docker Compose Deployment (Recommended for Single-Host / Staging)

The project includes an enterprise-ready `docker-compose.yml` orchestrating PostgreSQL, Redis, FastAPI Backend, and React Admin Dashboard.

### Step 1: Clone and Configure Environment Variables
Create a production `.env` file from `.env.example`:
```bash
cp .env.example .env
```

Ensure critical security variables are populated with high-entropy values:
```ini
ENVIRONMENT=production
SECRET_KEY=generate_with_openssl_rand_hex_32_bytes
POSTGRES_USER=fraudshield_user
POSTGRES_PASSWORD=strong_unique_postgres_password_2026
POSTGRES_DB=fraudshield_db
REDIS_PASSWORD=strong_unique_redis_password_2026
CORS_ORIGINS=https://dashboard.fraudshield.ai,https://soc.fraudshield.ai
TRUST_PROXY_HEADERS=True
```

### Step 2: Build and Launch Services
```bash
docker compose up -d --build
```

### Step 3: Verify Container Health
```bash
docker compose ps
```
Expected output:
```
NAME                    STATUS                    PORTS
fraudshield_postgres    Up (healthy)              0.0.0.0:5432->5432/tcp
fraudshield_redis       Up (healthy)              0.0.0.0:6379->6379/tcp
fraudshield_backend     Up (healthy)              0.0.0.0:8000->8000/tcp
fraudshield_dashboard   Up                        0.0.0.0:5173->80/tcp
```

### Step 4: Apply Database Migrations
Migrations run automatically on container startup or can be triggered manually:
```bash
docker compose exec backend alembic upgrade head
```

---

## 3. Kubernetes Deployment (Production Cluster)

For high-availability multi-node Kubernetes clusters, deploy using the following manifest pattern:

### A. Secret Configuration (`secrets.yaml`)
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: fraudshield-secrets
type: Opaque
stringData:
  SECRET_KEY: "production_secret_key_32_bytes_min"
  DATABASE_URL: "postgresql://fraudshield_user:pass@postgres-service:5432/fraudshield_db"
  REDIS_URL: "redis://:redis_pass@redis-service:6379/0"
```

### B. Backend Deployment with Readiness and Liveness Probes
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fraudshield-backend
spec:
  replicas: 3
  selector:
    matchLabels:
      app: fraudshield-backend
  template:
    metadata:
      labels:
        app: fraudshield-backend
    spec:
      containers:
      - name: backend
        image: fraudshield/backend:v1.0.0
        ports:
        - containerPort: 8000
        envFrom:
        - secretRef:
            name: fraudshield-secrets
        resources:
          limits:
            cpu: "2000m"
            memory: "2048Mi"
          requests:
            cpu: "500m"
            memory: "512Mi"
        livenessProbe:
          httpGet:
            path: /health/live
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 15
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 8000
          initialDelaySeconds: 15
          periodSeconds: 10
```

---

## 4. Production Security & Hardening Checklist

Before going live in production, verify:
- [x] `SECRET_KEY` is cryptographically random (minimum 32 bytes) and never committed to source control.
- [x] `ENVIRONMENT=production` is active (suppresses internal debug traces).
- [x] TLS 1.3 encryption is terminated at the edge reverse proxy / ingress controller.
- [x] Database port `5432` and Redis port `6379` are bound to private internal networks only.
- [x] File upload size limits (30MB ASGI middleware, 25MB forensic engine) are enforced.
- [x] Rate limiting is enabled on public endpoints (`/api/scan/url`, `/api/auth/token`).
- [x] Read-only Docker container root filesystems are configured where possible with dedicated `/tmp` volumes.
- [x] Daily automated database backups are enabled with offsite replication.

