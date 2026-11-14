import os
import sys
import signal
import asyncio
from datetime import timedelta
import httpx
from asyncio import proactor_events
import anyio.to_thread

# Set isolated test database environment
os.environ["DATABASE_URL"] = "sqlite:///./test_independent_backend.db"
os.environ["ENVIRONMENT"] = "testing"

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.abspath("backend"))

# Sandbox compatibility patch for Windows IOCP loopback
signal.set_wakeup_fd = lambda fd, *args, **kwargs: -1
class FakeSock:
    def fileno(self): return -1
    def setblocking(self, b): pass
    def close(self): pass
    def send(self, b): return len(b)
    def recv(self, n): return b''

proactor_events.BaseProactorEventLoop._make_self_pipe = lambda self: (
    setattr(self, '_ssock', FakeSock()),
    setattr(self, '_csock', FakeSock()),
    setattr(self, '_internal_fds', self._internal_fds + 1)
)
proactor_events.BaseProactorEventLoop._close_self_pipe = lambda self: None
proactor_events.BaseProactorEventLoop._loop_self_reading = lambda self, f=None: None

async def _sync_runner(func, *args, **kwargs):
    return func(*args)

anyio.to_thread.run_sync = _sync_runner

from app.main import app
from app.core.database import SessionLocal, engine, Base
from app.core.security import create_access_token, get_password_hash
from app.models import User

class FastASGITransport(httpx.BaseTransport):
    def __init__(self, asgi_app):
        self.app = asgi_app

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        status_code = 500
        response_headers = []
        response_body = []
        body = request.read()
        sent_body = False

        async def receive():
            nonlocal sent_body
            if not sent_body:
                sent_body = True
                return {'type': 'http.request', 'body': body, 'more_body': False}
            return {'type': 'http.disconnect'}

        async def send(message):
            nonlocal status_code
            if message['type'] == 'http.response.start':
                status_code = message['status']
                response_headers.extend(message.get('headers', []))
            elif message['type'] == 'http.response.body':
                response_body.append(message.get('body', b''))

        scope = {
            'type': 'http',
            'asgi': {'version': '3.0'},
            'http_version': '1.1',
            'method': request.method,
            'path': request.url.path,
            'raw_path': request.url.raw_path.split(b'?', 1)[0],
            'query_string': request.url.query,
            'headers': [(k.lower().encode(), v.encode()) for k, v in request.headers.items()],
            'client': ('127.0.0.1', 12345),
            'server': ('testserver', 80),
            'scheme': request.url.scheme,
        }

        asyncio.run(self.app(scope, receive, send))
        return httpx.Response(
            status_code=status_code,
            headers=response_headers,
            content=b''.join(response_body),
            request=request
        )

# Initialize database
Base.metadata.create_all(bind=engine)
db = SessionLocal()

# Seed admin and analyst accounts
admin_user = db.query(User).filter(User.email == "admin@fraudshield.ai").first()
if not admin_user:
    admin_user = User(
        email="admin@fraudshield.ai",
        hashed_password=get_password_hash("Admin@FraudShield2026!"),
        full_name="Security Admin",
        role="admin",
        is_active=True
    )
    db.add(admin_user)

analyst_user = db.query(User).filter(User.email == "analyst@fraudshield.ai").first()
if not analyst_user:
    analyst_user = User(
        email="analyst@fraudshield.ai",
        hashed_password=get_password_hash("Analyst@FraudShield2026!"),
        full_name="Junior Analyst",
        role="analyst",
        is_active=True
    )
    db.add(analyst_user)

db.commit()
db.close()

# Tokens
admin_token = create_access_token(subject="admin@fraudshield.ai", role="admin", expires_delta=timedelta(hours=1))
analyst_token = create_access_token(subject="analyst@fraudshield.ai", role="analyst", expires_delta=timedelta(hours=1))

admin_headers = {"Authorization": f"Bearer {admin_token}"}
analyst_headers = {"Authorization": f"Bearer {analyst_token}"}

client = httpx.Client(transport=FastASGITransport(app), base_url="http://testserver", follow_redirects=True)

results = []

def record(test_name: str, passed: bool, detail: str = ""):
    status = "PASS" if passed else "FAIL"
    results.append({"test": test_name, "status": status, "detail": detail})
    print(f"[{status}] {test_name}: {detail}")

try:
    print("\n--- 1. HEALTH CHECKS ---")
    r = client.get("/health/live")
    record("Health Live Endpoint", r.status_code == 200 and r.json().get("status") == "alive")

    r = client.get("/health/ready")
    record("Health Ready Endpoint", r.status_code == 200 and r.json().get("status") == "healthy")

    print("\n--- 2. AUTHENTICATION & RBAC ---")
    # Public access check on me endpoint
    r = client.get("/api/auth/me")
    record("Unauthenticated /auth/me returns 401", r.status_code == 401)

    # Analyst access on me endpoint
    r = client.get("/api/auth/me", headers=analyst_headers)
    record("Analyst access /auth/me returns 200", r.status_code == 200 and r.json().get("email") == "analyst@fraudshield.ai")

    # Admin access on me endpoint
    r = client.get("/api/auth/me", headers=admin_headers)
    record("Admin access /auth/me returns 200", r.status_code == 200 and r.json().get("role") == "admin")

    # RBAC: Analyst attempting Admin operation (add blocklist entry)
    r = client.post("/api/blocklist", json={"target": "malicious-test.com", "target_type": "DOMAIN", "reason": "Test", "severity": "CRITICAL"}, headers=analyst_headers)
    record("RBAC: Analyst forbidden from adding blocklist (403)", r.status_code == 403)

    # Admin can add blocklist
    r = client.post("/api/blocklist", json={"target": "malicious-test.com", "target_type": "DOMAIN", "reason": "Test", "severity": "CRITICAL"}, headers=admin_headers)
    blocklist_id = r.json().get("id") if r.status_code == 200 else None
    record("RBAC: Admin can add blocklist (200)", r.status_code == 200 and blocklist_id is not None)

    # Admin can delete blocklist
    if blocklist_id:
        r = client.delete(f"/api/blocklist/{blocklist_id}", headers=admin_headers)
        record("RBAC: Admin can delete blocklist (200)", r.status_code == 200)

    print("\n--- 3. INPUT VALIDATION & MALFORMED PAYLOADS ---")
    # Malformed URL scan
    r = client.post("/api/scan/url", json={"url": "not-a-valid-url-format"})
    record("Scan malformed URL handled safely", r.status_code in [200, 422])

    # Empty URL
    r = client.post("/api/scan/url", json={"url": ""})
    record("Scan empty URL rejected (422)", r.status_code == 422)

    # SQL Injection attempt in URL
    r = client.post("/api/scan/url", json={"url": "http://example.com/' OR '1'='1"})
    record("SQL Injection in URL handled safely without crash", r.status_code == 200)

    # Device registration with invalid pseudonym (< 8 chars)
    r = client.post("/api/devices/register", json={"installation_pseudonym": "short"})
    record("Device invalid pseudonym rejected (422)", r.status_code == 422)

    # Device registration with valid UUID
    r = client.post("/api/devices/register", json={"installation_pseudonym": "12345678-1234-1234-1234-1234567890ab", "extension_version": "1.0.0"})
    record("Device valid pseudonym registered (200)", r.status_code == 200)

    print("\n--- 4. SOC ENDPOINTS & REPORTING ---")
    # Overview
    r = client.get("/api/metrics/overview", headers=admin_headers)
    record("Metrics Overview (200)", r.status_code == 200 and "metrics" in r.json())

    # Security Report
    r = client.get("/api/metrics/report", headers=admin_headers)
    record("Security Report (200)", r.status_code == 200 and "report_id" in r.json())

    # Threats CSV export
    r = client.get("/api/metrics/export-threats-csv", headers=admin_headers)
    record("Threats CSV Export (200 text/csv)", r.status_code == 200 and "text/csv" in r.headers.get("content-type", ""))

    # Campaigns
    r = client.get("/api/campaigns", headers=admin_headers)
    record("Campaigns list (200)", r.status_code == 200 and isinstance(r.json(), list))

    # Alerts
    r = client.get("/api/alerts", headers=admin_headers)
    record("Alerts list (200)", r.status_code == 200 and isinstance(r.json(), list))

    # Downloads
    r = client.get("/api/downloads", headers=admin_headers)
    record("Downloads list (200)", r.status_code == 200 and isinstance(r.json(), list))

    # Devices
    r = client.get("/api/devices", headers=admin_headers)
    record("Devices list (200)", r.status_code == 200 and isinstance(r.json(), list))

    # Events
    r = client.get("/api/events", headers=admin_headers)
    record("Events list (200)", r.status_code == 200 and isinstance(r.json(), list))

finally:
    client.close()
    engine.dispose()
    try:
        if os.path.exists("./test_independent_backend.db"):
            os.remove("./test_independent_backend.db")
    except Exception:
        pass

pass_count = sum(1 for res in results if res["status"] == "PASS")
fail_count = sum(1 for res in results if res["status"] == "FAIL")
print(f"\n==========================================")
print(f"Backend Test Summary: {pass_count} PASSED, {fail_count} FAILED out of {len(results)}")
print(f"==========================================")
