import os
import pytest
import signal
import asyncio
from datetime import timedelta
import httpx
from asyncio import proactor_events
import anyio.to_thread

# Isolate test database so test executions never touch or pollute production database
os.environ["DATABASE_URL"] = "sqlite:///./test_runner_fraudshield.db"
os.environ["ENVIRONMENT"] = "testing"

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

@pytest.fixture(scope="session", autouse=True)
def setup_database():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    # Ensure test admin and analyst accounts exist
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

    yield

    engine.dispose()
    try:
        if os.path.exists("./test_runner_fraudshield.db"):
            os.remove("./test_runner_fraudshield.db")
    except Exception:
        pass

@pytest.fixture
def client():
    return httpx.Client(transport=FastASGITransport(app), base_url="http://testserver", follow_redirects=True)

@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()

@pytest.fixture
def admin_token():
    return create_access_token(subject="admin@fraudshield.ai", role="admin", expires_delta=timedelta(hours=1))

@pytest.fixture
def analyst_token():
    return create_access_token(subject="analyst@fraudshield.ai", role="analyst", expires_delta=timedelta(hours=1))

@pytest.fixture
def expired_token():
    return create_access_token(subject="admin@fraudshield.ai", role="admin", expires_delta=timedelta(minutes=-10))

@pytest.fixture
def admin_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}

@pytest.fixture
def analyst_headers(analyst_token):
    return {"Authorization": f"Bearer {analyst_token}"}


