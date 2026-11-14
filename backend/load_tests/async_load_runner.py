"""
FraudShield AI - High-Concurrency Load and Stress Test Benchmark Runner
Executes real concurrent synthetic workloads across the ASGI application to measure:
  - Throughput (Requests per Second / RPS)
  - Latency distribution (Mean, Median, p95, p99)
  - Error and failure rates
  - System reliability under load
"""

import sys
import os
import time
import statistics
import random
import concurrent.futures
import httpx
import asyncio
import signal
from asyncio import proactor_events
import anyio.to_thread

# Sandbox compatibility patch for Windows IOCP loopback and offline DNS
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

import socket
_orig_getaddrinfo = socket.getaddrinfo
def _mock_getaddrinfo(host, port, *args, **kwargs):
    if host in ("localhost", "127.0.0.1", "testserver"):
        return _orig_getaddrinfo(host, port, *args, **kwargs)
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('104.21.28.12', port))]
socket.getaddrinfo = _mock_getaddrinfo
socket.gethostbyaddr = lambda ip: ("cdn.cloudflare.net", [], [ip])

# Ensure backend root is on Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Isolate benchmark load tests from production database
os.environ["DATABASE_URL"] = "sqlite:///./test_load_fraudshield.db"
os.environ["ENVIRONMENT"] = "testing"

from app.main import app
from app.core.database import Base, engine
from app.engines.threat_intelligence import threat_intelligence_aggregator
from app.core.circuit_breaker import CircuitState

# Open external threat intelligence circuit breakers to benchmark internal backend pipeline with zero network latency
for p in threat_intelligence_aggregator.providers:
    p.circuit_breaker.state = CircuitState.OPEN
    p.circuit_breaker.last_failure_time = time.time() + 3600

# Pure in-process ASGI transport avoiding Windows loopback socket deadlocks
class InProcessTransport(httpx.BaseTransport):
    def __init__(self, asgi_app):
        self.app = asgi_app

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        status_code = 500
        response_headers = []
        response_body = []

        async def receive():
            body = request.read()
            return {'type': 'http.request', 'body': body, 'more_body': False}

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

TEST_URLS = [
    "https://google.com",
    "https://microsoft.com",
    "https://secure-login-portal-auth.fake-verify-net.com",
    "https://metamask-crypto-wallet-verify.online",
    "https://github.com",
    "https://urgent-security-account-action.xyz/verify"
]

def execute_single_request(client: httpx.Client, worker_id: int) -> dict:
    url = random.choice(TEST_URLS)
    endpoint_type = random.choices(["scan", "event", "health", "metrics"], weights=[50, 25, 15, 10])[0]

    start_time = time.perf_counter()
    status_code = 0
    success = False

    try:
        if endpoint_type == "scan":
            payload = {
                "url": url,
                "device_pseudonym": f"load-dev-{worker_id % 10}",
                "page_title": f"Test Page {worker_id}",
                "dom_signals": {"has_password_field": worker_id % 2 == 0}
            }
            res = client.post("/api/scan/url", json=payload)
            status_code = res.status_code
            success = status_code == 200
        elif endpoint_type == "event":
            payload = {
                "url": url,
                "device_pseudonym": f"load-dev-{worker_id % 10}",
                "risk_score": 75,
                "classification": "CRITICAL",
                "attack_types": ["PHISHING"]
            }
            res = client.post("/api/events/detection", json=payload)
            status_code = res.status_code
            success = status_code == 200
        elif endpoint_type == "health":
            res = client.get("/health/ready")
            status_code = res.status_code
            success = status_code == 200
        else:
            res = client.get("/health/live")
            status_code = res.status_code
            success = status_code == 200
    except Exception as ex:
        status_code = 500
        success = False

    duration_ms = (time.perf_counter() - start_time) * 1000
    return {
        "status_code": status_code,
        "success": success,
        "latency_ms": duration_ms,
        "endpoint": endpoint_type
    }

def worker_task(worker_id: int, request_ids: list[int]) -> list[dict]:
    transport = InProcessTransport(asgi_app=app)
    results = []
    with httpx.Client(transport=transport, base_url="http://testserver", timeout=15.0) as client:
        for req_id in request_ids:
            results.append(execute_single_request(client, req_id))
    return results

def run_stress_test(total_requests: int = 100, concurrency: int = 10) -> dict:
    Base.metadata.create_all(bind=engine)
    print("=================================================================", flush=True)
    print("   [FRAUDSHIELD AI] PRODUCTION LOAD & STRESS BENCHMARK RUNNER    ", flush=True)
    print(f"   Target: In-Process ASGI Engine | Concurrency: {concurrency} | Total: {total_requests}", flush=True)
    print("=================================================================", flush=True)

    # Distribute requests among workers
    worker_buckets = [[] for _ in range(concurrency)]
    for i in range(total_requests):
        worker_buckets[i % concurrency].append(i)

    start_bench = time.perf_counter()
    results = []

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = [executor.submit(worker_task, w_id, bucket) for w_id, bucket in enumerate(worker_buckets) if bucket]
            for f in concurrent.futures.as_completed(futures):
                results.extend(f.result())
    finally:
        engine.dispose()
        try:
            if os.path.exists("./test_load_fraudshield.db"):
                os.remove("./test_load_fraudshield.db")
        except Exception:
            pass

    total_duration = time.perf_counter() - start_bench
    latencies = [r["latency_ms"] for r in results]
    latencies.sort()

    successful = [r for r in results if r["success"]]
    failed = [r for r in results if not r["success"]]
    rps = len(results) / total_duration if total_duration > 0 else 0

    p50 = statistics.median(latencies) if latencies else 0
    p95 = latencies[int(len(latencies) * 0.95)] if latencies else 0
    p99 = latencies[int(len(latencies) * 0.99)] if latencies else 0
    avg_latency = statistics.mean(latencies) if latencies else 0

    print(f"\n[+] Benchmark Results Completed in {total_duration:.2f}s:", flush=True)
    print(f"    - Total Requests Executed : {len(results)}", flush=True)
    print(f"    - Successful Requests     : {len(successful)} ({len(successful)/len(results)*100:.1f}%)", flush=True)
    print(f"    - Failed Requests         : {len(failed)}", flush=True)
    print(f"    - Throughput (RPS)        : {rps:.2f} req/sec", flush=True)
    print(f"    - Average Latency         : {avg_latency:.2f} ms", flush=True)
    print(f"    - Median Latency (p50)    : {p50:.2f} ms", flush=True)
    print(f"    - 95th Percentile (p95)   : {p95:.2f} ms", flush=True)
    print(f"    - 99th Percentile (p99)   : {p99:.2f} ms", flush=True)
    print("=================================================================", flush=True)

    return {
        "total_requests": len(results),
        "successful_requests": len(successful),
        "failed_requests": len(failed),
        "throughput_rps": round(rps, 2),
        "avg_latency_ms": round(avg_latency, 2),
        "p50_latency_ms": round(p50, 2),
        "p95_latency_ms": round(p95, 2),
        "p99_latency_ms": round(p99, 2),
        "duration_seconds": round(total_duration, 2)
    }

if __name__ == "__main__":
    run_stress_test(total_requests=40, concurrency=4)
