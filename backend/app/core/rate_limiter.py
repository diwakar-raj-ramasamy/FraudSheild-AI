"""
FraudShield AI Rate Limiting Middleware / Dependency
Implements an in-memory sliding-window rate limiter per client IP.
Protects sensitive API endpoints from brute-force authentication, scan denial-of-service,
and file analysis abuse.
"""

import time
import os
from collections import defaultdict
from typing import Dict, List
from fastapi import Request, HTTPException, status

class InMemoryRateLimiter:
    def __init__(self, requests_limit: int, window_seconds: int, scope: str = "default"):
        self.requests_limit = requests_limit
        self.window_seconds = window_seconds
        self.scope = scope
        self._history: Dict[str, List[float]] = defaultdict(list)

    def _get_client_ip(self, request: Request) -> str:
        # Secure IP resolution: Only trust reverse-proxy headers if configured
        trust_proxy = os.getenv("TRUST_PROXY_HEADERS", "0") == "1"
        if trust_proxy:
            forwarded_for = request.headers.get("X-Forwarded-For")
            if forwarded_for:
                candidate = forwarded_for.split(",")[0].strip()
                if candidate:
                    return candidate
            real_ip = request.headers.get("X-Real-IP")
            if real_ip:
                return real_ip.strip()

        if request.client and request.client.host:
            return request.client.host
        return "127.0.0.1"

    async def __call__(self, request: Request):
        # Allow disabling rate limiting in specific test mode if explicitly configured
        if os.getenv("TESTING_DISABLE_RATE_LIMIT") == "1":
            return

        client_ip = self._get_client_ip(request)
        now = time.time()
        cutoff = now - self.window_seconds

        timestamps = [t for t in self._history[client_ip] if t > cutoff]
        if len(timestamps) >= self.requests_limit:
            retry_after = int(self.window_seconds - (now - timestamps[0])) + 1
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded for {self.scope}. Limit is {self.requests_limit} requests per {self.window_seconds} seconds.",
                headers={"Retry-After": str(max(1, retry_after))}
            )

        timestamps.append(now)
        self._history[client_ip] = timestamps

    def reset(self):
        """Clears rate limit state (useful in test teardown)."""
        self._history.clear()


# Pre-configured rate limiters for key routes
auth_rate_limiter = InMemoryRateLimiter(requests_limit=10, window_seconds=60, scope="Authentication")
scan_rate_limiter = InMemoryRateLimiter(requests_limit=120, window_seconds=60, scope="Threat Scanning")
file_rate_limiter = InMemoryRateLimiter(requests_limit=20, window_seconds=60, scope="File Forensics Upload")

