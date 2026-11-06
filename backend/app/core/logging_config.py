import json
import logging
import time
import uuid
from contextvars import ContextVar
from typing import Optional
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# Context variable preserving correlation ID across async task contexts
correlation_id_ctx: ContextVar[str] = ContextVar("correlation_id", default="system")

class StructuredJsonFormatter(logging.Formatter):
    """
    JSON log formatter enriching logs with timestamp, level, correlation ID,
    logger name, and message for ELK, Grafana Loki, or CloudWatch ingestion.
    """
    def format(self, record: logging.LogRecord) -> str:
        log_obj = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "correlation_id": correlation_id_ctx.get(),
            "message": record.getMessage(),
        }
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_obj)

def setup_logging():
    """Initializes structured logging across the application."""
    root_logger = logging.getLogger()
    handler = logging.StreamHandler()
    handler.setFormatter(StructuredJsonFormatter())
    root_logger.handlers = [handler]
    root_logger.setLevel(logging.INFO)

class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """
    Ensures every request carries a correlation ID (from X-Correlation-ID / X-Request-ID
    or newly generated). Propagates it in headers and log context.
    """
    async def dispatch(self, request: Request, call_next):
        req_id = (
            request.headers.get("X-Correlation-ID")
            or request.headers.get("X-Request-ID")
            or str(uuid.uuid4())
        )
        token = correlation_id_ctx.set(req_id)
        start_time = time.perf_counter()

        try:
            response: Response = await call_next(request)
            response.headers["X-Correlation-ID"] = req_id
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            response.headers["X-Response-Time-MS"] = str(duration_ms)
            return response
        finally:
            correlation_id_ctx.reset(token)

class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """
    Enforces maximum request body size limits to prevent Denial of Service via memory exhaustion.
    """
    def __init__(self, app, max_size_bytes: int = 30 * 1024 * 1024):
        super().__init__(app)
        self.max_size_bytes = max_size_bytes

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("Content-Length")
        if content_length and int(content_length) > self.max_size_bytes:
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=413,
                content={
                    "error": {
                        "code": "PAYLOAD_TOO_LARGE",
                        "message": f"Request body exceeds maximum size of {self.max_size_bytes // (1024 * 1024)}MB.",
                        "correlation_id": correlation_id_ctx.get()
                    }
                }
            )
        return await call_next(request)

