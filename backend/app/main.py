import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.encoders import jsonable_encoder
from sqlalchemy.exc import SQLAlchemyError

from app.core.config import settings
from app.core.database import check_database_health, Base, engine
from app.core.logging_config import (
    setup_logging,
    CorrelationIdMiddleware,
    RequestSizeLimitMiddleware,
    correlation_id_ctx
)
from app.core.exceptions import FraudShieldBaseException, build_error_response
from app.engines.threat_intelligence import threat_intelligence_aggregator
from app.ml.model import ml_threat_classifier

# Routers
from app.api.auth import router as auth_router
from app.api.scan import router as scan_router
from app.api.events import router as events_router
from app.api.threats import router as threats_router
from app.api.investigation import router as investigation_router
from app.api.campaigns import router as campaigns_router
from app.api.alerts import router as alerts_router
from app.api.blocklist import router as blocklist_router
from app.api.file_analysis import router as file_analysis_router
from app.api.devices import router as devices_router
from app.api.downloads import router as downloads_router
from app.api.metrics import router as metrics_router
from app.api.ws import router as ws_router

logger = logging.getLogger("fraudshield.main")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize logging and database schema
    setup_logging()
    logger.info("Initializing FraudShield AI platform...")
    Base.metadata.create_all(bind=engine)
    logger.info("Database schema verified.")
    yield
    logger.info("Shutting down FraudShield AI gracefully.")

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="FraudShield AI - Multi-Signal Cyber Threat Detection, Prevention, Explainable AI, Multi-Device Threat Correlation and Digital Forensics Platform",
    lifespan=lifespan
)

# 1. Request Correlation ID & Tracing Middleware
app.add_middleware(CorrelationIdMiddleware)

# 2. Request Payload Size Guard (30 MB maximum request boundary)
app.add_middleware(RequestSizeLimitMiddleware, max_size_bytes=30 * 1024 * 1024)

# 3. Pure ASGI Security Headers Middleware (zero deadlock risk, high performance)
class SecurityHeadersMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_security_headers(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.append((b"x-content-type-options", b"nosniff"))
                headers.append((b"x-frame-options", b"DENY"))
                headers.append((b"x-xss-protection", b"1; mode=block"))
                headers.append((b"referrer-policy", b"strict-origin-when-cross-origin"))
                headers.append((b"strict-transport-security", b"max-age=31536000; includeSubDomains"))
                headers.append((b"content-security-policy", b"default-src 'self'; frame-ancestors 'none';"))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_security_headers)

app.add_middleware(SecurityHeadersMiddleware)

# 4. Explicit CORS configuration (No wildcard origins combined with credentials)
ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:5173",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=r"^chrome-extension://[a-z]{32}$|^chrome-extension://.*$",
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["*"],
)

# --- Centralized Fault-Tolerant Exception Handlers ---

@app.exception_handler(FraudShieldBaseException)
async def fraudshield_exception_handler(request: Request, exc: FraudShieldBaseException):
    cid = correlation_id_ctx.get()
    logger.warning(f"Domain exception [{exc.code}] on {request.method} {request.url.path}: {exc.message}")
    return build_error_response(
        status_code=exc.status_code,
        code=exc.code,
        message=exc.message,
        correlation_id=cid,
        details=exc.details
    )

@app.exception_handler(404)
async def not_found_handler(request: Request, exc: Exception):
    cid = correlation_id_ctx.get()
    return build_error_response(
        status_code=404,
        code="NOT_FOUND",
        message="The requested API resource was not found.",
        correlation_id=cid
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    cid = correlation_id_ctx.get()
    # Preserve standard detail string
    detail_msg = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
    return build_error_response(
        status_code=exc.status_code,
        code="HTTP_ERROR",
        message=detail_msg,
        correlation_id=cid
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    cid = correlation_id_ctx.get()
    encoded_errors = jsonable_encoder(exc.errors())
    logger.info(f"Validation failure on {request.method} {request.url.path}: {encoded_errors}")
    content = {
        "detail": encoded_errors,
        "error": {
            "code": "VALIDATION_ERROR",
            "message": "Request validation failed. Review the errors in details.",
            "correlation_id": cid,
            "details": {"validation_errors": encoded_errors}
        }
    }
    return JSONResponse(status_code=422, content=content)

@app.exception_handler(SQLAlchemyError)
async def database_exception_handler(request: Request, exc: SQLAlchemyError):
    cid = correlation_id_ctx.get()
    logger.error(f"Database error on {request.method} {request.url.path}: {exc}", exc_info=True)
    return build_error_response(
        status_code=503,
        code="DATABASE_UNAVAILABLE",
        message="Database service is temporarily unavailable or encountered a transaction error.",
        correlation_id=cid
    )

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    cid = correlation_id_ctx.get()
    logger.error(f"Unhandled system error on {request.method} {request.url.path}: {exc}", exc_info=True)
    return build_error_response(
        status_code=500,
        code="INTERNAL_SERVER_ERROR",
        message="An unexpected system error occurred. Please provide the correlation ID to technical support.",
        correlation_id=cid
    )

# --- Include Modular API Routers ---
app.include_router(auth_router, prefix="/api", tags=["Authentication"])
app.include_router(scan_router, prefix="/api", tags=["Threat Scanning"])
app.include_router(events_router, prefix="/api", tags=["Detection Events"])
app.include_router(threats_router, prefix="/api", tags=["Threats"])
app.include_router(investigation_router, prefix="/api", tags=["Investigation"])
app.include_router(campaigns_router, prefix="/api", tags=["Campaigns"])
app.include_router(alerts_router, prefix="/api", tags=["Alerts"])
app.include_router(blocklist_router, prefix="/api", tags=["Blocklist"])
app.include_router(file_analysis_router, prefix="/api", tags=["File Forensics"])
app.include_router(devices_router, prefix="/api", tags=["Devices"])
app.include_router(downloads_router, prefix="/api", tags=["Dangerous Downloads"])
app.include_router(metrics_router, prefix="/api", tags=["Metrics"])
app.include_router(ws_router, prefix="/api", tags=["Real-Time WebSockets"])

# --- Health, Liveness, and Readiness Endpoints ---

@app.get("/health", tags=["Health"])
def health_check():
    """General health check (backward compatible)."""
    return {
        "status": "healthy",
        "service": "FraudShield AI",
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT
    }

@app.get("/health/live", tags=["Health"])
def liveness_probe():
    """
    Kubernetes / Docker container liveness probe.
    Confirms the application process is running and responsive.
    """
    return {
        "status": "alive",
        "service": "FraudShield AI",
        "version": settings.VERSION
    }

@app.get("/health/ready", tags=["Health"])
def readiness_probe():
    """
    Kubernetes / Docker container readiness probe.
    Validates operational readiness of critical subsystems:
      - Database connectivity & response latency
      - External Threat Intelligence Circuit Breaker states
      - Machine Learning Model availability
    """
    db_health = check_database_health()
    providers_health = threat_intelligence_aggregator.get_provider_statuses()
    ml_status = "operational" if ml_threat_classifier.model is not None else "degraded_heuristic_fallback"

    is_ready = db_health.get("status") == "healthy"
    status_str = "ready" if is_ready else "not_ready"

    content = {
        "status": status_str,
        "service": "FraudShield AI",
        "subsystems": {
            "database": db_health,
            "threat_intelligence_circuit_breakers": providers_health,
            "machine_learning_engine": {
                "status": ml_status,
                "model_loaded": ml_threat_classifier.model is not None
            }
        }
    }
    return JSONResponse(status_code=200 if is_ready else 503, content=content)
