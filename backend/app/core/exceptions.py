import time
from typing import Optional, Any, Dict
from fastapi import Request
from fastapi.responses import JSONResponse

class FraudShieldBaseException(Exception):
    """Base class for domain-specific FraudShield exceptions."""
    def __init__(self, message: str, code: str = "INTERNAL_ERROR", status_code: int = 500, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details or {}

class ResourceNotFoundException(FraudShieldBaseException):
    def __init__(self, resource: str, identifier: str):
        super().__init__(
            message=f"{resource} with identifier '{identifier}' was not found.",
            code="RESOURCE_NOT_FOUND",
            status_code=404,
            details={"resource": resource, "identifier": identifier}
        )

class AuthorizationException(FraudShieldBaseException):
    def __init__(self, message: str = "Access denied. Insufficient privileges."):
        super().__init__(
            message=message,
            code="AUTHORIZATION_FAILED",
            status_code=403
        )

class AuthenticationException(FraudShieldBaseException):
    def __init__(self, message: str = "Invalid credentials or token expired."):
        super().__init__(
            message=message,
            code="AUTHENTICATION_FAILED",
            status_code=401
        )

class ServiceUnavailableException(FraudShieldBaseException):
    def __init__(self, service_name: str, message: Optional[str] = None):
        super().__init__(
            message=message or f"The requested service '{service_name}' is temporarily unavailable. Please retry shortly.",
            code="SERVICE_UNAVAILABLE",
            status_code=503,
            details={"service": service_name}
        )

class RateLimitExceededException(FraudShieldBaseException):
    def __init__(self, limit: int, window_seconds: int):
        super().__init__(
            message=f"Rate limit of {limit} requests per {window_seconds}s exceeded.",
            code="RATE_LIMIT_EXCEEDED",
            status_code=429,
            details={"limit": limit, "window_seconds": window_seconds}
        )

class SSRFBlockedException(FraudShieldBaseException):
    def __init__(self, target: str, reason: str):
        super().__init__(
            message=f"Request to target '{target}' blocked by SSRF egress security policy: {reason}",
            code="SSRF_PROTECTION_BLOCKED",
            status_code=400,
            details={"target": target, "reason": reason}
        )

class FileProcessingException(FraudShieldBaseException):
    def __init__(self, message: str, code: str = "FILE_PROCESSING_ERROR", status_code: int = 400):
        super().__init__(
            message=message,
            code=code,
            status_code=status_code
        )

def build_error_response(
    status_code: int,
    code: str,
    message: str,
    correlation_id: str,
    details: Optional[Dict[str, Any]] = None
) -> JSONResponse:
    """Creates a standardized, clean API error JSON response without leaking stack traces."""
    content = {
        "detail": message,
        "error": {
            "code": code,
            "message": message,
            "correlation_id": correlation_id,
            "timestamp": time.time(),
            "details": details or {}
        }
    }
    return JSONResponse(status_code=status_code, content=content)
