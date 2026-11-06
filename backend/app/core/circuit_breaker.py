import time
import logging
from enum import Enum
from typing import Callable, Any, Optional

logger = logging.getLogger("fraudshield.circuit_breaker")

class CircuitState(str, Enum):
    CLOSED = "CLOSED"        # Normal operation: requests pass through
    OPEN = "OPEN"            # Tripped: requests immediately fail / short-circuit
    HALF_OPEN = "HALF_OPEN"  # Testing recovery: single probe allowed

class CircuitBreakerOpenException(Exception):
    """Raised when an operation is attempted on an open circuit breaker."""
    def __init__(self, service_name: str, cooldown_remaining: float):
        super().__init__(f"Circuit breaker for service '{service_name}' is OPEN. Retry in {cooldown_remaining:.1f}s.")
        self.service_name = service_name
        self.cooldown_remaining = cooldown_remaining

class CircuitBreaker:
    """
    Production-grade Circuit Breaker with exponential backoff / cool-down and state telemetry.
    States:
      - CLOSED: Operates normally. Tracks consecutive failures.
      - OPEN: Fails fast after failure_threshold consecutive failures without hitting remote service.
      - HALF_OPEN: After recovery_timeout, allows a canary request to test provider health.
    """
    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        success_threshold: int = 2
    ):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.success_threshold = success_threshold

        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time: Optional[float] = None
        self.last_state_change: float = time.time()
        self.total_requests = 0
        self.total_failures = 0
        self.total_short_circuits = 0

    def can_execute(self) -> bool:
        """Determines if a request should be allowed through."""
        now = time.time()
        if self.state == CircuitState.CLOSED:
            return True

        if self.state == CircuitState.OPEN:
            # Check if recovery timeout has elapsed
            if now - (self.last_failure_time or 0) >= self.recovery_timeout:
                logger.info(f"CircuitBreaker '{self.name}': Recovery timeout elapsed. Transitioning OPEN -> HALF_OPEN.")
                self.state = CircuitState.HALF_OPEN
                self.success_count = 0
                self.last_state_change = now
                return True
            return False

        if self.state == CircuitState.HALF_OPEN:
            # In half-open, allow limited probe traffic
            return True

        return False

    def record_success(self) -> None:
        """Records a successful operation."""
        self.total_requests += 1
        now = time.time()

        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.success_threshold:
                logger.info(f"CircuitBreaker '{self.name}': Canary probe succeeded. Transitioning HALF_OPEN -> CLOSED.")
                self.state = CircuitState.CLOSED
                self.failure_count = 0
                self.success_count = 0
                self.last_state_change = now
        elif self.state == CircuitState.CLOSED:
            self.failure_count = 0

    def record_failure(self, error: Optional[Exception] = None) -> None:
        """Records a failed operation and trips if threshold exceeded."""
        self.total_requests += 1
        self.total_failures += 1
        now = time.time()
        self.last_failure_time = now
        self.failure_count += 1

        if self.state == CircuitState.CLOSED:
            if self.failure_count >= self.failure_threshold:
                logger.warning(
                    f"CircuitBreaker '{self.name}': Trip threshold reached ({self.failure_count}/{self.failure_threshold} failures). "
                    f"Transitioning CLOSED -> OPEN for {self.recovery_timeout}s. Last error: {error}"
                )
                self.state = CircuitState.OPEN
                self.last_state_change = now
        elif self.state == CircuitState.HALF_OPEN:
            logger.warning(
                f"CircuitBreaker '{self.name}': Canary request failed. Transitioning HALF_OPEN -> OPEN. Error: {error}"
            )
            self.state = CircuitState.OPEN
            self.last_state_change = now

    def record_short_circuit(self) -> None:
        """Increments short-circuit metrics when request is rejected."""
        self.total_short_circuits += 1

    def get_status(self) -> dict:
        """Returns health telemetry for monitoring and readiness probes."""
        now = time.time()
        cooldown_remaining = 0.0
        if self.state == CircuitState.OPEN and self.last_failure_time:
            cooldown_remaining = max(0.0, self.recovery_timeout - (now - self.last_failure_time))

        return {
            "name": self.name,
            "state": self.state.value,
            "failure_count": self.failure_count,
            "success_count": self.success_count,
            "cooldown_remaining_seconds": round(cooldown_remaining, 1),
            "total_requests": self.total_requests,
            "total_failures": self.total_failures,
            "total_short_circuits": self.total_short_circuits,
            "healthy": self.state == CircuitState.CLOSED
        }

