import time
import pytest
from app.core.circuit_breaker import CircuitBreaker, CircuitState

def test_circuit_breaker_initial_closed_state():
    cb = CircuitBreaker("test-service", failure_threshold=3, recovery_timeout=0.2)
    assert cb.state == CircuitState.CLOSED
    assert cb.can_execute() is True
    assert cb.get_status()["healthy"] is True

def test_circuit_breaker_trips_to_open_after_threshold():
    cb = CircuitBreaker("test-service", failure_threshold=3, recovery_timeout=0.2)
    
    cb.record_failure(Exception("Fail 1"))
    assert cb.state == CircuitState.CLOSED
    assert cb.can_execute() is True

    cb.record_failure(Exception("Fail 2"))
    assert cb.state == CircuitState.CLOSED
    assert cb.can_execute() is True

    cb.record_failure(Exception("Fail 3"))
    assert cb.state == CircuitState.OPEN
    assert cb.can_execute() is False
    assert cb.get_status()["healthy"] is False

def test_circuit_breaker_recovers_via_half_open_canary():
    cb = CircuitBreaker("test-service", failure_threshold=2, recovery_timeout=0.1, success_threshold=1)
    
    cb.record_failure(Exception("Fail 1"))
    cb.record_failure(Exception("Fail 2"))
    assert cb.state == CircuitState.OPEN
    assert cb.can_execute() is False

    # Wait for recovery timeout
    time.sleep(0.15)

    # First request after timeout should transition to HALF_OPEN
    assert cb.can_execute() is True
    assert cb.state == CircuitState.HALF_OPEN

    # Canary success transitions to CLOSED
    cb.record_success()
    assert cb.state == CircuitState.CLOSED
    assert cb.can_execute() is True
    assert cb.get_status()["healthy"] is True

def test_circuit_breaker_half_open_failure_re_opens():
    cb = CircuitBreaker("test-service", failure_threshold=2, recovery_timeout=0.1, success_threshold=2)
    
    cb.record_failure(Exception("Fail 1"))
    cb.record_failure(Exception("Fail 2"))
    assert cb.state == CircuitState.OPEN

    time.sleep(0.15)
    assert cb.can_execute() is True
    assert cb.state == CircuitState.HALF_OPEN

    # Canary failure trips back to OPEN
    cb.record_failure(Exception("Canary fail"))
    assert cb.state == CircuitState.OPEN
    assert cb.can_execute() is False

