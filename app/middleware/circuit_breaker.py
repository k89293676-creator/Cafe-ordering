"""Circuit breaker for external service calls — Issue #12.

Prevents cascading failures when Stripe / Razorpay / mail servers are
unavailable by fast-failing after a configurable number of consecutive
errors and re-trying after a cool-down window.

State machine:
    CLOSED    → normal operation; failures increment a counter.
    OPEN      → fast-fail; no calls reach the external service.
    HALF_OPEN → one probe call is allowed; success → CLOSED, failure → OPEN.

Enhancements applied:
  Enhancement — reset() method added for manual recovery (admin/ops endpoint).
  Enhancement — half_open_probe_count exposed in stats for dashboard monitoring.
  Enhancement — is_available property for quick boolean health checks.
  Enhancement — success_threshold configurable (n consecutive successes needed
                to transition HALF_OPEN → CLOSED, prevents flappy recovery).

Usage::

    from app.middleware.circuit_breaker import get_breaker, CircuitOpenError

    _stripe_cb = get_breaker("stripe", failure_threshold=5, recovery_timeout=30)

    try:
        with _stripe_cb:
            result = stripe.PaymentIntent.create(...)
    except CircuitOpenError:
        return jsonify(error="Payment temporarily unavailable"), 503
"""
from __future__ import annotations

import logging
import threading
import time
from enum import Enum, auto
from typing import Any, Callable

log = logging.getLogger("cafe.circuit_breaker")


class CircuitState(Enum):
    CLOSED = auto()
    OPEN = auto()
    HALF_OPEN = auto()


class CircuitOpenError(Exception):
    """Raised when a call is rejected because the circuit is OPEN."""

    def __init__(self, name: str, retry_after: float) -> None:
        self.name = name
        self.retry_after = retry_after
        super().__init__(
            f"Circuit '{name}' is OPEN — service unavailable. "
            f"Retry after {retry_after:.1f}s."
        )


class CircuitBreaker:
    """Thread-safe circuit breaker for a single named external dependency."""

    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        success_threshold: int = 2,
    ) -> None:
        self.name = name
        self._failure_threshold = failure_threshold
        self._recovery_timeout = recovery_timeout
        self._success_threshold = success_threshold

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._half_open_probe_count = 0  # consecutive successes in HALF_OPEN
        self._opened_at: float = 0.0
        self._last_failure_at: float = 0.0
        self._lock = threading.Lock()

        self._lifetime_stats = {
            "calls": 0,
            "failures": 0,
            "rejected": 0,
            "state_changes": 0,
        }

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def state(self) -> CircuitState:
        return self._state

    @property
    def is_available(self) -> bool:
        """True when the circuit will allow the next call (CLOSED or HALF_OPEN probe)."""
        with self._lock:
            self._maybe_transition_to_half_open()
            return self._state != CircuitState.OPEN

    @property
    def stats(self) -> dict:
        with self._lock:
            return {
                "name": self.name,
                "state": self._state.name,
                "failure_count": self._failure_count,
                "half_open_probe_count": self._half_open_probe_count,
                "failure_threshold": self._failure_threshold,
                "recovery_timeout_s": self._recovery_timeout,
                "opened_at": self._opened_at or None,
                "last_failure_at": self._last_failure_at or None,
                **self._lifetime_stats,
            }

    # ── State helpers (caller must hold _lock) ────────────────────────────────

    def _transition(self, new_state: CircuitState) -> None:
        if new_state == self._state:
            return
        log.warning(
            "Circuit '%s': %s → %s (failures=%d)",
            self.name,
            self._state.name,
            new_state.name,
            self._failure_count,
        )
        self._state = new_state
        self._lifetime_stats["state_changes"] += 1
        if new_state == CircuitState.OPEN:
            self._opened_at = time.monotonic()
        if new_state == CircuitState.HALF_OPEN:
            self._half_open_probe_count = 0

    def _maybe_transition_to_half_open(self) -> None:
        if self._state == CircuitState.OPEN:
            if time.monotonic() - self._opened_at >= self._recovery_timeout:
                self._transition(CircuitState.HALF_OPEN)

    def _on_success(self) -> None:
        if self._state == CircuitState.HALF_OPEN:
            self._half_open_probe_count += 1
            if self._half_open_probe_count >= self._success_threshold:
                self._failure_count = 0
                self._transition(CircuitState.CLOSED)
        elif self._state == CircuitState.CLOSED:
            # Decay: successful call reduces failure counter toward zero
            self._failure_count = max(0, self._failure_count - 1)

    def _on_failure(self) -> None:
        self._failure_count += 1
        self._last_failure_at = time.monotonic()
        self._lifetime_stats["failures"] += 1
        if self._state == CircuitState.HALF_OPEN:
            self._transition(CircuitState.OPEN)
        elif self._state == CircuitState.CLOSED:
            if self._failure_count >= self._failure_threshold:
                self._transition(CircuitState.OPEN)

    # ── Context manager API ────────────────────────────────────────────────────

    def __enter__(self) -> "CircuitBreaker":
        with self._lock:
            self._maybe_transition_to_half_open()
            if self._state == CircuitState.OPEN:
                remaining = self._recovery_timeout - (
                    time.monotonic() - self._opened_at
                )
                self._lifetime_stats["rejected"] += 1
                raise CircuitOpenError(self.name, max(0.0, remaining))
            self._lifetime_stats["calls"] += 1
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        with self._lock:
            if exc_type is None:
                self._on_success()
            elif not issubclass(exc_type, CircuitOpenError):
                self._on_failure()
        return False

    # ── Convenience helpers ────────────────────────────────────────────────────

    def call(self, fn: Callable, *args: Any, **kwargs: Any) -> Any:
        """``cb.call(stripe.PaymentIntent.create, amount=100, currency="usd")``."""
        with self:
            return fn(*args, **kwargs)

    def reset(self) -> None:
        """Manually reset the circuit to CLOSED (for admin/ops recovery).

        Use with caution: a manual reset bypasses the recovery timeout so it
        should only be triggered by an operator after the upstream issue is
        confirmed resolved.
        """
        with self._lock:
            log.warning(
                "Circuit '%s': manual reset from %s → CLOSED", self.name, self._state.name
            )
            self._failure_count = 0
            self._half_open_probe_count = 0
            self._state = CircuitState.CLOSED
            self._lifetime_stats["state_changes"] += 1


# ── Module-level registry ─────────────────────────────────────────────────────

_registry: dict[str, CircuitBreaker] = {}
_registry_lock = threading.Lock()


def get_breaker(
    name: str,
    failure_threshold: int = 5,
    recovery_timeout: float = 30.0,
    success_threshold: int = 2,
) -> CircuitBreaker:
    """Get or create a named circuit breaker (module-level singleton registry).

    Subsequent calls with the same *name* return the existing breaker — the
    threshold/timeout args are only applied on first creation.
    """
    with _registry_lock:
        if name not in _registry:
            _registry[name] = CircuitBreaker(
                name,
                failure_threshold=failure_threshold,
                recovery_timeout=recovery_timeout,
                success_threshold=success_threshold,
            )
        return _registry[name]


def all_breaker_stats() -> list[dict]:
    """Return stats for every registered circuit breaker (for health checks)."""
    with _registry_lock:
        return [cb.stats for cb in _registry.values()]


def reset_breaker(name: str) -> bool:
    """Reset a named breaker by name. Returns False if breaker does not exist."""
    with _registry_lock:
        cb = _registry.get(name)
    if cb is None:
        return False
    cb.reset()
    return True
