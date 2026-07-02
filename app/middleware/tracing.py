"""Lightweight distributed tracing — Issue #10.

Propagates a trace-ID through every request so log lines from the same
request (including background tasks and downstream calls) are correlated.

Usage:
    from app.middleware.tracing import init_tracing, get_trace_id, traced_call

    # In create_app():
    init_tracing(app)

    # In any route / service:
    tid = get_trace_id()            # current request's trace-ID
    with traced_call("stripe.create_intent"):
        ...
"""
from __future__ import annotations

import functools
import logging
import secrets
import time
from contextlib import contextmanager
from typing import Any, Callable, Generator

from flask import Flask, g, request

log = logging.getLogger("cafe.tracing")

_TRACE_HEADER = "X-Trace-ID"
_SPAN_HEADER = "X-Span-ID"


def _new_id(length: int = 16) -> str:
    return secrets.token_hex(length)


def get_trace_id() -> str:
    """Return the trace-ID for the current request, or a fallback."""
    try:
        return g.get("trace_id") or "no-trace"
    except RuntimeError:
        return "no-trace"


def get_span_id() -> str:
    try:
        return g.get("span_id") or "no-span"
    except RuntimeError:
        return "no-span"


@contextmanager
def traced_call(
    name: str,
    attrs: dict[str, Any] | None = None,
) -> Generator[dict, None, None]:
    """Context manager that records a named span with duration + outcome.

    Example::

        with traced_call("stripe.create_intent", {"order_id": 42}) as span:
            result = stripe_provider.create_payment_intent(...)
        # After the block: span["duration_ms"] and span["ok"] are set.
    """
    span: dict[str, Any] = {
        "name": name,
        "trace_id": get_trace_id(),
        "span_id": _new_id(8),
        "started_at": time.perf_counter(),
        "ok": True,
        "error": None,
        **(attrs or {}),
    }
    try:
        yield span
    except Exception as exc:
        span["ok"] = False
        span["error"] = str(exc)
        raise
    finally:
        span["duration_ms"] = round((time.perf_counter() - span["started_at"]) * 1000, 2)
        status = "ok" if span["ok"] else "error"
        log.info(
            "span %s %s duration_ms=%.2f trace_id=%s",
            name,
            status,
            span["duration_ms"],
            span["trace_id"],
            extra={"span": span},
        )


def trace(fn: Callable) -> Callable:
    """Decorator that wraps a function in a traced_call span."""
    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        with traced_call(fn.__qualname__):
            return fn(*args, **kwargs)
    return wrapper


def init_tracing(app: Flask) -> None:
    """Install before/after-request hooks on *app* for trace propagation."""

    @app.before_request
    def _inject_trace() -> None:
        incoming_trace = (request.headers.get(_TRACE_HEADER) or "").strip()
        if incoming_trace and len(incoming_trace) <= 64 and incoming_trace.isalnum():
            g.trace_id = incoming_trace
        else:
            g.trace_id = _new_id(16)
        g.span_id = _new_id(8)
        g.t_start = time.perf_counter()

    @app.after_request
    def _propagate_trace(response):
        try:
            tid = g.get("trace_id")
            sid = g.get("span_id")
            if tid:
                response.headers[_TRACE_HEADER] = tid
            if sid:
                response.headers[_SPAN_HEADER] = sid
            t0 = g.get("t_start")
            if t0 is not None:
                dur_ms = round((time.perf_counter() - t0) * 1000, 2)
                response.headers.setdefault("X-Response-Time-Ms", str(dur_ms))
        except Exception:
            pass
        return response

    log.info("Distributed tracing middleware initialised (trace header: %s)", _TRACE_HEADER)
