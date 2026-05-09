"""Background task queue powered by RQ (Redis Queue).

Usage — enqueue from application code::

    from app.tasks import enqueue_with_fallback
    enqueue_with_fallback(send_order_confirmation_email, order_id=42)

``enqueue_with_fallback`` tries RQ first (Redis-backed, survives worker
restarts) and falls back to the in-process BackgroundTaskQueue when
Redis is unavailable, so no functionality is lost on free-tier Railway.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from rq import Queue

log = logging.getLogger("cafe.tasks")

_queue: "Queue | None" = None


def init_queue(redis_url: str | None) -> None:
    """Initialise the RQ default queue. Called once from ``create_app``."""
    global _queue
    if not redis_url:
        return
    try:
        import redis
        from rq import Queue

        conn = redis.from_url(redis_url, socket_connect_timeout=2, socket_timeout=2)
        conn.ping()
        _queue = Queue(connection=conn)
        log.info("RQ queue initialised (Redis-backed)")
    except Exception as exc:
        log.warning("RQ init failed (%s); background tasks use in-process queue.", exc)
        _queue = None


def get_queue() -> "Queue | None":
    """Return the RQ queue, or *None* when Redis is not available."""
    return _queue


def enqueue_with_fallback(
    fn: Callable,
    *args: Any,
    _job_timeout: int = 300,
    **kwargs: Any,
) -> None:
    """Enqueue *fn* via RQ when available, otherwise run in-process.

    This is the preferred way to dispatch background work from routes and
    services. It guarantees the task runs even when Redis is down.

    Example::

        from app.tasks import enqueue_with_fallback
        from app.tasks.jobs import send_order_confirmation_email

        enqueue_with_fallback(send_order_confirmation_email, order_id=order["id"])
    """
    q = _queue
    if q is not None:
        try:
            q.enqueue(fn, *args, job_timeout=_job_timeout, **kwargs)
            return
        except Exception as exc:
            log.warning(
                "RQ enqueue failed for %s (%s); running in-process.",
                getattr(fn, "__name__", fn),
                exc,
            )

    # Fallback: in-process background queue (lib_runtime.BackgroundTaskQueue)
    try:
        from app.cache import BackgroundTaskQueue
        _bg: BackgroundTaskQueue = BackgroundTaskQueue.__new__(BackgroundTaskQueue)
        # Re-use the module-level singleton if it exists, otherwise create one
        from app import cache as _cache_mod
        bg_queue = getattr(_cache_mod, "_bg_queue", None)
        if bg_queue is None:
            bg_queue = BackgroundTaskQueue(name="bg-tasks-fallback")
            _cache_mod._bg_queue = bg_queue  # type: ignore[attr-defined]
        bg_queue.submit(fn, *args, **kwargs)
    except Exception as exc:
        log.error(
            "enqueue_with_fallback: both RQ and in-process fallback failed for %s: %s",
            getattr(fn, "__name__", fn),
            exc,
        )
