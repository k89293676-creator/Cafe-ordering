"""Background task queue powered by RQ (Redis Queue).

Usage — enqueue from application code::

    from app.tasks import get_queue
    q = get_queue()
    if q:
        q.enqueue(send_order_confirmation_email, order_id=42)

When Redis is unavailable ``get_queue()`` returns ``None``; callers
should execute the work synchronously in that case so no functionality
is lost.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rq import Queue

_queue: "Queue | None" = None


def init_queue(redis_url: str | None) -> None:
    """Initialise the RQ default queue.  Called once from ``create_app``."""
    global _queue
    if not redis_url:
        return
    try:
        import redis
        from rq import Queue

        conn = redis.from_url(redis_url, socket_connect_timeout=2, socket_timeout=2)
        conn.ping()
        _queue = Queue(connection=conn)
    except Exception:
        _queue = None


def get_queue() -> "Queue | None":
    """Return the RQ queue, or *None* when Redis is not available."""
    return _queue
