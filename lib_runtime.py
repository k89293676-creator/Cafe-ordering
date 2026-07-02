"""In-process production primitives — no Redis / no external services.

Everything in this module is intentionally self-contained so it works on
Railway's single-worker (``WEB_CONCURRENCY=1``) free-tier without extra
infrastructure. If you ever scale to multiple workers, swap these for
their distributed equivalents (Redis-backed RQ, redis-py SETNX, etc.) —
the call sites import a tiny stable surface (``submit``, ``check_and_set``,
``get_or_set``, ``feature_enabled``) so the migration is a drop-in.
"""
from __future__ import annotations

import logging
import os
import queue
import threading
import time
from collections import OrderedDict
from typing import Any, Callable

log = logging.getLogger("cafe.runtime")


# ---------------------------------------------------------------------------
# Background task queue
# ---------------------------------------------------------------------------

class BackgroundTaskQueue:
    """Fire-and-forget task runner backed by a single daemon worker thread.

    Replaces the need for Redis-backed RQ for things like:
      - sending order-confirmation email
      - dispatching web-push notifications
      - generating PDF receipts on demand

    Design notes:
      - Single worker keeps memory + DB connections bounded on free-tier.
      - Queue is unbounded by default; callers should not submit hot loops.
      - Each task gets a few retries with exponential back-off; permanent
        failures are logged with the task name + traceback (visible in
        Railway logs / Sentry).
      - The thread is a daemon so it cannot block process shutdown.
    """

    def __init__(self, name: str = "bg-tasks", max_retries: int = 2) -> None:
        self._q: "queue.Queue[tuple[str, Callable, tuple, dict, int]]" = queue.Queue()
        self._max_retries = max_retries
        self._name = name
        self._stats = {"submitted": 0, "completed": 0, "failed": 0, "retried": 0}
        self._stats_lock = threading.Lock()
        self._worker = threading.Thread(target=self._run, name=name, daemon=True)
        self._worker.start()
        log.info("BackgroundTaskQueue %s started", name)

    def submit(self, fn: Callable, *args: Any, _name: str | None = None, **kwargs: Any) -> None:
        task_name = _name or getattr(fn, "__name__", "task")
        self._q.put((task_name, fn, args, kwargs, 0))
        with self._stats_lock:
            self._stats["submitted"] += 1

    def stats(self) -> dict:
        with self._stats_lock:
            s = dict(self._stats)
        s["pending"] = self._q.qsize()
        return s

    def _run(self) -> None:
        while True:
            try:
                task_name, fn, args, kwargs, attempt = self._q.get()
            except Exception:  # pragma: no cover — queue.Queue.get can't fail
                continue
            try:
                fn(*args, **kwargs)
                with self._stats_lock:
                    self._stats["completed"] += 1
            except Exception as exc:
                if attempt < self._max_retries:
                    delay = 2 ** attempt
                    log.warning(
                        "bg-task %s failed (attempt %d/%d): %s — retrying in %ds",
                        task_name, attempt + 1, self._max_retries + 1, exc, delay,
                    )
                    with self._stats_lock:
                        self._stats["retried"] += 1
                    threading.Timer(
                        delay,
                        lambda: self._q.put((task_name, fn, args, kwargs, attempt + 1)),
                    ).start()
                else:
                    log.exception("bg-task %s permanently failed: %s", task_name, exc)
                    with self._stats_lock:
                        self._stats["failed"] += 1
            finally:
                self._q.task_done()


# ---------------------------------------------------------------------------
# Idempotency cache (TTL dict, thread-safe, bounded)
# ---------------------------------------------------------------------------

class IdempotencyCache:
    """Tiny TTL store for idempotency keys.

    Used at the front of mutating POST endpoints (e.g. /api/checkout) so a
    customer who taps "Place Order" twice — or whose phone retries the
    request after a flaky network — does not create a duplicate order.

    Stores are keyed by (scope, key) and hold the original response payload
    + status code so the second call returns the same result. Bounded so
    memory cannot grow without limit; oldest entries are evicted first.
    """

    def __init__(self, ttl_seconds: int = 86400, max_entries: int = 10_000) -> None:
        self._ttl = ttl_seconds
        self._max = max_entries
        self._lock = threading.Lock()
        self._store: "OrderedDict[str, tuple[float, Any]]" = OrderedDict()

    def _gc(self, now: float) -> None:
        # Evict expired + oldest if over capacity. Caller holds lock.
        while self._store:
            k, (exp, _) = next(iter(self._store.items()))
            if exp <= now:
                self._store.popitem(last=False)
            else:
                break
        while len(self._store) > self._max:
            self._store.popitem(last=False)

    def get(self, scope: str, key: str) -> Any | None:
        if not key:
            return None
        full = f"{scope}::{key}"
        now = time.time()
        with self._lock:
            self._gc(now)
            entry = self._store.get(full)
            if entry and entry[0] > now:
                return entry[1]
            if entry:
                self._store.pop(full, None)
            return None

    def set(self, scope: str, key: str, value: Any) -> None:
        if not key:
            return
        full = f"{scope}::{key}"
        now = time.time()
        with self._lock:
            self._gc(now)
            self._store[full] = (now + self._ttl, value)
            self._store.move_to_end(full)


# ---------------------------------------------------------------------------
# Response cache (TTL dict, thread-safe, bounded) — for read-heavy endpoints
# ---------------------------------------------------------------------------

class ResponseCache:
    """Process-local TTL cache for cheap-to-serve, slow-to-compute reads.

    Use sparingly — only for endpoints that are (a) read-only, (b) safe to
    serve slightly stale data, (c) hot on the request path. Public menu
    listings and table-status reads are the canonical wins.
    """

    def __init__(self, max_entries: int = 1_000) -> None:
        self._max = max_entries
        self._lock = threading.Lock()
        self._store: "OrderedDict[str, tuple[float, Any]]" = OrderedDict()

    def get_or_set(self, key: str, ttl_seconds: int, factory: Callable[[], Any]) -> Any:
        now = time.time()
        with self._lock:
            entry = self._store.get(key)
            if entry and entry[0] > now:
                self._store.move_to_end(key)
                return entry[1]
        # Compute outside the lock so a slow factory does not block readers
        # of unrelated keys.
        value = factory()
        with self._lock:
            self._store[key] = (now + ttl_seconds, value)
            self._store.move_to_end(key)
            while len(self._store) > self._max:
                self._store.popitem(last=False)
        return value

    def invalidate(self, key: str) -> None:
        with self._lock:
            self._store.pop(key, None)

    def invalidate_prefix(self, prefix: str) -> None:
        with self._lock:
            for k in [k for k in self._store if k.startswith(prefix)]:
                self._store.pop(k, None)


# ---------------------------------------------------------------------------
# Feature flags (env-driven)
# ---------------------------------------------------------------------------

_TRUTHY = {"1", "true", "yes", "on"}


def feature_enabled(name: str, default: bool = False) -> bool:
    """Read a boolean feature flag from the environment.

    Convention: ``FEATURE_<NAME>=on`` enables, anything else disables.
    Lets you dark-launch risky changes without a redeploy by toggling the
    Railway variable.
    """
    raw = os.environ.get(f"FEATURE_{name.upper()}", "").strip().lower()
    if not raw:
        return default
    return raw in _TRUTHY
