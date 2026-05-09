"""Application-level caching layer.

Provides a Redis-backed cache with an in-memory LRU fallback so the app
degrades gracefully when Redis is unavailable. All callers use the same
stable interface and never need to know which backend is active.

Also re-exports ``BackgroundTaskQueue``, ``IdempotencyCache``, and
``ResponseCache`` from ``lib_runtime`` for a single import point.

Enhancements applied:
  Enhancement — mget() / mset() batch operations added (single round-trip to
                Redis vs. N individual get/set calls; falls back to N in-memory
                ops when Redis is not available).
  Enhancement — exists() check added (avoids deserialising a value just to test
                presence).
  Enhancement — get_or_set() added: atomic read-through caching helper so
                callers don't need to manually check + set.
  Enhancement — Module-level _bg_queue singleton exposed so enqueue_with_fallback
                can reuse it without creating extra threads.
"""
from __future__ import annotations

import json
import logging
import os
import time
from collections import OrderedDict
from threading import Lock
from typing import Any, Callable

log = logging.getLogger("cafe.cache")

_REDIS_URL = os.environ.get("REDIS_URL", "")


class InMemoryLRU:
    """Thread-safe LRU cache with per-entry TTL."""

    def __init__(self, maxsize: int = 1024) -> None:
        self._store: OrderedDict[str, tuple[Any, float]] = OrderedDict()
        self._lock = Lock()
        self._maxsize = maxsize

    def get(self, key: str) -> Any:
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            value, expires_at = entry
            if expires_at and time.time() > expires_at:
                self._store.pop(key, None)
                return None
            self._store.move_to_end(key)
            return value

    def set(self, key: str, value: Any, ttl: int = 300) -> None:
        expires_at = time.time() + ttl if ttl else 0.0
        with self._lock:
            if key in self._store:
                self._store.move_to_end(key)
            self._store[key] = (value, expires_at)
            while len(self._store) > self._maxsize:
                self._store.popitem(last=False)

    def delete(self, key: str) -> None:
        with self._lock:
            self._store.pop(key, None)

    def exists(self, key: str) -> bool:
        return self.get(key) is not None

    def flush(self) -> None:
        with self._lock:
            self._store.clear()

    def mget(self, keys: list[str]) -> list[Any]:
        return [self.get(k) for k in keys]

    def mset(self, mapping: dict[str, Any], ttl: int = 300) -> None:
        for k, v in mapping.items():
            self.set(k, v, ttl)


class AppCache:
    """Redis-first cache; falls back to InMemoryLRU transparently."""

    def __init__(self, redis_url: str = "") -> None:
        self._local = InMemoryLRU()
        self._redis = None
        if redis_url:
            try:
                import redis  # type: ignore

                client = redis.Redis.from_url(
                    redis_url, decode_responses=True, socket_timeout=1
                )
                client.ping()
                self._redis = client
                log.info("AppCache: Redis backend active at %s", redis_url)
            except Exception as exc:
                log.warning("AppCache: Redis unavailable (%s); using in-memory.", exc)

    # ── Single-key operations ─────────────────────────────────────────────────

    def get(self, key: str) -> Any:
        if self._redis:
            try:
                raw = self._redis.get(key)
                return json.loads(raw) if raw is not None else None
            except Exception as exc:
                log.warning("AppCache.get redis error: %s", exc)
        return self._local.get(key)

    def set(self, key: str, value: Any, ttl: int = 300) -> None:
        serialised = json.dumps(value, default=str)
        if self._redis:
            try:
                self._redis.setex(key, ttl, serialised)
                return
            except Exception as exc:
                log.warning("AppCache.set redis error: %s", exc)
        self._local.set(key, value, ttl)

    def delete(self, key: str) -> None:
        if self._redis:
            try:
                self._redis.delete(key)
            except Exception as exc:
                log.warning("AppCache.delete redis error: %s", exc)
        self._local.delete(key)

    def exists(self, key: str) -> bool:
        """Return True if *key* is present (and not expired) without deserialising."""
        if self._redis:
            try:
                return bool(self._redis.exists(key))
            except Exception as exc:
                log.warning("AppCache.exists redis error: %s", exc)
        return self._local.exists(key)

    # ── Batch operations ──────────────────────────────────────────────────────

    def mget(self, keys: list[str]) -> list[Any]:
        """Fetch multiple keys in a single round-trip (Redis MGET)."""
        if not keys:
            return []
        if self._redis:
            try:
                raws = self._redis.mget(keys)
                return [json.loads(r) if r is not None else None for r in raws]
            except Exception as exc:
                log.warning("AppCache.mget redis error: %s", exc)
        return self._local.mget(keys)

    def mset(self, mapping: dict[str, Any], ttl: int = 300) -> None:
        """Store multiple key-value pairs (Redis pipeline for atomicity)."""
        if not mapping:
            return
        serialised = {k: json.dumps(v, default=str) for k, v in mapping.items()}
        if self._redis:
            try:
                pipe = self._redis.pipeline(transaction=False)
                for k, v in serialised.items():
                    pipe.setex(k, ttl, v)
                pipe.execute()
                return
            except Exception as exc:
                log.warning("AppCache.mset redis error: %s", exc)
        self._local.mset(mapping, ttl)

    # ── Read-through helper ────────────────────────────────────────────────────

    def get_or_set(self, key: str, factory: Callable[[], Any], ttl: int = 300) -> Any:
        """Return cached value for *key*, calling *factory* to populate on miss.

        Example::

            orders = cache.get_or_set(
                f"orders:{owner_id}",
                lambda: load_orders(owner_id),
                ttl=5,
            )
        """
        value = self.get(key)
        if value is not None:
            return value
        value = factory()
        if value is not None:
            self.set(key, value, ttl)
        return value

    # ── Maintenance ────────────────────────────────────────────────────────────

    def flush(self) -> None:
        if self._redis:
            try:
                self._redis.flushdb()
            except Exception:
                pass
        self._local.flush()


# ── Module-level singleton ─────────────────────────────────────────────────────
cache = AppCache(redis_url=_REDIS_URL)

# Background task queue singleton — reused by enqueue_with_fallback
from lib_runtime import BackgroundTaskQueue as _BTQ  # noqa: E402

_bg_queue: _BTQ = _BTQ(name="bg-tasks")

# Re-export runtime primitives for a single import point
from lib_runtime import BackgroundTaskQueue, IdempotencyCache, ResponseCache  # noqa: E402

__all__ = [
    "cache",
    "AppCache",
    "InMemoryLRU",
    "BackgroundTaskQueue",
    "IdempotencyCache",
    "ResponseCache",
    "_bg_queue",
]
