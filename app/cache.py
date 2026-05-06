"""Application-level caching layer.

Provides a Redis-backed cache with an in-memory LRU fallback so the app
degrades gracefully when Redis is unavailable.  All callers use the same
stable interface (``get``, ``set``, ``delete``) and never need to know
which backend is active.

Also re-exports the ``BackgroundTaskQueue`` and ``IdempotencyCache`` from
``lib_runtime`` so callers import from a single place.
"""
from __future__ import annotations

import json
import logging
import os
import time
from collections import OrderedDict
from threading import Lock
from typing import Any

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

    def flush(self) -> None:
        with self._lock:
            self._store.clear()


class AppCache:
    """Redis-first cache; falls back to InMemoryLRU transparently."""

    def __init__(self, redis_url: str = "") -> None:
        self._local = InMemoryLRU()
        self._redis = None
        if redis_url:
            try:
                import redis  # type: ignore

                client = redis.Redis.from_url(redis_url, decode_responses=True, socket_timeout=1)
                client.ping()
                self._redis = client
                log.info("AppCache: Redis backend active at %s", redis_url)
            except Exception as exc:
                log.warning("AppCache: Redis unavailable (%s); using in-memory.", exc)

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

    def flush(self) -> None:
        if self._redis:
            try:
                self._redis.flushdb()
            except Exception:
                pass
        self._local.flush()


# Module-level singleton — import and use directly.
cache = AppCache(redis_url=_REDIS_URL)

# Re-export runtime primitives for convenience.
from lib_runtime import BackgroundTaskQueue, IdempotencyCache, ResponseCache  # noqa: E402

__all__ = [
    "cache",
    "AppCache",
    "InMemoryLRU",
    "BackgroundTaskQueue",
    "IdempotencyCache",
    "ResponseCache",
]
