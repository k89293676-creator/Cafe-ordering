"""SSE and push-notification services.

Supports both in-memory (single worker) and Redis pub/sub (multi-worker)
fan-out transparently.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from typing import Any

log = logging.getLogger("cafe.notifications")

# ── SSE subscriber registries ─────────────────────────────────────────────────
_sse_subscribers: dict[int, list] = {}        # owner_id → list[(queue, event)]
_sse_customer_subs: dict[int, list] = {}      # order_id → list[(queue, event)]
_sse_table_subs: dict[str, list] = {}         # table_id → list[(queue, event)]
_sse_lock = threading.Lock()

# ── Redis pub/sub (optional) ──────────────────────────────────────────────────
_REDIS_URL = os.environ.get("REDIS_URL", "")
_REDIS_OWNER_CHANNEL = "sse:owner"
_REDIS_CUSTOMER_CHANNEL = "sse:customer"
_REDIS_TABLE_CHANNEL = "sse:table"
_redis_client = None


def init_redis_pubsub() -> None:
    """Call from create_app() after the app starts.  Safe to call multiple times."""
    global _redis_client
    if not _REDIS_URL or _redis_client is not None:
        return
    try:
        import redis  # type: ignore
        client = redis.Redis.from_url(_REDIS_URL, decode_responses=True)
        client.ping()
        _redis_client = client
        log.info("SSE: Redis pub/sub enabled at %s", _REDIS_URL)

        def _subscriber_loop() -> None:
            backoff = 1
            while True:
                try:
                    pubsub = _redis_client.pubsub(ignore_subscribe_messages=True)
                    pubsub.subscribe(_REDIS_OWNER_CHANNEL, _REDIS_CUSTOMER_CHANNEL, _REDIS_TABLE_CHANNEL)
                    backoff = 1
                    for message in pubsub.listen():
                        try:
                            channel = message.get("channel")
                            raw = message.get("data")
                            if not raw:
                                continue
                            envelope = json.loads(raw)
                            if channel == _REDIS_OWNER_CHANNEL:
                                _local_dispatch_owner(int(envelope["owner_id"]), envelope["payload"])
                            elif channel == _REDIS_CUSTOMER_CHANNEL:
                                _local_dispatch_customer(int(envelope["order_id"]), envelope["payload"])
                            elif channel == _REDIS_TABLE_CHANNEL:
                                _local_dispatch_table(str(envelope["table_id"]), envelope["payload"])
                        except Exception as inner:
                            log.warning("SSE redis dispatch error: %s", inner)
                except Exception as exc:
                    log.warning("SSE redis subscriber error: %s; retrying in %ss", exc, backoff)
                    import time
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 30)

        threading.Thread(target=_subscriber_loop, name="sse-redis-sub", daemon=True).start()
    except Exception as exc:
        log.warning("SSE: Redis unavailable (%s); falling back to in-memory.", exc)
        _redis_client = None


def _local_dispatch_owner(owner_id: int, payload: str) -> None:
    with _sse_lock:
        entries = _sse_subscribers.get(owner_id, [])
        dead = []
        for entry in entries:
            try:
                q, ev = entry
                q.append(payload)
                ev.set()
            except Exception:
                dead.append(entry)
        for entry in dead:
            entries.remove(entry)


def _local_dispatch_customer(order_id: int, payload: str) -> None:
    with _sse_lock:
        entries = _sse_customer_subs.get(order_id, [])
        dead = []
        for entry in entries:
            try:
                q, ev = entry
                q.append(payload)
                ev.set()
            except Exception:
                dead.append(entry)
        for entry in dead:
            entries.remove(entry)


def _local_dispatch_table(table_id: str, payload: str) -> None:
    with _sse_lock:
        entries = _sse_table_subs.get(table_id, [])
        dead = []
        for entry in entries:
            try:
                q, ev = entry
                q.append(payload)
                ev.set()
            except Exception:
                dead.append(entry)
        for entry in dead:
            entries.remove(entry)


def _notify_owner(owner_id: int, event_type: str, data: dict) -> None:
    payload = json.dumps({"type": event_type, "data": data})
    if _redis_client is not None:
        try:
            _redis_client.publish(_REDIS_OWNER_CHANNEL, json.dumps({"owner_id": owner_id, "payload": payload}))
            return
        except Exception as exc:
            log.warning("SSE redis publish failed (owner): %s; using local.", exc)
    _local_dispatch_owner(owner_id, payload)


def _notify_order_status(order_id: int, status: str) -> None:
    payload = json.dumps({"status": status, "id": order_id})
    if _redis_client is not None:
        try:
            _redis_client.publish(_REDIS_CUSTOMER_CHANNEL, json.dumps({"order_id": order_id, "payload": payload}))
            return
        except Exception as exc:
            log.warning("SSE redis publish failed (customer): %s; using local.", exc)
    _local_dispatch_customer(order_id, payload)


def _notify_table_call(table_id: str, event_type: str, data: dict) -> None:
    if not table_id:
        return
    payload = json.dumps({"type": event_type, "data": data})
    if _redis_client is not None:
        try:
            _redis_client.publish(_REDIS_TABLE_CHANNEL, json.dumps({"table_id": str(table_id), "payload": payload}))
            return
        except Exception as exc:
            log.warning("SSE redis publish failed (table): %s; using local.", exc)
    _local_dispatch_table(str(table_id), payload)


def _push_new_order(owner_id: int, customer_name: str, total: float) -> None:
    try:
        from extensions.push_bp import push_owner
        push_owner(
            owner_id,
            title="New order",
            body=f"{customer_name} — {total:.2f}" if total else f"Order from {customer_name}",
            data={"type": "new_order"},
        )
    except Exception:
        pass
