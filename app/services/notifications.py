"""SSE and push-notification services.

Supports both in-memory (single worker) and Redis pub/sub (multi-worker)
fan-out transparently.

Fixes applied:
  Bug #1 — _push_new_order signature unified: now accepts (owner_id, order_id,
             table_name) to match all call-sites in tasks/jobs.py and orders API.
             The old positional (owner_id, customer_name, total) overload is
             preserved via keyword arguments for backward compatibility.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from typing import Any

log = logging.getLogger("cafe.notifications")

# ── SSE subscriber registries ─────────────────────────────────────────────────
_sse_subscribers: dict[int, list] = {}       # owner_id → list[(queue, event)]
_sse_customer_subs: dict[int, list] = {}     # order_id → list[(queue, event)]
_sse_table_subs: dict[str, list] = {}        # table_id → list[(queue, event)]
_sse_lock = threading.Lock()

# ── Redis pub/sub (optional) ──────────────────────────────────────────────────
_REDIS_URL = os.environ.get("REDIS_URL", "")
_REDIS_OWNER_CHANNEL = "sse:owner"
_REDIS_CUSTOMER_CHANNEL = "sse:customer"
_REDIS_TABLE_CHANNEL = "sse:table"
_redis_client = None


def init_redis_pubsub() -> None:
    """Call from create_app() after the app starts. Safe to call multiple times."""
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
                    pubsub.subscribe(
                        _REDIS_OWNER_CHANNEL,
                        _REDIS_CUSTOMER_CHANNEL,
                        _REDIS_TABLE_CHANNEL,
                    )
                    backoff = 1  # reset on successful connect
                    for message in pubsub.listen():
                        try:
                            channel = message.get("channel")
                            raw = message.get("data")
                            if not raw:
                                continue
                            envelope = json.loads(raw)
                            if channel == _REDIS_OWNER_CHANNEL:
                                _local_dispatch_owner(
                                    int(envelope["owner_id"]), envelope["payload"]
                                )
                            elif channel == _REDIS_CUSTOMER_CHANNEL:
                                _local_dispatch_customer(
                                    int(envelope["order_id"]), envelope["payload"]
                                )
                            elif channel == _REDIS_TABLE_CHANNEL:
                                _local_dispatch_table(
                                    str(envelope["table_id"]), envelope["payload"]
                                )
                        except Exception as inner:
                            log.warning("SSE redis dispatch error: %s", inner)
                except Exception as exc:
                    log.warning(
                        "SSE redis subscriber error: %s; reconnecting in %ds", exc, backoff
                    )
                    import time
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 60)

        threading.Thread(
            target=_subscriber_loop, name="sse-redis-sub", daemon=True
        ).start()
    except Exception as exc:
        log.warning("SSE: Redis unavailable (%s); falling back to in-memory.", exc)
        _redis_client = None


# ── Local dispatch helpers ────────────────────────────────────────────────────

def _local_dispatch_owner(owner_id: int, payload: str) -> None:
    with _sse_lock:
        entries = list(_sse_subscribers.get(owner_id, []))
        dead = []
        for entry in entries:
            try:
                q, ev = entry
                q.append(payload)
                ev.set()
            except Exception:
                dead.append(entry)
        for entry in dead:
            _sse_subscribers.get(owner_id, []).remove(entry)


def _local_dispatch_customer(order_id: int, payload: str) -> None:
    with _sse_lock:
        entries = list(_sse_customer_subs.get(order_id, []))
        dead = []
        for entry in entries:
            try:
                q, ev = entry
                q.append(payload)
                ev.set()
            except Exception:
                dead.append(entry)
        for entry in dead:
            _sse_customer_subs.get(order_id, []).remove(entry)


def _local_dispatch_table(table_id: str, payload: str) -> None:
    with _sse_lock:
        entries = list(_sse_table_subs.get(table_id, []))
        dead = []
        for entry in entries:
            try:
                q, ev = entry
                q.append(payload)
                ev.set()
            except Exception:
                dead.append(entry)
        for entry in dead:
            _sse_table_subs.get(table_id, []).remove(entry)


# ── Public notification helpers ───────────────────────────────────────────────

def _notify_owner(owner_id: int, event_type: str, data: dict) -> None:
    payload = json.dumps({"type": event_type, "data": data})
    if _redis_client is not None:
        try:
            _redis_client.publish(
                _REDIS_OWNER_CHANNEL,
                json.dumps({"owner_id": owner_id, "payload": payload}),
            )
            return
        except Exception as exc:
            log.warning("SSE redis publish failed (owner): %s; using local.", exc)
    _local_dispatch_owner(owner_id, payload)


def _notify_order_status(order_id: int, status: str) -> None:
    payload = json.dumps({"status": status, "id": order_id})
    if _redis_client is not None:
        try:
            _redis_client.publish(
                _REDIS_CUSTOMER_CHANNEL,
                json.dumps({"order_id": order_id, "payload": payload}),
            )
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
            _redis_client.publish(
                _REDIS_TABLE_CHANNEL,
                json.dumps({"table_id": str(table_id), "payload": payload}),
            )
            return
        except Exception as exc:
            log.warning("SSE redis publish failed (table): %s; using local.", exc)
    _local_dispatch_table(str(table_id), payload)


def _push_new_order(
    owner_id: int,
    # New canonical signature (matches tasks/jobs.py and orders API):
    order_id: int | None = None,
    table_name: str = "",
    # Legacy positional params kept for any call-sites still using the old form:
    customer_name: str = "",
    total: float = 0.0,
) -> None:
    """Deliver a Web Push notification to all subscribed owner devices.

    Canonical call (from tasks/jobs.py and orders API)::

        _push_new_order(owner_id=42, order_id=123, table_name="Table 4")

    Legacy call (backward compat)::

        _push_new_order(owner_id=42, customer_name="Alice", total=19.50)
    """
    try:
        from extensions.push_bp import push_owner  # type: ignore
        # Build a human-readable body from whichever params we received
        if order_id and not customer_name:
            body = f"New order #{order_id}"
            if table_name:
                body += f" — {table_name}"
        elif customer_name:
            body = f"{customer_name}"
            if total:
                body += f" — {total:.2f}"
        else:
            body = "New order received"

        push_owner(
            owner_id,
            title="New Order",
            body=body,
            data={
                "type": "new_order",
                "order_id": order_id,
                "table_name": table_name,
            },
        )
    except ImportError:
        pass
    except Exception as exc:
        log.warning("_push_new_order failed for owner %s: %s", owner_id, exc)
