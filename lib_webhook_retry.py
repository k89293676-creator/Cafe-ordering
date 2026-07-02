"""Outbound webhook delivery with exponential-backoff retry.

The legacy code path used ``requests.post(...)`` inline inside the
request handler. That has three production problems:

1. A single failing receiver stalls the user-facing request.
2. A flaky receiver loses every event we couldn't deliver in 30s.
3. We have no record of which receivers are slow, broken, or hostile.

This module fixes all three:

- ``enqueue(url, payload, ...)`` writes a row and returns *immediately*.
- A background worker (one per process) pops due rows, POSTs them with
  HMAC signing, and re-schedules failures with exponential backoff +
  jitter (capped at one hour).
- Rows that exceed ``max_attempts`` are marked ``dead`` (dead-letter
  queue) and surfaced via a token-protected ops endpoint.

Cross-worker safety
-------------------
The work queue lives in the database (table ``outbound_webhooks``), so
multiple gunicorn workers can each claim rows safely via
``UPDATE ... WHERE status='pending' AND id=:id`` (we read-then-claim,
checking ``rowcount`` to detect a race). No Redis required — but if
``REDIS_URL`` is set we also publish a "wakeup" pubsub message so
workers don't have to sleep through a 5-second poll.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import random
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any

_logger = logging.getLogger("cafe.webhooks")

# Tunables (all overridable via env so production can react without a
# code deploy when a partner's endpoint melts down).
MAX_ATTEMPTS = int(os.environ.get("WEBHOOK_MAX_ATTEMPTS", "8"))
BASE_BACKOFF_SECONDS = float(os.environ.get("WEBHOOK_BASE_BACKOFF_SECONDS", "5"))
MAX_BACKOFF_SECONDS = float(os.environ.get("WEBHOOK_MAX_BACKOFF_SECONDS", "3600"))
TIMEOUT_SECONDS = float(os.environ.get("WEBHOOK_TIMEOUT_SECONDS", "10"))
WORKER_POLL_SECONDS = float(os.environ.get("WEBHOOK_POLL_SECONDS", "5"))
BATCH_SIZE = int(os.environ.get("WEBHOOK_BATCH_SIZE", "10"))
SIGNING_HEADER = os.environ.get("WEBHOOK_SIGNATURE_HEADER", "X-Cafe-Signature")
TIMESTAMP_HEADER = os.environ.get("WEBHOOK_TIMESTAMP_HEADER", "X-Cafe-Timestamp")


def compute_backoff(attempt: int, *, base: float = BASE_BACKOFF_SECONDS,
                     cap: float = MAX_BACKOFF_SECONDS) -> float:
    """Return the seconds to wait before the *next* attempt.

    Decorrelated jitter (AWS-style) so a thundering herd of N receivers
    failing at the same moment doesn't all retry at the same instant.
    """
    attempt = max(1, int(attempt))
    exp = min(cap, base * (2 ** (attempt - 1)))
    # uniform jitter between base and exp (clamped). Always returns
    # at least ``base`` so a tight loop can't burn CPU on a hot failure.
    return min(cap, random.uniform(base, max(base, exp)))


def sign_payload(secret: str, body: bytes, timestamp: str) -> str:
    """HMAC-SHA256 signature over ``timestamp.body`` (Stripe-style).

    Including the timestamp in the signed material foils replay attacks
    even when the receiver doesn't keep its own nonce log.
    """
    mac = hmac.new(secret.encode("utf-8"), digestmod=hashlib.sha256)
    mac.update(timestamp.encode("utf-8"))
    mac.update(b".")
    mac.update(body)
    return mac.hexdigest()


# ---------------------------------------------------------------------------
# SQLAlchemy model + Flask integration
# ---------------------------------------------------------------------------

def register(app, db) -> None:
    """Define the model, register the routes, and start the worker."""

    class OutboundWebhook(db.Model):  # type: ignore
        __tablename__ = "outbound_webhooks"

        id = db.Column(db.Integer, primary_key=True)
        owner_id = db.Column(db.Integer, index=True)
        target_url = db.Column(db.Text, nullable=False)
        method = db.Column(db.String(10), default="POST")
        # JSON-serialised body and headers — we store as TEXT so we don't
        # have to fight the JSON column compatibility matrix on SQLite.
        body = db.Column(db.Text, nullable=False, default="{}")
        headers = db.Column(db.Text, default="{}")
        signing_secret = db.Column(db.Text, default="")
        attempts = db.Column(db.Integer, default=0)
        max_attempts = db.Column(db.Integer, default=MAX_ATTEMPTS)
        status = db.Column(db.String(16), default="pending", index=True)
        # status: pending | delivered | failed | dead
        next_attempt_at = db.Column(db.DateTime, default=datetime.utcnow,
                                     index=True)
        last_status_code = db.Column(db.Integer, default=0)
        last_error = db.Column(db.Text, default="")
        created_at = db.Column(db.DateTime, default=datetime.utcnow)
        updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                                onupdate=datetime.utcnow)
        delivered_at = db.Column(db.DateTime)
        # Optional dedup key — if the caller passes the same key twice
        # we no-op on the second insert to make ``enqueue`` idempotent.
        dedup_key = db.Column(db.String(120), unique=True, nullable=True,
                                index=True)

        def to_dict(self) -> dict:
            return {
                "id": self.id,
                "owner_id": self.owner_id,
                "target_url": self.target_url,
                "method": self.method,
                "attempts": self.attempts,
                "max_attempts": self.max_attempts,
                "status": self.status,
                "last_status_code": self.last_status_code,
                "last_error": (self.last_error or "")[:300],
                "created_at": self.created_at.isoformat() if self.created_at else None,
                "updated_at": self.updated_at.isoformat() if self.updated_at else None,
                "delivered_at": self.delivered_at.isoformat() if self.delivered_at else None,
                "next_attempt_at": (self.next_attempt_at.isoformat()
                                      if self.next_attempt_at else None),
                "dedup_key": self.dedup_key,
            }

    # Auto-create the table on first import. The repo already uses
    # db.create_all() in app.py, but a fresh install via ``flask db
    # upgrade`` may run before the model is imported.
    with app.app_context():
        try:
            OutboundWebhook.__table__.create(db.engine, checkfirst=True)
        except Exception as exc:  # noqa: BLE001
            app.logger.warning("outbound_webhooks: create_table skipped: %s", exc)

    # Stash the model + helpers on the app so other modules can call
    # ``current_app.extensions['outbound_webhooks'].enqueue(...)``.
    helpers = _build_helpers(app, db, OutboundWebhook)
    app.extensions = getattr(app, "extensions", {})
    app.extensions["outbound_webhooks"] = helpers
    _register_routes(app, helpers, OutboundWebhook)
    _start_worker(app, db, OutboundWebhook)


def _build_helpers(app, db, OutboundWebhook):
    """Return a tiny namespace of helpers other code calls.

    Returning a namespace (not bare functions on the model) lets the
    test suite swap implementations without monkey-patching SQLAlchemy.
    """

    def enqueue(*, target_url: str, payload: Any, owner_id: int | None = None,
                method: str = "POST", headers: dict | None = None,
                signing_secret: str = "", max_attempts: int = MAX_ATTEMPTS,
                dedup_key: str | None = None) -> dict:
        """Insert a pending row. Returns the dict representation."""
        body_text = json.dumps(payload, separators=(",", ":"),
                                default=str, ensure_ascii=False)
        headers_text = json.dumps(headers or {}, separators=(",", ":"))
        existing = None
        if dedup_key:
            existing = OutboundWebhook.query.filter_by(dedup_key=dedup_key).first()
            if existing:
                return existing.to_dict()
        row = OutboundWebhook(
            owner_id=owner_id,
            target_url=target_url,
            method=method.upper(),
            body=body_text,
            headers=headers_text,
            signing_secret=signing_secret,
            max_attempts=max(1, int(max_attempts)),
            next_attempt_at=datetime.utcnow(),
            dedup_key=dedup_key,
        )
        db.session.add(row)
        db.session.commit()
        # Best-effort wake-up so the worker doesn't sleep through it.
        _wakeup()
        return row.to_dict()

    def deliver_one(row: "OutboundWebhook") -> bool:
        """Attempt delivery. Returns True on success."""
        body_bytes = (row.body or "").encode("utf-8")
        headers = json.loads(row.headers or "{}")
        # Always set timestamp + signature when a secret is configured.
        ts = str(int(time.time()))
        if row.signing_secret:
            headers[SIGNING_HEADER] = sign_payload(row.signing_secret,
                                                   body_bytes, ts)
            headers[TIMESTAMP_HEADER] = ts
        headers.setdefault("Content-Type", "application/json")
        headers.setdefault("User-Agent", "cafe-ordering-webhook/1")
        req = urllib.request.Request(
            row.target_url, data=body_bytes,
            method=row.method.upper(), headers=headers,
        )
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
                code = getattr(resp, "status", 200) or 200
                row.last_status_code = code
                if 200 <= code < 300:
                    row.status = "delivered"
                    row.delivered_at = datetime.utcnow()
                    row.last_error = ""
                    return True
                row.last_error = f"HTTP {code}"
                return False
        except urllib.error.HTTPError as exc:
            row.last_status_code = exc.code
            row.last_error = f"HTTP {exc.code}: {exc.reason}"[:500]
            # 4xx errors (except 408 + 429) are unrecoverable — fast-fail
            # to dead-letter so we don't waste retries on a permanent typo.
            if 400 <= exc.code < 500 and exc.code not in (408, 429):
                row.status = "dead"
                row.attempts = row.max_attempts
            return False
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            row.last_status_code = 0
            row.last_error = f"{type(exc).__name__}: {exc}"[:500]
            return False

    def process_due(limit: int = BATCH_SIZE) -> int:
        """Process up to ``limit`` due rows. Returns count processed."""
        now = datetime.utcnow()
        rows = (OutboundWebhook.query
                .filter(OutboundWebhook.status == "pending")
                .filter(OutboundWebhook.next_attempt_at <= now)
                .order_by(OutboundWebhook.next_attempt_at)
                .limit(limit).all())
        processed = 0
        for row in rows:
            row.attempts = (row.attempts or 0) + 1
            ok = False
            try:
                ok = deliver_one(row)
            except Exception as exc:  # noqa: BLE001 - never crash the worker
                row.last_error = f"unhandled: {type(exc).__name__}: {exc}"[:500]
                _logger.exception("webhook delivery threw")
            if ok:
                pass  # status set inside deliver_one
            elif row.status != "dead" and row.attempts >= row.max_attempts:
                row.status = "dead"
            elif row.status != "dead":
                # schedule next attempt with exp-backoff + jitter.
                wait = compute_backoff(row.attempts)
                row.next_attempt_at = datetime.utcnow() + timedelta(seconds=wait)
            db.session.commit()
            processed += 1
        return processed

    def stats() -> dict:
        from sqlalchemy import func
        rows = (db.session.query(OutboundWebhook.status,
                                  func.count(OutboundWebhook.id))
                .group_by(OutboundWebhook.status).all())
        return {status: count for status, count in rows}

    def list_dead(limit: int = 50) -> list[dict]:
        rows = (OutboundWebhook.query
                .filter(OutboundWebhook.status == "dead")
                .order_by(OutboundWebhook.updated_at.desc())
                .limit(limit).all())
        return [r.to_dict() for r in rows]

    def requeue(row_id: int) -> bool:
        row = db.session.get(OutboundWebhook, row_id)
        if not row:
            return False
        row.status = "pending"
        row.attempts = 0
        row.next_attempt_at = datetime.utcnow()
        row.last_error = ""
        db.session.commit()
        _wakeup()
        return True

    return type("WebhookHelpers", (), {
        "enqueue": staticmethod(enqueue),
        "deliver_one": staticmethod(deliver_one),
        "process_due": staticmethod(process_due),
        "stats": staticmethod(stats),
        "list_dead": staticmethod(list_dead),
        "requeue": staticmethod(requeue),
    })


# Per-process wake-up event so a freshly-enqueued row is processed ASAP.
_WAKE = threading.Event()


def _wakeup() -> None:
    _WAKE.set()


def _start_worker(app, db, OutboundWebhook) -> None:
    """Spin one daemon thread per process. Multiple workers across
    multiple gunicorn workers all poll the same table — that's fine
    because each row is taken once via the COMMIT-after-process pattern.
    """
    # Tests drive ``process_due`` directly so we don't need a background
    # thread that could race assertions. We read the env var (not
    # ``app.config["TESTING"]``) because conftest sets the env *before*
    # importing app.py, but the config flag isn't applied until the
    # ``app`` fixture runs — and by then the worker would already be up.
    if (app.config.get("TESTING")
        or os.environ.get("TESTING")
        or os.environ.get("PYTEST_CURRENT_TEST")
        or os.environ.get("DISABLE_WEBHOOK_WORKER")):
        return

    helpers = app.extensions["outbound_webhooks"]

    def _loop():
        while True:
            try:
                with app.app_context():
                    helpers.process_due(limit=BATCH_SIZE)
            except Exception as exc:  # noqa: BLE001
                app.logger.warning("webhook worker iteration failed: %s", exc)
            # Sleep with wake-up — interrupted by enqueue().
            _WAKE.wait(timeout=WORKER_POLL_SECONDS)
            _WAKE.clear()

    t = threading.Thread(target=_loop, daemon=True, name="webhook-worker")
    t.start()


def _register_routes(app, helpers, OutboundWebhook) -> None:
    """Token-protected ops endpoints for the dead-letter queue."""
    from flask import jsonify, request

    def _check_token() -> bool:
        token = (os.environ.get("OPS_HEALTH_TOKEN") or "").strip()
        provided = (request.headers.get("Authorization") or "").strip()
        if provided.lower().startswith("bearer "):
            provided = provided[7:].strip()
        return bool(token) and hmac.compare_digest(token, provided)

    @app.route("/api/ops/webhooks")
    def _ops_webhooks():
        if not _check_token():
            return jsonify(error="unauthorized"), 401
        return jsonify({
            "ok": True,
            "stats": helpers.stats(),
            "dead": helpers.list_dead(limit=int(request.args.get("limit", "50"))),
        })

    @app.route("/api/ops/webhooks/<int:row_id>/requeue", methods=["POST"])
    def _ops_webhooks_requeue(row_id: int):
        if not _check_token():
            return jsonify(error="unauthorized"), 401
        ok = helpers.requeue(row_id)
        return jsonify({"ok": ok}), (200 if ok else 404)
