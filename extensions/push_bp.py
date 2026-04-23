"""Web Push API notifications for owners and customers.

VAPID keys must be set in the environment:
    VAPID_PRIVATE_PEM  — full PEM string (BEGIN PRIVATE KEY … END PRIVATE KEY)
                         with literal \\n between lines, as stored by python-dotenv
    VAPID_PUBLIC_KEY   — base64url-encoded uncompressed EC public key (for JS)
    VAPID_EMAIL        — contact email, e.g. mailto:admin@cafe.app

Generate a fresh keypair by running:
    python extensions/generate_vapid.py

Push is silently disabled (no error, just a log.warning) when the env vars are
absent, so the app works normally without push configured.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from typing import Optional

from flask import Blueprint, abort, jsonify, request

from app import db, login_required, logged_in_owner_id, limiter

log = logging.getLogger(__name__)

bp = Blueprint("push", __name__)

# ---------------------------------------------------------------------------
# Lazy VAPID initialisation
# ---------------------------------------------------------------------------

_vapid_lock = threading.Lock()
_vapid_obj = None           # py_vapid.Vapid instance, cached after first load
_vapid_loaded = False       # True once we have tried to load (even if failed)
_PUSH_AVAILABLE = False     # True if pywebpush can be imported


try:
    from pywebpush import webpush as _webpush_send_fn, WebPushException
    from py_vapid import Vapid as _Vapid
    _PUSH_AVAILABLE = True
except ImportError:
    _webpush_send_fn = None  # type: ignore[assignment]
    WebPushException = Exception
    _Vapid = None  # type: ignore[assignment]
    log.warning("push: pywebpush not installed — Web Push notifications disabled.")


def _get_vapid() -> Optional[object]:
    """Return a cached Vapid instance, or None if keys are not configured."""
    global _vapid_obj, _vapid_loaded
    if _vapid_loaded:
        return _vapid_obj
    with _vapid_lock:
        if _vapid_loaded:
            return _vapid_obj
        _vapid_loaded = True
        if not _PUSH_AVAILABLE or _Vapid is None:
            return None
        pem = os.environ.get("VAPID_PRIVATE_PEM", "").strip()
        if not pem:
            log.warning("push: VAPID_PRIVATE_PEM not set — Web Push disabled.")
            return None
        # python-dotenv stores literal \n; replace them with real newlines.
        pem = pem.replace("\\n", "\n")
        try:
            _vapid_obj = _Vapid.from_pem(pem.encode())
            log.info("push: VAPID keys loaded OK.")
        except Exception as exc:
            log.error("push: failed to load VAPID key: %s", exc)
        return _vapid_obj


def _vapid_claims() -> dict:
    email = os.environ.get("VAPID_EMAIL", "mailto:admin@cafe.app")
    return {"sub": email}


# ---------------------------------------------------------------------------
# PushSubscription model  (defined here; db.create_all() picks it up via
# register_extensions which imports this module)
# ---------------------------------------------------------------------------

class PushSubscription(db.Model):
    __tablename__ = "push_subscriptions"

    id = db.Column(db.Integer, primary_key=True)
    # Exactly one of owner_id / table_id is set.
    owner_id = db.Column(
        db.Integer,
        db.ForeignKey("owners.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    table_id = db.Column(db.Text, nullable=True, index=True)

    endpoint = db.Column(db.Text, nullable=False, unique=True)
    p256dh   = db.Column(db.Text, nullable=False)
    auth     = db.Column(db.Text, nullable=False)

    created_at = db.Column(
        db.DateTime(timezone=True), server_default=db.func.now()
    )


# ---------------------------------------------------------------------------
# Internal push helper
# ---------------------------------------------------------------------------

def _do_send(sub: PushSubscription, payload: dict) -> bool:
    """Send one Web Push message synchronously. Returns True on success.

    Automatically deletes stale subscriptions (HTTP 410 Gone).
    Runs in a daemon thread so callers are never blocked.
    """
    v = _get_vapid()
    if v is None:
        return False
    try:
        _webpush_send_fn(
            subscription_info={
                "endpoint": sub.endpoint,
                "keys": {"p256dh": sub.p256dh, "auth": sub.auth},
            },
            data=json.dumps(payload, ensure_ascii=False),
            vapid_private_key=v,
            vapid_claims=_vapid_claims(),
        )
        return True
    except WebPushException as exc:
        resp = getattr(exc, "response", None)
        status = resp.status_code if resp is not None else None
        if status in (404, 410):
            # Subscription expired — remove it so we don't keep trying.
            try:
                db.session.delete(sub)
                db.session.commit()
            except Exception:
                db.session.rollback()
        else:
            log.warning("push send failed (status=%s): %s", status, exc)
        return False
    except Exception as exc:
        log.warning("push send error: %s", exc)
        return False


def _push_all(subs: list[PushSubscription], payload: dict) -> None:
    """Fan-out push to a list of subscriptions in a background thread."""
    if not subs:
        return
    # Take copies of the data we need — avoid DB session issues across threads.
    entries = [(s.endpoint, s.p256dh, s.auth, s.id) for s in subs]

    def _worker():
        v = _get_vapid()
        if v is None:
            return
        for endpoint, p256dh, auth, sub_id in entries:
            try:
                _webpush_send_fn(
                    subscription_info={
                        "endpoint": endpoint,
                        "keys": {"p256dh": p256dh, "auth": auth},
                    },
                    data=json.dumps(payload, ensure_ascii=False),
                    vapid_private_key=v,
                    vapid_claims=_vapid_claims(),
                )
            except WebPushException as exc:
                resp = getattr(exc, "response", None)
                status = resp.status_code if resp is not None else None
                if status in (404, 410):
                    try:
                        from app import app as flask_app  # local import to avoid circular
                        with flask_app.app_context():
                            row = db.session.get(PushSubscription, sub_id)
                            if row:
                                db.session.delete(row)
                                db.session.commit()
                    except Exception:
                        pass
            except Exception as exc:
                log.warning("push worker error: %s", exc)

    t = threading.Thread(target=_worker, daemon=True, name="push-worker")
    t.start()


# ---------------------------------------------------------------------------
# Public helpers called by other blueprints
# ---------------------------------------------------------------------------

def push_owner(owner_id: int, title: str, body: str, data: Optional[dict] = None) -> None:
    """Fire a push notification to every browser subscribed as this owner."""
    if not _PUSH_AVAILABLE:
        return
    try:
        subs = PushSubscription.query.filter_by(owner_id=owner_id).all()
    except Exception:
        return
    if not subs:
        return
    payload = {"title": title, "body": body, "type": "owner"}
    if data:
        payload["data"] = data
    _push_all(subs, payload)


def push_table(table_id: str, title: str, body: str, data: Optional[dict] = None) -> None:
    """Fire a push notification to every browser subscribed for this table."""
    if not _PUSH_AVAILABLE:
        return
    try:
        subs = PushSubscription.query.filter_by(table_id=str(table_id)).all()
    except Exception:
        return
    if not subs:
        return
    payload = {"title": title, "body": body, "type": "table"}
    if data:
        payload["data"] = data
    _push_all(subs, payload)


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

@bp.route("/api/push/vapid-public-key", methods=["GET"])
def vapid_public_key():
    """Return the VAPID public key for the browser to subscribe with."""
    key = os.environ.get("VAPID_PUBLIC_KEY", "")
    if not key:
        return jsonify({"ok": False, "error": "Push not configured."}), 503
    return jsonify({"ok": True, "key": key})


@bp.route("/api/push/subscribe-owner", methods=["POST"])
@login_required
@limiter.limit("20 per hour")
def subscribe_owner():
    """Store a PushSubscription for the currently logged-in owner."""
    owner_id = logged_in_owner_id()
    if not owner_id:
        abort(401)
    return _upsert_subscription(owner_id=owner_id, table_id=None)


@bp.route("/api/push/subscribe-table/<table_id>", methods=["POST"])
@limiter.limit("30 per hour")
def subscribe_table(table_id: str):
    """Store a PushSubscription for a customer at a table (no auth needed)."""
    if len(table_id) > 64:
        abort(400)
    return _upsert_subscription(owner_id=None, table_id=table_id)


@bp.route("/api/push/unsubscribe", methods=["POST"])
def unsubscribe():
    """Remove a PushSubscription by endpoint (called when browser unsubscribes)."""
    payload = request.get_json(silent=True) or {}
    endpoint = str(payload.get("endpoint", "")).strip()
    if not endpoint:
        return jsonify({"ok": False}), 400
    deleted = PushSubscription.query.filter_by(endpoint=endpoint).delete()
    db.session.commit()
    return jsonify({"ok": True, "deleted": bool(deleted)})


def _upsert_subscription(owner_id, table_id) -> tuple:
    payload = request.get_json(silent=True) or {}
    endpoint = str(payload.get("endpoint", "")).strip()
    keys = payload.get("keys") or {}
    p256dh = str(keys.get("p256dh", "")).strip()
    auth   = str(keys.get("auth", "")).strip()

    if not endpoint or not p256dh or not auth:
        return jsonify({"ok": False, "error": "Missing subscription fields."}), 400

    # Upsert: update if endpoint already exists, else insert.
    existing = PushSubscription.query.filter_by(endpoint=endpoint).first()
    if existing:
        existing.owner_id = owner_id
        existing.table_id = table_id
        existing.p256dh   = p256dh
        existing.auth     = auth
    else:
        sub = PushSubscription(
            owner_id=owner_id,
            table_id=table_id,
            endpoint=endpoint,
            p256dh=p256dh,
            auth=auth,
        )
        db.session.add(sub)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({"ok": False, "error": "DB error."}), 500

    return jsonify({"ok": True})
