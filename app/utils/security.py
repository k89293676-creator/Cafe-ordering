"""Security helpers: rate-limit tracking, IP extraction, decorators."""
from __future__ import annotations

import collections
import logging
import mimetypes
import os
import time
from functools import wraps
from pathlib import Path
from typing import Any

from flask import abort, jsonify, redirect, request, session, url_for

security_log = logging.getLogger("cafe.security")
if not security_log.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("[SECURITY] %(asctime)s %(levelname)s %(message)s"))
    security_log.addHandler(_h)
    security_log.setLevel(logging.INFO)
    security_log.propagate = False

SECURITY_EVENT_BUFFER: collections.deque = collections.deque(maxlen=2000)

_ALLOWED_UPLOADS = {
    ".json": {"application/json", "text/json"},
    ".jpg": {"image/jpeg"},
    ".jpeg": {"image/jpeg"},
    ".png": {"image/png"},
}

# ── Failed login rate limiter (in-memory; fine for single worker) ─────────────
import threading as _threading

_failed_login_store: dict = {}
_failed_login_lock = _threading.Lock()
_MAX_ATTEMPTS = 10
_LOCKOUT_WINDOW = 900  # 15 minutes


def _client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()


def log_security(event: str, detail: str = "") -> None:
    ip = _client_ip()
    security_log.info("%s ip=%s %s", event, ip, detail)
    try:
        SECURITY_EVENT_BUFFER.append({
            "ts": time.time(),
            "event": event,
            "ip": ip,
            "detail": detail,
            "actor": session.get("admin_owner_id") or session.get("_user_id") or None,
        })
    except Exception:
        pass


def _failed_login_key(ip: str) -> str:
    return f"fail:{ip}"


def _is_ip_locked_out(ip: str) -> bool:
    now = time.time()
    with _failed_login_lock:
        attempts = [ts for ts in _failed_login_store.get(ip, []) if now - ts < _LOCKOUT_WINDOW]
        _failed_login_store[ip] = attempts
        return len(attempts) >= _MAX_ATTEMPTS


def _record_failed_login(ip: str) -> None:
    with _failed_login_lock:
        _failed_login_store.setdefault(ip, []).append(time.time())


def _clear_failed_logins(ip: str) -> None:
    with _failed_login_lock:
        _failed_login_store.pop(ip, None)


def validate_uploaded_file(uploaded_file: Any, file_bytes: bytes) -> tuple[str | None, str | None]:
    filename = (uploaded_file.filename or "").lower()
    ext = Path(filename).suffix
    if ext not in _ALLOWED_UPLOADS:
        return "Unsupported file type.", None
    guessed_type = (mimetypes.guess_type(filename)[0] or "").lower()
    provided_type = (uploaded_file.mimetype or "").split(";", 1)[0].lower()
    allowed_types = _ALLOWED_UPLOADS[ext]
    if guessed_type not in allowed_types:
        return "File extension does not match MIME type.", None
    if provided_type and provided_type not in allowed_types and provided_type != "application/octet-stream":
        return "File MIME type not allowed.", None
    if not file_bytes:
        return "File is empty.", None
    return None, "image" if ext in {".jpg", ".jpeg", ".png"} else "json"


# ── Auth decorators ───────────────────────────────────────────────────────────

def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        from app.services.auth import logged_in_owner
        if not logged_in_owner():
            return redirect(url_for("web_auth.owner_login"))
        return view_func(*args, **kwargs)
    return wrapper


def api_login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        from app.services.auth import logged_in_owner
        if not logged_in_owner():
            log_security("API_UNAUTHORISED", f"path={request.path}")
            return jsonify(description="Authentication required."), 401
        return view_func(*args, **kwargs)
    return wrapper


def _superadmin_key_configured() -> bool:
    return bool(os.environ.get("SUPERADMIN_KEY", "").strip() or os.environ.get("ADMIN_SECRET_KEY", "").strip())


def _superadmin_key_matches(provided: str) -> bool:
    key = os.environ.get("SUPERADMIN_KEY", "") or os.environ.get("ADMIN_SECRET_KEY", "")
    if not key:
        return False
    import hmac
    return hmac.compare_digest(provided.encode(), key.encode())


def _superadmin_session_verified() -> bool:
    return bool(session.get("superadmin_verified") or session.get("admin_authenticated"))


def _is_real_superadmin(owner: Any) -> bool:
    return bool(owner and getattr(owner, "is_superadmin", False))


def superadmin_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        from app.services.auth import logged_in_owner_obj
        owner = logged_in_owner_obj()
        if _is_real_superadmin(owner) or _superadmin_session_verified():
            return view_func(*args, **kwargs)
        from flask import current_app
        if _superadmin_key_configured():
            return redirect(url_for("web_superadmin.superadmin_verify_key"))
        abort(403)
    return wrapper


def superadmin_destructive(view_func):
    """Require a fresh superadmin step-up for destructive actions."""
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        from app.services.auth import logged_in_owner_obj
        owner = logged_in_owner_obj()
        if not (_is_real_superadmin(owner) or _superadmin_session_verified()):
            abort(403)
        return view_func(*args, **kwargs)
    return wrapper
