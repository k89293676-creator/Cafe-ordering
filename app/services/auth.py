"""Authentication services: login helpers, token management, password utilities."""
from __future__ import annotations

import hashlib
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from flask import session
from flask_login import login_user, logout_user

from app.extensions import db, bcrypt


# ── Session helpers ───────────────────────────────────────────────────────────

def logged_in_owner() -> str | None:
    return session.get("owner_username")


def logged_in_owner_id() -> int | None:
    val = session.get("owner_id")
    return int(val) if val else None


def logged_in_owner_obj() -> Any:
    from app.models import Owner
    owner_id = logged_in_owner_id()
    if not owner_id:
        return None
    return db.session.get(Owner, owner_id)


def load_owner_user(owner_id: str) -> Any:
    from app.models import Owner
    return db.session.get(Owner, int(owner_id))


# ── Password ──────────────────────────────────────────────────────────────────

def _is_strong_password(password: str) -> bool:
    return (
        len(password) >= 8
        and any(c.isalpha() for c in password)
        and any(c.isdigit() for c in password)
    )


def _make_password_hash(password: str) -> str:
    return bcrypt.generate_password_hash(password).decode("utf-8")


def _password_matches(password_hash: str, password: str) -> bool:
    try:
        return bcrypt.check_password_hash(password_hash, password)
    except Exception:
        from werkzeug.security import check_password_hash
        try:
            return check_password_hash(password_hash, password)
        except Exception:
            return False


def verify_password_constant_time(a: str, b: str) -> bool:
    import hmac
    return hmac.compare_digest(a.encode(), b.encode())


# ── Login flow ────────────────────────────────────────────────────────────────

_REMEMBER_COOKIE = "cafe_remember"
_REMEMBER_DAYS = 90


def _ua_fingerprint() -> str:
    from flask import request
    ua = (request.headers.get("User-Agent") or "")[:512]
    return hashlib.sha256(ua.encode("utf-8", "ignore")).hexdigest()[:16]


def _complete_login(owner: Any, remember_me: bool = False) -> None:
    session.clear()
    session["owner_username"] = owner.username
    session["owner_id"] = owner.id
    session["ua_fp"] = _ua_fingerprint()
    session.permanent = True
    login_user(owner, remember=False)


def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def create_remember_token(owner_id: int) -> str:
    from app.models import RememberToken
    raw = secrets.token_urlsafe(48)
    token_hash = _hash_token(raw)
    expires = datetime.now(timezone.utc) + timedelta(days=_REMEMBER_DAYS)
    stale = (
        RememberToken.query.filter_by(owner_id=owner_id)
        .order_by(RememberToken.created_at.desc())
        .offset(4)
        .all()
    )
    for token in stale:
        db.session.delete(token)
    db.session.add(RememberToken(owner_id=owner_id, token_hash=token_hash, expires_at=expires))
    db.session.commit()
    return raw


def validate_remember_token(raw: str) -> dict | None:
    from app.models import RememberToken
    if not raw:
        return None
    token = RememberToken.query.filter_by(token_hash=_hash_token(raw)).first()
    if not token:
        return None
    now = datetime.now(timezone.utc)
    expires_at = token.expires_at
    if expires_at and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at and expires_at < now:
        db.session.delete(token)
        db.session.commit()
        return None
    owner = db.session.get(__import__("app.models", fromlist=["Owner"]).Owner, token.owner_id)
    if not owner or not owner.is_active:
        return None
    return {"id": owner.id, "username": owner.username}


def revoke_remember_token(raw: str) -> None:
    from app.models import RememberToken
    if not raw:
        return
    token = RememberToken.query.filter_by(token_hash=_hash_token(raw)).first()
    if token:
        db.session.delete(token)
        db.session.commit()


def revoke_all_tokens_for_owner(owner_id: int) -> None:
    from app.models import RememberToken
    RememberToken.query.filter_by(owner_id=owner_id).delete()
    db.session.commit()


# ── Admin key management (DB-backed, no JSON locks) ───────────────────────────

_ADMIN_KEYS_PATH = Path(os.environ.get("DATA_DIR", ".")) / "admin_keys.json"
_admin_keys_lock = __import__("threading").Lock()


def _load_admin_keys_from_db() -> list[dict]:
    """Load admin keys from a JSON sidecar file.
    TODO: Migrate to a proper AdminKey DB table in a future migration."""
    import json
    import portalocker  # type: ignore
    if not _ADMIN_KEYS_PATH.exists():
        return []
    try:
        with portalocker.Lock(str(_ADMIN_KEYS_PATH) + ".lock", timeout=5):
            return json.loads(_ADMIN_KEYS_PATH.read_text()) if _ADMIN_KEYS_PATH.exists() else []
    except Exception:
        return []


def _save_admin_keys(keys: list[dict]) -> None:
    import json
    import portalocker  # type: ignore
    with portalocker.Lock(str(_ADMIN_KEYS_PATH) + ".lock", timeout=5):
        _ADMIN_KEYS_PATH.write_text(json.dumps(keys, indent=2))


def generate_admin_key_for_owner(owner_id: int, username: str = "") -> str:
    keys = _load_admin_keys_from_db()
    raw = secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(raw.encode()).hexdigest()
    keys = [k for k in keys if k.get("ownerId") != owner_id]
    keys.append({
        "ownerId": owner_id,
        "username": username,
        "keyHash": key_hash,
        "createdAt": datetime.now(timezone.utc).isoformat(),
    })
    _save_admin_keys(keys)
    return raw


def find_admin_key_owner(plaintext: str) -> int | None:
    key_hash = hashlib.sha256(plaintext.encode()).hexdigest()
    for k in _load_admin_keys_from_db():
        if k.get("keyHash") == key_hash:
            return k.get("ownerId")
    return None


def consume_admin_key(plaintext: str) -> int | None:
    key_hash = hashlib.sha256(plaintext.encode()).hexdigest()
    keys = _load_admin_keys_from_db()
    matched = next((k for k in keys if k.get("keyHash") == key_hash), None)
    if not matched:
        return None
    new_keys = [k for k in keys if k.get("keyHash") != key_hash]
    _save_admin_keys(new_keys)
    return matched.get("ownerId")


def revoke_admin_key_for_owner(owner_id: int) -> bool:
    keys = _load_admin_keys_from_db()
    new_keys = [k for k in keys if k.get("ownerId") != owner_id]
    if len(new_keys) == len(keys):
        return False
    _save_admin_keys(new_keys)
    return True


# ── Owner / cafe creation ─────────────────────────────────────────────────────

def create_owner_in_db(username: str, email: str | None, password_hash: str, cafe_name: str = "") -> dict:
    from app.models import Owner, Cafe
    from app.utils.serializers import _owner_dict
    cafe = None
    if cafe_name:
        slug = re.sub(r"[^a-z0-9]+", "-", cafe_name.lower()).strip("-")[:60] or "cafe"
        existing = Cafe.query.filter_by(slug=slug).first()
        if not existing:
            cafe = Cafe(name=cafe_name, slug=slug)
            db.session.add(cafe)
            db.session.flush()
        else:
            cafe = existing
    owner = Owner(
        username=username,
        email=email,
        password_hash=password_hash,
        cafe_name=cafe_name,
        cafe_id=cafe.id if cafe else None,
    )
    db.session.add(owner)
    db.session.commit()
    return _owner_dict(owner)


def load_owners() -> list[dict]:
    from app.models import Owner
    from app.utils.serializers import _owner_dict
    return [_owner_dict(o) for o in Owner.query.order_by(Owner.id).all()]
