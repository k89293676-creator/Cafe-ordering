"""Interactive CLI to create or promote a superadmin owner.

Access is gated by the SUPERADMIN_KEY environment variable (set on Railway,
Replit, or your hosting provider). The operator must supply the same key at
the prompt before any account changes are made.

Usage:
    SUPERADMIN_KEY=... python scripts/bootstrap_superadmin.py
    SUPERADMIN_KEY=... python scripts/bootstrap_superadmin.py \
        --username admin --password 'StrongPass123' --key "$SUPERADMIN_KEY"

Exit codes:
    0   success
    2   bad input / weak password
    3   SUPERADMIN_KEY not configured on the server
    4   provided key does not match SUPERADMIN_KEY
"""
from __future__ import annotations

import argparse
import getpass
import hmac
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _verify_superadmin_key(provided: str) -> bool:
    expected = os.environ.get("SUPERADMIN_KEY", "")
    if not expected:
        print(
            "ERROR: SUPERADMIN_KEY is not configured on this server. "
            "Set it in your hosting provider (Railway/Replit/etc.) first.",
            file=sys.stderr,
        )
        sys.exit(3)
    return hmac.compare_digest(expected.encode("utf-8"), (provided or "").encode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Create or promote a superadmin owner.")
    parser.add_argument("--username", help="Owner username (default: prompt)")
    parser.add_argument("--password", help="Owner password (default: prompt)")
    parser.add_argument("--email", help="Owner email (optional)")
    parser.add_argument("--key", help="SUPERADMIN_KEY (default: prompt)")
    args = parser.parse_args()

    provided_key = args.key or getpass.getpass("Enter SUPERADMIN_KEY: ")
    if not _verify_superadmin_key(provided_key):
        print("ERROR: provided key does not match SUPERADMIN_KEY.", file=sys.stderr)
        return 4

    username = (args.username or input("Superadmin username: ").strip())[:64]
    if not username:
        print("ERROR: username is required.", file=sys.stderr)
        return 2
    password = args.password or getpass.getpass("Password (min 8 chars, letters + digits): ")
    if len(password) < 8 or not any(c.isalpha() for c in password) or not any(c.isdigit() for c in password):
        print("ERROR: password must be at least 8 chars and contain a letter and a digit.", file=sys.stderr)
        return 2
    email = args.email or None

    os.environ.setdefault("SKIP_SUPERADMIN_AUTOSEED", "1")
    import app  # type: ignore

    flask_app = getattr(app, "app", app)
    Owner = app.Owner
    db = app.db
    with flask_app.app_context():
        existing = Owner.query.filter_by(username=username).first()
        if existing:
            existing.is_superadmin = True
            existing.is_active = True
            if email:
                existing.email = email
            existing.password_hash = app._make_password_hash(password)
            db.session.commit()
            print(f"OK: promoted '{username}' to superadmin and reset password.")
            return 0
        owner = Owner(
            username=username,
            email=email,
            password_hash=app._make_password_hash(password),
            cafe_name="",
            is_superadmin=True,
            is_active=True,
        )
        db.session.add(owner)
        db.session.commit()
        print(f"OK: created superadmin '{username}'.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
