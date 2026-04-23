"""Interactive CLI to create or promote a superadmin owner.

Usage:
    python scripts/bootstrap_superadmin.py
    python scripts/bootstrap_superadmin.py --username admin --password 'StrongPass123'

This bypasses the env-var-only seeding in app._make_superadmin_if_missing()
so an operator can recover access without redeploying.
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

# Ensure project root is importable when run as `python scripts/...`
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> int:
    parser = argparse.ArgumentParser(description="Create or promote a superadmin owner.")
    parser.add_argument("--username", help="Owner username (default: prompt)")
    parser.add_argument("--password", help="Owner password (default: prompt)")
    parser.add_argument("--email", help="Owner email (optional)")
    args = parser.parse_args()

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

    with app.app_context() if hasattr(app, "app_context") else app.app.app_context():
        flask_app = getattr(app, "app", app)
        Owner = app.Owner
        db = app.db
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
