"""Test fixtures: bring up the Flask app on an in-memory SQLite database."""
from __future__ import annotations

import os
import sys
import tempfile

import pytest

# Force a clean test environment BEFORE app.py is imported.
os.environ["FLASK_ENV"] = "development"
os.environ["TESTING"] = "1"
os.environ.pop("REDIS_URL", None)
os.environ.setdefault("SESSION_SECRET", "test-secret")
os.environ.setdefault("SECRET_KEY", "test-secret")

# Use an isolated SQLite file so each test session starts fresh.
_TMP_DB = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
_TMP_DB.close()
os.environ["DATABASE_URL"] = f"sqlite:///{_TMP_DB.name}"

# Make the project root importable.
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


@pytest.fixture(scope="session")
def app():
    import app as flask_app  # noqa: WPS433
    flask_app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    with flask_app.app.app_context():
        flask_app.db.create_all()
    return flask_app.app


@pytest.fixture()
def client(app):
    return app.test_client()
