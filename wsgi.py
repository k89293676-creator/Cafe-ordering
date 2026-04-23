"""Dev/prod entry point.

Importing app as a module (instead of running ``python app.py`` directly)
ensures ``from app import db`` everywhere returns the same SQLAlchemy
instance. Running ``python app.py`` makes the file load twice (once as
``__main__``, once as ``app``) which produces two ``db`` objects and
breaks the extensions blueprint registration.
"""
from __future__ import annotations

import os

from app import app  # noqa: F401  (re-exported for gunicorn / waitress)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("FLASK_ENV") == "development"
    app.run(host="0.0.0.0", port=port, debug=debug, use_reloader=False)
