from __future__ import annotations

import os
import sys


# ---------------------------------------------------------------------------
# Production environment validation
# Fail fast here — before gunicorn forks workers — so Railway's pre-deploy
# healthcheck surfaces a clear error rather than a cryptic worker crash.
# ---------------------------------------------------------------------------

def _validate_env() -> None:
    errors: list[str] = []

    # Detect whether we are running in a production-like environment.
    # Railway sets RAILWAY_ENVIRONMENT; Render sets RENDER=true;
    # IS_PRODUCTION is the manual override.
    is_prod = (
        os.environ.get("IS_PRODUCTION", "").lower() in {"1", "true", "yes"}
        or os.environ.get("RAILWAY_ENVIRONMENT", "").lower() == "production"
        or os.environ.get("FLASK_ENV", "") == "production"
        or os.environ.get("RENDER") is not None
    )

    secret_key = os.environ.get("SECRET_KEY", "")
    if not secret_key:
        errors.append("SECRET_KEY is not set — sessions and CSRF cannot work.")
    elif is_prod and len(secret_key) < 32:
        errors.append(
            f"SECRET_KEY is only {len(secret_key)} chars in production; "
            "use at least 32 random bytes."
        )

    _raw_db_url = os.environ.get("DATABASE_URL", "")
    if is_prod and not _raw_db_url:
        errors.append(
            "DATABASE_URL is not set. Orders would be lost on container restart. "
            "Attach a Postgres service (Railway / Render) and confirm DATABASE_URL is wired."
        )
    elif _raw_db_url:
        # Validate that the URL is actually parseable — a non-empty but malformed
        # DATABASE_URL (e.g. a DSN string, unexpanded template, or missing scheme)
        # will pass the presence check above but crash SQLAlchemy on startup.
        import re as _re
        _coerced = _raw_db_url
        if _coerced.startswith("postgres://"):
            _coerced = _coerced.replace("postgres://", "postgresql://", 1)
        if not _re.match(r"^[\w+]+://", _coerced):
            _preview = _coerced[:60].replace("\n", " ")
            errors.append(
                f"DATABASE_URL does not look like a valid connection URL. "
                f"Expected postgresql://user:pass@host:port/db, "
                f"got: {_preview!r}. "
                f"Check the Environment Variables section in your Render dashboard."
            )

    if errors:
        for msg in errors:
            print(f"[start] FATAL: {msg}", file=sys.stderr)
        sys.exit(1)

    # Friendly startup banner so Railway logs show intent at boot time.
    port = os.environ.get("PORT", "8000")
    workers = os.environ.get("WEB_CONCURRENCY", "auto")
    commit = (
        (os.environ.get("RAILWAY_GIT_COMMIT_SHA") or "")[:12]
        or (os.environ.get("RENDER_GIT_COMMIT") or "")[:12]
        or os.environ.get("APP_VERSION", "dev")
    )
    env_label = "production" if is_prod else "development"
    print(
        f"[start] cafe-ordering {commit} | env={env_label} "
        f"port={port} workers={workers}",
        flush=True,
    )

    # Issue 9: warn when running multiple workers without a shared session store.
    # Each gunicorn worker gets its own in-memory/filesystem session cache when
    # REDIS_URL is absent, so a user whose requests land on different workers
    # will appear to be randomly logged out.  Redis makes sticky sessions
    # unnecessary by giving all workers a single shared session backend.
    if not os.environ.get("REDIS_URL"):
        try:
            import multiprocessing as _mp
            _n_str = str(workers).lower()
            if _n_str == "auto":
                _n_workers = min((_mp.cpu_count() * 2) + 1, 8)
            else:
                _n_workers = int(_n_str)
        except Exception:
            _n_workers = 1
        if _n_workers > 1:
            print(
                f"[start] WARN: WEB_CONCURRENCY={_n_workers} but REDIS_URL is not "
                "set. Without a shared session store, users on different workers "
                "will lose their sessions. Set REDIS_URL for any multi-worker "
                "production deploy.",
                file=sys.stderr,
                flush=True,
            )


def main() -> None:
    """Launch gunicorn using ``gunicorn_conf.py``.

    All worker-pool tuning lives in ``gunicorn_conf.py`` so it can be read,
    diffed, and overridden via environment variables in one place. Defaults
    are tuned for Railway free-tier (512 MB / 1 vCPU). See ``ENV_CONFIG.md``
    for the override list (WEB_CONCURRENCY, GUNICORN_THREADS, …).
    """
    _validate_env()

    cmd = [
        sys.executable,
        "-m",
        "gunicorn",
        "app:app",
        "--config",
        "python:gunicorn_conf",
    ]
    os.execvp(cmd[0], cmd)


if __name__ == "__main__":
    main()
