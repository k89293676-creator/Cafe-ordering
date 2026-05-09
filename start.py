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
    # Railway sets RAILWAY_ENVIRONMENT; IS_PRODUCTION is the manual override.
    is_prod = (
        os.environ.get("IS_PRODUCTION", "").lower() in {"1", "true", "yes"}
        or os.environ.get("RAILWAY_ENVIRONMENT", "").lower() == "production"
        or os.environ.get("FLASK_ENV", "") == "production"
    )

    secret_key = os.environ.get("SECRET_KEY", "")
    if not secret_key:
        errors.append("SECRET_KEY is not set — sessions and CSRF cannot work.")
    elif is_prod and len(secret_key) < 32:
        errors.append(
            f"SECRET_KEY is only {len(secret_key)} chars in production; "
            "use at least 32 random bytes."
        )

    if is_prod and not os.environ.get("DATABASE_URL"):
        errors.append(
            "DATABASE_URL is not set. Orders would be lost on container restart. "
            "Attach a Railway PostgreSQL service and confirm DATABASE_URL is wired."
        )

    if errors:
        for msg in errors:
            print(f"[start] FATAL: {msg}", file=sys.stderr)
        sys.exit(1)

    # Friendly startup banner so Railway logs show intent at boot time.
    port = os.environ.get("PORT", "8000")
    workers = os.environ.get("WEB_CONCURRENCY", "auto")
    commit = (
        os.environ.get("RAILWAY_GIT_COMMIT_SHA", "")[:12]
        or os.environ.get("APP_VERSION", "dev")
    )
    env_label = "production" if is_prod else "development"
    print(
        f"[start] cafe-ordering {commit} | env={env_label} "
        f"port={port} workers={workers}",
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
