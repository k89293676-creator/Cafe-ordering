from __future__ import annotations

import os
import sys


def main() -> None:
    """Launch gunicorn with safe defaults for Railway free-tier (512 MB / 1 vCPU).

    Hard-coded defaults are tuned for low-memory containers:
      - 1 worker keeps memory headroom for Python + gevent + SQLAlchemy pools.
      - 2 threads provides a small amount of I/O concurrency on top of gevent.
      - 60s timeout is generous for slow upstream calls (Mail, push, etc.) but
        still recycles stuck workers.
      - max-requests + jitter recycles workers periodically to avoid memory
        creep without thundering-herd restarts.

    The gevent worker class is intentionally retained because it is highly
    memory-efficient and pairs well with the SSE / long-poll routes.

    Environment variable overrides (WEB_CONCURRENCY, GUNICORN_THREADS,
    GUNICORN_TIMEOUT, GUNICORN_MAX_REQUESTS, GUNICORN_MAX_REQUESTS_JITTER) are
    intentionally commented out to prevent accidental misconfiguration on
    Railway. Re-enable them only if you know your container has more headroom.
    """
    port = os.environ.get("PORT", "8000")
    cmd = [
        sys.executable,
        "-m",
        "gunicorn",
        "app:app",
        "--bind",
        f"0.0.0.0:{port}",
        "--worker-class",
        "gevent",  # memory-efficient; do not change without load testing
        "--workers",
        "1",        # os.environ.get("WEB_CONCURRENCY", "1"),
        "--threads",
        "2",        # os.environ.get("GUNICORN_THREADS", "4"),
        "--timeout",
        "60",       # os.environ.get("GUNICORN_TIMEOUT", "120"),
        "--max-requests",
        "500",      # os.environ.get("GUNICORN_MAX_REQUESTS", "1000"),
        "--max-requests-jitter",
        "50",       # os.environ.get("GUNICORN_MAX_REQUESTS_JITTER", "100"),
    ]
    os.execvp(cmd[0], cmd)


if __name__ == "__main__":
    main()
