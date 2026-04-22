from __future__ import annotations

import os
import sys


def main() -> None:
    port = os.environ.get("PORT", "8000")
    cmd = [
        sys.executable,
        "-m",
        "gunicorn",
        "app:app",
        "--bind",
        f"0.0.0.0:{port}",
        "--worker-class",
        os.environ.get("GUNICORN_WORKER_CLASS", "gevent"),
        "--workers",
        os.environ.get("WEB_CONCURRENCY", "1"),
        "--threads",
        os.environ.get("GUNICORN_THREADS", "4"),
        "--timeout",
        os.environ.get("GUNICORN_TIMEOUT", "120"),
        "--max-requests",
        os.environ.get("GUNICORN_MAX_REQUESTS", "1000"),
        "--max-requests-jitter",
        os.environ.get("GUNICORN_MAX_REQUESTS_JITTER", "100"),
    ]
    os.execvp(cmd[0], cmd)


if __name__ == "__main__":
    main()