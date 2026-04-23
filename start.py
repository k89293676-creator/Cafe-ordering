from __future__ import annotations

import os
import sys


def main() -> None:
    """Launch gunicorn using ``gunicorn_conf.py``.

    All worker-pool tuning lives in ``gunicorn_conf.py`` so it can be read,
    diffed, and overridden via environment variables in one place. Defaults
    are tuned for Railway free-tier (512 MB / 1 vCPU). See ``ENV_CONFIG.md``
    for the override list (WEB_CONCURRENCY, GUNICORN_THREADS, …).
    """
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
