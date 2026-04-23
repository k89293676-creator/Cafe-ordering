"""Gunicorn configuration for production (Railway) deployments.

Loaded by ``start.py`` via ``--config python:gunicorn_conf``. Hard-coded
defaults are tuned for Railway free-tier (512 MB / 1 vCPU). Each value can
be overridden through environment variables — handy when scaling up.

The gevent worker class is intentionally retained because it is highly
memory-efficient and pairs well with the SSE / long-poll routes in this
codebase.
"""
from __future__ import annotations

import os
import logging


# ── Networking ──────────────────────────────────────────────────────────────
bind = f"0.0.0.0:{os.environ.get('PORT', '8000')}"

# ── Worker model ────────────────────────────────────────────────────────────
worker_class = "gevent"
workers = int(os.environ.get("WEB_CONCURRENCY", "1"))
threads = int(os.environ.get("GUNICORN_THREADS", "2"))
worker_connections = int(os.environ.get("GUNICORN_WORKER_CONNECTIONS", "1000"))

# ── Timeouts & recycling ────────────────────────────────────────────────────
timeout = int(os.environ.get("GUNICORN_TIMEOUT", "60"))
graceful_timeout = int(os.environ.get("GUNICORN_GRACEFUL_TIMEOUT", "30"))
keepalive = int(os.environ.get("GUNICORN_KEEPALIVE", "5"))
max_requests = int(os.environ.get("GUNICORN_MAX_REQUESTS", "500"))
max_requests_jitter = int(os.environ.get("GUNICORN_MAX_REQUESTS_JITTER", "50"))

# ── Trust proxy headers (Railway terminates TLS at the edge) ────────────────
forwarded_allow_ips = os.environ.get("FORWARDED_ALLOW_IPS", "*")
proxy_allow_ips = os.environ.get("PROXY_ALLOW_IPS", "*")

# ── Logging — emit access + error logs to stdout/stderr so Railway captures
#     them. The app itself emits structured JSON via @app.after_request, so
#     gunicorn's access log stays in the simpler combined format.
accesslog = "-"
errorlog = "-"
loglevel = os.environ.get("GUNICORN_LOG_LEVEL", "info")
access_log_format = (
    '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(L)ss'
)


# ── Lifecycle hooks ─────────────────────────────────────────────────────────
def on_starting(server) -> None:
    """Logged once when the master boots. Useful as a deploy marker."""
    logging.getLogger("gunicorn.error").info(
        "gunicorn master starting: workers=%s threads=%s worker_class=%s",
        workers, threads, worker_class,
    )


def post_fork(server, worker) -> None:
    """Re-seed entropy and dispose pre-fork DB connections so each worker owns
    its own connection pool. Inheriting open sockets across fork() is the most
    common cause of mysterious ``InterfaceError: connection already closed``
    errors right after a deploy."""
    try:
        from app import db  # local import to avoid loading the app in master
        db.engine.dispose()
    except Exception:  # pragma: no cover — best-effort cleanup
        pass


def worker_int(worker) -> None:
    """SIGINT (Ctrl-C / Railway shutdown) — log and let gevent flush."""
    worker.log.info("worker received SIGINT, draining…")


def worker_abort(worker) -> None:
    """SIGABRT — usually a hung request killed by the master timeout."""
    worker.log.warning("worker aborted (timeout?)")
