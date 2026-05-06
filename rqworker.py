#!/usr/bin/env python3
"""RQ worker entry point.

Start a worker that processes background jobs from the default queue::

    python rqworker.py

Environment variables:
    REDIS_URL          — Redis connection URI (required)
    RQ_WORKER_NAME     — Override the auto-generated worker name
    RQ_QUEUES          — Comma-separated queue names to listen on (default: "default")
    RQ_BURST           — Set to "true" to exit when queues are empty (CI mode)
"""
from __future__ import annotations

import logging
import os
import sys

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
)
log = logging.getLogger("cafe.rqworker")


def main() -> None:
    redis_url = os.environ.get("REDIS_URL")
    if not redis_url:
        log.error("REDIS_URL is not set — RQ worker cannot start.")
        sys.exit(1)

    try:
        import redis
        from rq import Queue, Worker
    except ImportError:
        log.error("rq is not installed. Run: pip install rq")
        sys.exit(1)

    queues_env = os.environ.get("RQ_QUEUES", "default")
    queue_names = [q.strip() for q in queues_env.split(",") if q.strip()]
    burst = os.environ.get("RQ_BURST", "false").lower() in {"1", "true", "yes"}

    conn = redis.from_url(redis_url)
    queues = [Queue(name, connection=conn) for name in queue_names]

    worker_name = os.environ.get("RQ_WORKER_NAME")
    kwargs: dict = dict(queues=queues, connection=conn)
    if worker_name:
        kwargs["name"] = worker_name

    log.info("RQ worker starting: queues=%s burst=%s", queue_names, burst)
    worker = Worker(**kwargs)
    worker.work(burst=burst)


if __name__ == "__main__":
    main()
