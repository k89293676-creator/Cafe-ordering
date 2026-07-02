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


def _start_periodic_retry(default_queue) -> None:
    """Issue 7: daemon thread that re-enqueues retry_failed_webhooks every 5 min.

    retry_failed_webhooks() is defined in app/tasks/jobs.py but was never
    called periodically.  This thread acts as a minimal scheduler — no
    APScheduler dependency needed.  A stable job_id prevents the queue from
    accumulating duplicate retry jobs when the previous run is still in flight.
    """
    import threading
    import time

    interval = int(os.environ.get("WEBHOOK_RETRY_INTERVAL_SECS", "300"))

    def _loop() -> None:
        while True:
            time.sleep(interval)
            try:
                from app.tasks.jobs import retry_failed_webhooks
                default_queue.enqueue(
                    retry_failed_webhooks,
                    job_timeout=120,
                    job_id="periodic-webhook-retry",  # stable ID prevents stacking
                    description="Periodic webhook retry (all owners)",
                )
                log.info(
                    "Enqueued periodic retry_failed_webhooks (interval=%ds)", interval
                )
            except Exception as exc:  # noqa: BLE001 — never crash the scheduler
                log.warning("Periodic webhook retry enqueue failed: %s", exc)

    t = threading.Thread(target=_loop, daemon=True, name="periodic-webhook-retry")
    t.start()
    log.info("Periodic webhook retry thread started (every %ds)", interval)


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

    # Issue 7: start periodic webhook retry scheduler (skipped in burst/CI mode
    # since burst workers exit as soon as queues are empty).
    if not burst:
        _start_periodic_retry(queues[0] if queues else Queue("default", connection=conn))

    worker.work(burst=burst)


if __name__ == "__main__":
    main()
