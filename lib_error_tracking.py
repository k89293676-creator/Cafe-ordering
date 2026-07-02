"""Structured error tracking that works without Sentry.

Why this module exists
----------------------
The codebase already initialises Sentry when ``SENTRY_DSN`` is set, and
keeps a tiny in-process ring buffer (``_LAST_ERRORS``) for the
``/superadmin/last-error`` page. Both have gaps:

- Sentry costs money on volume; many small operators turn it off.
- The in-process buffer is per-worker, so the same error can hide on a
  worker the operator never inspects — and it dies on every restart.

This module adds a third layer that fills both gaps:

- A **JSONL file** (``LOGS_DIR / errors.jsonl``) that every worker
  appends to with portalocker, so an SSH-less operator can ``tail -f``
  it from a Railway shell and see *every* worker's errors interleaved
  in real time.
- A **token-protected API** (``GET /api/ops/errors``) returning the
  last N JSONL entries — same auth as ``/api/ops/health``, so the
  GitHub Actions post-deploy workflow can verify "no fresh errors" as
  one more probe.

The file rotates at ``ERROR_LOG_MAX_BYTES`` (default 5 MB) — old
content is overwritten as a single in-place truncation. This is
deliberately simple: a real shop with retention requirements should
ship to Sentry / Datadog instead.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import portalocker  # type: ignore
    _PORTA_OK = True
except ImportError:  # pragma: no cover - portalocker is in requirements.txt
    _PORTA_OK = False


_logger = logging.getLogger("cafe.errors")

# Default location under the existing data dir; overridden by app.py at
# registration time so we honour DATA_DIR / LOGS_DIR conventions.
_LOG_PATH: Path | None = None
_MAX_BYTES = int(os.environ.get("ERROR_LOG_MAX_BYTES", str(5 * 1024 * 1024)))
_INMEM_RING_MAX = int(os.environ.get("ERROR_INMEM_RING_MAX", "100"))
_INMEM: list[dict] = []
_INMEM_LOCK = threading.Lock()


def configure(log_path: Path) -> None:
    """Tell the tracker where to write its JSONL file.

    Called once from ``app.py`` after the data directory is known.
    """
    global _LOG_PATH
    _LOG_PATH = Path(log_path)
    _LOG_PATH.parent.mkdir(parents=True, exist_ok=True)


def _truncate_if_needed(path: Path) -> None:
    """Rotate by simple truncation when the file exceeds the max size.

    A more elaborate rotation (rename + delete) would race with concurrent
    writers; truncation under the same lock is atomic and never loses
    fresh writes that arrive after the check.
    """
    try:
        if path.exists() and path.stat().st_size > _MAX_BYTES:
            path.write_text("", encoding="utf-8")
    except OSError:
        pass


def capture(event: dict[str, Any]) -> None:
    """Persist one error event. Best-effort — never raises.

    Always writes to the in-memory ring (so the support endpoint works
    even on a read-only filesystem) and tries to append to the JSONL
    file (so cross-worker / multi-restart visibility works).
    """
    enriched = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "monotonic": time.monotonic(),
        **event,
    }
    # In-memory first — cheap and always available.
    with _INMEM_LOCK:
        _INMEM.insert(0, enriched)
        del _INMEM[_INMEM_RING_MAX:]

    if _LOG_PATH is None or not _PORTA_OK:
        return
    try:
        # Cross-process append: portalocker advisory lock guards the
        # truncate-or-append window so two workers can't shred each other.
        lock_path = str(_LOG_PATH) + ".lock"
        with portalocker.Lock(lock_path, timeout=2):
            _truncate_if_needed(_LOG_PATH)
            with _LOG_PATH.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(enriched, ensure_ascii=False, default=str))
                fh.write("\n")
    except Exception as exc:  # noqa: BLE001
        # Capture failures must never propagate — the request that
        # caused the original error has its own concerns.
        _logger.warning("error-tracking: write failed: %s", exc)


def capture_exception(where: str, exc: BaseException, *,
                      request_id: str = "", path: str = "",
                      method: str = "", ip: str = "",
                      owner_id: int | None = None,
                      extra: dict | None = None) -> None:
    """Record one exception with full traceback + request context."""
    payload: dict[str, Any] = {
        "where": where,
        "type": type(exc).__name__,
        "message": str(exc)[:1000],
        "traceback": "".join(traceback.format_exception(
            type(exc), exc, exc.__traceback__))[:8000],
        "request_id": request_id or "",
        "path": path or "",
        "method": method or "",
        "ip": ip or "",
        "owner_id": owner_id,
    }
    if extra:
        # ``extra`` may carry the dimensions a Sentry tag would (e.g.
        # provider="stripe", route="checkout") so the operator can
        # filter the JSONL with a one-line jq.
        payload["extra"] = extra
    capture(payload)


def recent(limit: int = 50, *, since_seconds: int | None = None) -> list[dict]:
    """Return up to ``limit`` recent events from the in-memory ring.

    Cross-worker view requires reading the JSONL file — see ``read_jsonl``.
    """
    limit = max(1, min(int(limit or 50), _INMEM_RING_MAX))
    with _INMEM_LOCK:
        if since_seconds is None:
            return list(_INMEM[:limit])
        cutoff = time.monotonic() - max(0, int(since_seconds))
        return [e for e in _INMEM if e.get("monotonic", 0) >= cutoff][:limit]


def read_jsonl(limit: int = 100) -> list[dict]:
    """Return up to ``limit`` recent JSONL entries (cross-worker view).

    Reads the tail of the file in reverse and returns one event per line.
    Lines that fail to parse are skipped silently (malformed writes from
    a crashed worker shouldn't break the support page).
    """
    if _LOG_PATH is None or not _LOG_PATH.exists():
        return []
    limit = max(1, min(int(limit or 100), 500))
    try:
        with _LOG_PATH.open("r", encoding="utf-8", errors="replace") as fh:
            tail: list[str] = []
            # Cheap reverse-read: small file (5 MB max) so just slurp it.
            for line in fh:
                tail.append(line)
                if len(tail) > limit + 50:
                    tail = tail[-(limit + 10):]
        events = []
        for line in reversed(tail):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
            if len(events) >= limit:
                break
        return events
    except OSError as exc:
        _logger.warning("error-tracking: read failed: %s", exc)
        return []


def stats() -> dict:
    """Quick health snapshot for the ops dashboard."""
    return {
        "in_memory_count": len(_INMEM),
        "in_memory_max": _INMEM_RING_MAX,
        "jsonl_path": str(_LOG_PATH) if _LOG_PATH else None,
        "jsonl_size_bytes": (
            _LOG_PATH.stat().st_size
            if _LOG_PATH and _LOG_PATH.exists() else 0
        ),
        "max_bytes": _MAX_BYTES,
    }


# ---------------------------------------------------------------------------
# Flask integration
# ---------------------------------------------------------------------------

def register(app, *, data_dir: Path) -> None:
    """Wire the tracker into a Flask app.

    Adds:
      * ``GET /api/ops/errors`` — token-protected (re-uses
        ``OPS_HEALTH_TOKEN``); returns recent JSONL events.
      * Configures the file path under ``data_dir / "logs"``.
    """
    import hmac
    from flask import jsonify, request

    log_dir = Path(data_dir) / "logs"
    configure(log_dir / "errors.jsonl")

    @app.route("/api/ops/errors")
    def _ops_errors():
        token = (os.environ.get("OPS_HEALTH_TOKEN") or "").strip()
        provided = (request.headers.get("Authorization") or "").strip()
        if provided.lower().startswith("bearer "):
            provided = provided[7:].strip()
        if not token or not hmac.compare_digest(token, provided):
            return jsonify(error="unauthorized"), 401

        try:
            limit = int(request.args.get("limit", "50"))
        except (TypeError, ValueError):
            limit = 50
        source = (request.args.get("source") or "memory").lower()
        if source == "jsonl":
            events = read_jsonl(limit=limit)
        else:
            events = recent(limit=limit)
        return jsonify({
            "ok": True,
            "source": source,
            "count": len(events),
            "stats": stats(),
            "events": events,
        })
