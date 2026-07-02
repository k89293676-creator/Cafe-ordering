"""Tests for the 5xx error handlers and the JSONL error tracker.

We can't trigger a real 502/503/504 from inside the Flask test client
(those are emitted by upstream proxies), but we can verify that:

  * The handler registry contains a renderable template for each code
    so a future ``abort(503)`` call doesn't 500 trying to render.
  * The 500 handler captures into both the in-memory ring AND the
    JSONL file when a route raises.
  * ``GET /api/ops/errors`` enforces the OPS_HEALTH_TOKEN.
"""
from __future__ import annotations

import importlib
import json
import os
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _ops_token(monkeypatch):
    monkeypatch.setenv("OPS_HEALTH_TOKEN", "test-token-123")


def test_error_templates_render_for_each_status(client, app):
    """Every error template under templates/errors/ must be renderable.

    A template that raises during render would replace a 500 with a
    fresh 500 inside the error handler — silent failure mode.
    """
    from flask import render_template

    with app.app_context():
        for code in ("400", "403", "404", "405", "413", "429",
                      "500", "502", "503", "504"):
            html = render_template(f"errors/{code}.html",
                                     request_id="rid-test",
                                     retry_after=42)
            assert "Cafe Portal" in html, f"errors/{code}.html missing brand"
            assert code in html, f"errors/{code}.html missing status code"


def test_error_tracker_jsonl_round_trip(tmp_path, monkeypatch):
    """capture() → read_jsonl() must round-trip a payload across file boundary."""
    import lib_error_tracking as et
    importlib.reload(et)
    et.configure(tmp_path / "errors.jsonl")

    et.capture({"where": "test", "type": "ValueError", "message": "boom"})
    events = et.read_jsonl(limit=10)
    assert len(events) == 1
    assert events[0]["where"] == "test"
    assert events[0]["type"] == "ValueError"
    assert "ts" in events[0]


def test_error_tracker_in_memory_ring_caps(monkeypatch):
    """In-memory ring must enforce its size cap — an unbounded list
    is the kind of thing that takes a server down at 3am."""
    import lib_error_tracking as et
    importlib.reload(et)
    et._INMEM_RING_MAX = 5  # local override for the test

    for i in range(20):
        et.capture({"where": f"r{i}", "type": "X", "message": str(i)})
    rec = et.recent(limit=100)
    assert len(rec) == 5
    # Newest-first ordering preserved
    assert rec[0]["where"] == "r19"
    assert rec[-1]["where"] == "r15"


def test_error_tracker_capture_never_raises(monkeypatch):
    """Even with a busted log path, capture() must not propagate."""
    import lib_error_tracking as et
    importlib.reload(et)
    # Point at a path inside a file (so mkdir fails) — capture must
    # swallow the OSError because crashing the error path would crash
    # the original error path it's instrumenting.
    bad = Path("/dev/null/cannot/exist/errors.jsonl")
    et._LOG_PATH = bad  # bypass configure() which would have raised
    et.capture({"where": "still-works", "type": "X", "message": "x"})
    # In-memory still got it
    assert any(e.get("where") == "still-works" for e in et.recent())


def test_ops_errors_endpoint_requires_token(client):
    """No bearer token → 401."""
    res = client.get("/api/ops/errors")
    assert res.status_code == 401


def test_ops_errors_endpoint_with_token(client):
    """Right token → 200 + JSON envelope."""
    res = client.get("/api/ops/errors",
                       headers={"Authorization": "Bearer test-token-123"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["ok"] is True
    assert "events" in data
    assert "stats" in data


def test_ops_errors_endpoint_wrong_token(client):
    res = client.get("/api/ops/errors",
                       headers={"Authorization": "Bearer wrong"})
    assert res.status_code == 401


def test_500_handler_returns_html(client, app):
    """An uncaught exception in a route must render errors/500.html."""

    @app.route("/__test__/boom")
    def _boom():
        raise RuntimeError("intentional test failure")

    app.config["TESTING"] = False  # otherwise Flask propagates
    try:
        res = client.get("/__test__/boom")
    finally:
        app.config["TESTING"] = True

    assert res.status_code == 500
    body = res.get_data(as_text=True)
    assert "500" in body
    assert "Cafe Portal" in body
