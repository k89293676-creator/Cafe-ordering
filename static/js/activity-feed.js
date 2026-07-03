/* ==========================================================
   Cafe 11:11 — Live Activity Feed Widget
   v1.0 · Shared across Owner, Admin, Superadmin, Customer
   ==========================================================
   Usage:
     const feed = new ActivityFeed(containerEl, {
       fetchEvents: async () => [...events],   // called each poll cycle
       pollInterval: 12000,
       maxItems: 40,
       emptyText: 'No activity yet.',
     });
     feed.start();
     feed.push({ icon:'🆕', label:'Table 3 placed order', sub:'4 items · ₹450', type:'new' });
*/

"use strict";

class ActivityFeed {
  constructor(container, opts = {}) {
    this._el          = typeof container === "string"
                          ? document.getElementById(container)
                          : container;
    this._fetch       = opts.fetchEvents    || null;
    this._interval    = opts.pollInterval   || 12000;
    this._max         = opts.maxItems       || 40;
    this._emptyText   = opts.emptyText      || "No recent activity.";
    this._events      = [];   // newest first
    this._timer       = null;
    this._running     = false;
    this._listEl      = null;
    this._badgeEl     = opts.badgeEl || null;
    this._unseenCount = 0;

    this._build();
  }

  /* ── Build DOM skeleton ───────────────────────────────────── */
  _build() {
    if (!this._el) return;
    this._listEl = this._el.querySelector(".af-list");
    if (!this._listEl) {
      // container is bare — wrap it
      this._el.innerHTML = `<div class="af-list"></div>`;
      this._listEl = this._el.querySelector(".af-list");
    }
    this._showEmpty();
  }

  /* ── Public API ───────────────────────────────────────────── */
  start() {
    this._running = true;
    this._poll();
    this._timer = setInterval(() => this._poll(), this._interval);
    document.addEventListener("visibilitychange", () => {
      if (!document.hidden && this._running) this._poll();
    });
  }

  stop() {
    this._running = false;
    clearInterval(this._timer);
  }

  /** Push a single event immediately (no poll needed) */
  push(evt) {
    this._addEvent(evt, true);
    this._render();
  }

  /** Replace full event list (from bulk fetch) */
  setEvents(evts) {
    this._events = evts.slice(0, this._max);
    this._render();
  }

  /** Prepend new events, keep ring buffer size ≤ max */
  prependEvents(evts) {
    if (!evts.length) return;
    this._events = [...evts, ...this._events].slice(0, this._max);
    this._unseenCount += evts.length;
    if (this._badgeEl) {
      this._badgeEl.textContent = this._unseenCount;
      this._badgeEl.style.display = this._unseenCount ? "" : "none";
    }
    this._render();
  }

  resetUnseen() {
    this._unseenCount = 0;
    if (this._badgeEl) this._badgeEl.style.display = "none";
  }

  /* ── Private helpers ──────────────────────────────────────── */
  async _poll() {
    if (!this._fetch) return;
    try {
      const newEvts = await this._fetch(this._events[0]?.id);
      if (newEvts && newEvts.length) this.prependEvents(newEvts);
    } catch (_) { /* silent — network flake */ }
  }

  _addEvent(evt, prepend = false) {
    if (prepend) {
      this._events.unshift(evt);
    } else {
      this._events.push(evt);
    }
    if (this._events.length > this._max) this._events.length = this._max;
  }

  _render() {
    if (!this._listEl) return;
    if (!this._events.length) { this._showEmpty(); return; }

    const html = this._events.map((e, i) => {
      const typeClass = `af-item--${e.type || "info"}`;
      const isNew     = i === 0 ? "af-item--new" : "";
      return `<div class="af-item ${typeClass} ${isNew}" data-id="${e.id || i}">
        <div class="af-item__icon">${e.icon || "•"}</div>
        <div class="af-item__body">
          <div class="af-item__label">${_esc(e.label)}</div>
          ${e.sub ? `<div class="af-item__sub">${_esc(e.sub)}</div>` : ""}
        </div>
        <div class="af-item__time">${_fmtTime(e.time)}</div>
      </div>`;
    }).join("");

    this._listEl.innerHTML = html;

    // Animate the newest item in
    const first = this._listEl.firstElementChild;
    if (first && first.classList.contains("af-item--new")) {
      first.classList.add("af-item--animate");
      setTimeout(() => first.classList.remove("af-item--new"), 2500);
    }
  }

  _showEmpty() {
    if (!this._listEl) return;
    this._listEl.innerHTML =
      `<div class="af-empty">${_esc(this._emptyText)}</div>`;
  }
}

/* ── Helper: escape HTML ─────────────────────────────────── */
function _esc(s) {
  return String(s ?? "")
    .replace(/&/g,"&amp;").replace(/</g,"&lt;")
    .replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

/* ── Helper: relative timestamp ──────────────────────────── */
function _fmtTime(ts) {
  if (!ts) return "";
  const d = typeof ts === "number" ? new Date(ts) : new Date(ts);
  const diff = Math.round((Date.now() - d) / 1000);
  if (diff < 5)  return "just now";
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  return d.toLocaleTimeString([], {hour:"2-digit", minute:"2-digit"});
}

/* ==========================================================
   Owner / Admin / Superadmin — Kitchen Orders Activity Feed
   Uses /api/kitchen/orders?since=... (delta polling)
   ========================================================== */

function initKitchenFeed(containerEl, badgeEl) {
  if (!containerEl) return null;

  let lastFetchedAt = null;
  // snapshot: orderId → status (for change detection)
  const _snap = new Map();

  const STATUS_META = {
    pending:   { icon:"🆕", label:"New order",    type:"new"     },
    confirmed: { icon:"✅", label:"Confirmed",     type:"confirm" },
    preparing: { icon:"👨‍🍳", label:"Preparing",    type:"prepare" },
    ready:     { icon:"🔔", label:"Ready",         type:"ready"   },
    completed: { icon:"🎉", label:"Completed",     type:"done"    },
    cancelled: { icon:"❌", label:"Cancelled",     type:"cancel"  },
  };

  const feed = new ActivityFeed(containerEl, {
    badgeEl,
    pollInterval: 12000,
    maxItems: 40,
    emptyText: "Waiting for orders…",
    fetchEvents: async () => {
      const url = lastFetchedAt
        ? `/api/kitchen/orders?since=${encodeURIComponent(lastFetchedAt)}&include_completed=1`
        : `/api/kitchen/orders`;
      const res = await fetch(url, { credentials: "same-origin" });
      if (!res.ok) return [];
      const data = await res.json();
      lastFetchedAt = data.fetchedAt || new Date().toISOString();

      const newEvents = [];
      (data.orders || []).forEach(o => {
        const prev = _snap.get(o.id);
        const cur  = o.status;
        _snap.set(o.id, cur);

        if (!prev) {
          // Brand-new order in our snapshot (first load or newly placed)
          if (cur === "pending") {
            const meta = STATUS_META["pending"];
            newEvents.push({
              id:    `${o.id}-new`,
              icon:  meta.icon,
              label: `${o.tableName || "Table"} — new order`,
              sub:   `${(o.items||[]).length} item(s) · ₹${(o.total||0).toFixed(2)}`,
              type:  meta.type,
              time:  o.createdAt || Date.now(),
            });
          }
        } else if (prev !== cur) {
          // Status change
          const meta = STATUS_META[cur] || { icon:"•", label:cur, type:"info" };
          newEvents.push({
            id:    `${o.id}-${cur}`,
            icon:  meta.icon,
            label: `${o.tableName || "Table"} → ${meta.label}`,
            sub:   `Order #${o.id} · ₹${(o.total||0).toFixed(2)}`,
            type:  meta.type,
            time:  Date.now(),
          });
        }
      });

      return newEvents;
    },
  });

  feed.start();
  return feed;
}

/* ==========================================================
   Customer — Order Status Live Log
   Uses /api/orders/<id>/stream (SSE) + polling fallback
   ========================================================== */

function initCustomerFeed(containerEl, orderId, pickupCode) {
  if (!containerEl || !orderId) return null;
  // pickup_code is required by the server IDOR fix; encode it safely.
  const pcParam = pickupCode ? `?pickup_code=${encodeURIComponent(pickupCode)}` : "";

  const STATUS_META = {
    pending:   { icon:"⏳", label:"Order received",  sub:"We've got your order!", type:"info"    },
    confirmed: { icon:"✅", label:"Confirmed",        sub:"Your order is confirmed.", type:"confirm" },
    preparing: { icon:"👨‍🍳", label:"Being prepared",  sub:"The kitchen is working on it!", type:"prepare" },
    ready:     { icon:"🔔", label:"Ready to collect!", sub:"Come to the counter to collect.", type:"ready"  },
    completed: { icon:"🎉", label:"Order complete",   sub:"Thank you for dining with us!", type:"done"    },
    cancelled: { icon:"❌", label:"Cancelled",         sub:"Please speak with staff.", type:"cancel"  },
  };

  const feed = new ActivityFeed(containerEl, {
    maxItems: 20,
    emptyText: "Waiting for updates…",
  });

  let lastStatus = null;

  function handleStatus(status) {
    if (status === lastStatus) return;
    lastStatus = status;
    const meta = STATUS_META[status] || { icon:"•", label:status, sub:"", type:"info" };
    feed.push({
      id:   `${orderId}-${status}-${Date.now()}`,
      icon:  meta.icon,
      label: meta.label,
      sub:   meta.sub,
      type:  meta.type,
      time:  Date.now(),
    });
  }

  // Try SSE first
  let sse = null;
  let pollTimer = null;

  function startSSE() {
    try {
      sse = new EventSource(`/api/orders/${orderId}/stream${pcParam}`);
      sse.onmessage = e => {
        try {
          const d = JSON.parse(e.data);
          if (d.status) handleStatus(d.status);
        } catch (_) {}
      };
      sse.onerror = () => {
        sse.close();
        startPollFallback();
      };
    } catch (_) {
      startPollFallback();
    }
  }

  async function pollOnce() {
    try {
      const res = await fetch(`/api/orders/${orderId}${pcParam}`, { credentials: "same-origin" });
      if (res.ok) {
        const d = await res.json();
        if (d.order?.status) handleStatus(d.order.status);
        if (["completed","cancelled"].includes(d.order?.status)) {
          clearInterval(pollTimer);
        }
      }
    } catch (_) {}
  }

  function startPollFallback() {
    pollOnce();
    pollTimer = setInterval(pollOnce, 15000);
  }

  if (typeof EventSource !== "undefined") {
    startSSE();
  } else {
    startPollFallback();
  }

  return feed;
}

/* ── Expose globally ──────────────────────────────────────── */
window.ActivityFeed       = ActivityFeed;
window.initKitchenFeed    = initKitchenFeed;
window.initCustomerFeed   = initCustomerFeed;
