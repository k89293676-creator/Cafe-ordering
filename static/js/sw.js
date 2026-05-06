/* ============================================================
   Cafe 11:11 — Service Worker v3
   Offline caching · Background Sync · Web Push notifications
   ============================================================ */

const CACHE_VERSION  = "cafe-v3";
const OFFLINE_URL    = "/static/offline.html";
const STATIC_ASSETS  = [
  "/static/css/styles.css",
  "/static/css/order.css",
  "/static/css/enhancements.css",
  "/static/js/table.js",
  "/static/manifest.json",
  "https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;600;700&family=Inter:wght@300;400;500;600&display=swap",
];

const SYNC_TAG_ORDER = "sync-pending-order";

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_VERSION)
      .then((cache) => cache.addAll(STATIC_ASSETS.map((u) => new Request(u, { mode: "no-cors" }))))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE_VERSION).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // Never intercept SSE / EventSource streams
  if (request.headers.get("accept") === "text/event-stream") return;
  if (request.method !== "GET") return;
  // API reads — network-first, no caching
  if (url.pathname.startsWith("/api/")) return;

  // Static assets & fonts — stale-while-revalidate
  if (
    url.pathname.startsWith("/static/") ||
    url.hostname === "fonts.googleapis.com" ||
    url.hostname === "fonts.gstatic.com"
  ) {
    event.respondWith(
      caches.open(CACHE_VERSION).then(async (cache) => {
        const cached = await cache.match(request);
        const networkFetch = fetch(request).then((res) => {
          if (res && res.status === 200) cache.put(request, res.clone());
          return res;
        }).catch(() => cached);
        return cached || networkFetch;
      })
    );
    return;
  }

  // HTML — network-first, offline fallback
  if (request.headers.get("accept")?.includes("text/html")) {
    event.respondWith(
      fetch(request)
        .then((res) => {
          caches.open(CACHE_VERSION).then((c) => c.put(request, res.clone()));
          return res;
        })
        .catch(async () => {
          const cached = await caches.match(request);
          return cached || caches.match(OFFLINE_URL) || new Response("Offline", { status: 503 });
        })
    );
  }
});

// ── Background Sync: replay orders submitted while offline ─────────────────
self.addEventListener("sync", (event) => {
  if (event.tag === SYNC_TAG_ORDER) {
    event.waitUntil(replayPendingOrders());
  }
});

async function replayPendingOrders() {
  try {
    const db = await openPendingOrdersDB();
    const pending = await getAllPending(db);
    for (const entry of pending) {
      try {
        const res = await fetch("/api/v1/checkout", {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-CSRFToken": entry.csrf || "" },
          body: JSON.stringify(entry.payload),
        });
        if (res.ok) {
          await deletePending(db, entry.id);
          notifyClients({ type: "order_synced", entryId: entry.id });
        }
      } catch (_) {}
    }
  } catch (_) {}
}

function openPendingOrdersDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open("cafe_pending_orders", 1);
    req.onupgradeneeded = (e) => {
      e.target.result.createObjectStore("orders", { keyPath: "id", autoIncrement: true });
    };
    req.onsuccess = (e) => resolve(e.target.result);
    req.onerror   = (e) => reject(e.target.error);
  });
}

function getAllPending(db) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction("orders", "readonly");
    const req = tx.objectStore("orders").getAll();
    req.onsuccess = (e) => resolve(e.target.result || []);
    req.onerror   = (e) => reject(e.target.error);
  });
}

function deletePending(db, id) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction("orders", "readwrite");
    tx.objectStore("orders").delete(id);
    tx.oncomplete = resolve;
    tx.onerror    = (e) => reject(e.target.error);
  });
}

function notifyClients(msg) {
  self.clients.matchAll({ includeUncontrolled: true }).then((list) => {
    list.forEach((c) => c.postMessage(msg));
  });
}

// ── Message: skip-waiting on demand ────────────────────────────────────────
self.addEventListener("message", (event) => {
  if (event.data === "skipWaiting") self.skipWaiting();
});

// ── Push notifications ──────────────────────────────────────────────────────
self.addEventListener("push", (event) => {
  let payload = {};
  try { payload = event.data ? JSON.parse(event.data.text()) : {}; } catch (_) {}

  const title = payload.title || "Cafe 11:11";
  const body  = payload.body  || "You have a new notification.";
  const data  = payload.data  || {};
  const type  = payload.type  || "general";

  const options = {
    body,
    icon:  "/static/img/icon-192.png",
    badge: "/static/img/icon-badge.png",
    data: { ...data, type, tableUrl: data.tableUrl || "/" },
    tag: type === "owner"
      ? "cafe-owner-" + (data.callId || data.orderId || "notify")
      : "cafe-table-" + (data.callId || "notify"),
    renotify: true,
    requireInteraction: type === "owner",
    vibrate: [200, 100, 200],
    actions: type === "owner"
      ? [{ action: "view", title: "View orders" }]
      : [{ action: "track", title: "Track order" }],
  };

  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const data      = event.notification.data || {};
  const type      = data.type || "general";
  const urlToOpen = type === "owner" ? "/owner/dashboard" : (data.tableUrl || "/");

  event.waitUntil(
    clients.matchAll({ type: "window", includeUncontrolled: true }).then((list) => {
      for (const c of list) {
        if (c.url.includes(urlToOpen) && "focus" in c) return c.focus();
      }
      if (clients.openWindow) return clients.openWindow(urlToOpen);
    })
  );
});
