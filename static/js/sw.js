/* ============================================================
   Cafe 11:11 — Service Worker
   Handles offline caching AND Web Push notifications.
   ============================================================ */

const CACHE_VERSION = "cafe-v2";
const STATIC_ASSETS = [
  "/static/css/styles.css",
  "/static/css/order.css",
  "/static/js/table.js",
  "https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;600;700&family=Inter:wght@300;400;500;600&display=swap",
];

// ─── Install: pre-cache static assets ─────────────────────────────────────
self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_VERSION).then((cache) =>
      cache.addAll(STATIC_ASSETS.map((url) => new Request(url, { mode: "no-cors" })))
    ).then(() => self.skipWaiting())
  );
});

// ─── Activate: delete old caches ──────────────────────────────────────────
self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_VERSION).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

// ─── Fetch: network-first for API calls, cache-first for static assets ────
self.addEventListener("fetch", (event) => {
  const { request } = event;
  const url = new URL(request.url);

  if (request.method !== "GET" || url.pathname.startsWith("/api/")) {
    return;
  }

  if (
    url.pathname.startsWith("/static/") ||
    url.hostname === "fonts.googleapis.com" ||
    url.hostname === "fonts.gstatic.com"
  ) {
    event.respondWith(
      caches.match(request).then((cached) => {
        if (cached) return cached;
        return fetch(request).then((res) => {
          if (res && res.status === 200) {
            const clone = res.clone();
            caches.open(CACHE_VERSION).then((cache) => cache.put(request, clone));
          }
          return res;
        });
      })
    );
    return;
  }

  if (request.headers.get("accept")?.includes("text/html")) {
    event.respondWith(
      fetch(request)
        .then((res) => {
          const clone = res.clone();
          caches.open(CACHE_VERSION).then((cache) => cache.put(request, clone));
          return res;
        })
        .catch(() => caches.match(request))
    );
  }
});

// ─── Push: display a notification ─────────────────────────────────────────
self.addEventListener("push", (event) => {
  let payload = {};
  try {
    payload = event.data ? JSON.parse(event.data.text()) : {};
  } catch (_) {}

  const title = payload.title || "Cafe 11:11";
  const body  = payload.body  || "You have a new notification.";
  const data  = payload.data  || {};
  const type  = payload.type  || "general";

  const icon  = "/static/img/icon-192.png";
  const badge = "/static/img/icon-badge.png";

  const options = {
    body,
    icon,
    badge,
    data: { ...data, type, tableUrl: data.tableUrl || "/" },
    // Collapse same-type notifications so the screen isn't spammed.
    tag: type === "owner"
      ? "cafe-owner-" + (data.callId || data.orderId || "notify")
      : "cafe-table-" + (data.callId || "notify"),
    renotify: true,
    requireInteraction: type === "owner",
    vibrate: [200, 100, 200],
  };

  event.waitUntil(self.registration.showNotification(title, options));
});

// ─── NotificationClick: focus or open the relevant page ───────────────────
self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const data = event.notification.data || {};
  const type = data.type || "general";
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
