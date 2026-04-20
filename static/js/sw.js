/* ============================================================
   Cafe 11:11 — Service Worker
   Caches the menu page shell for offline resilience.
   Menu data (API) is always fetched fresh; only static
   assets are cached.
   ============================================================ */

const CACHE_VERSION = "cafe-v1";
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

  // Always bypass for API, POST, or non-GET requests
  if (request.method !== "GET" || url.pathname.startsWith("/api/")) {
    return;
  }

  // Static assets: cache-first with network fallback
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

  // For HTML pages: network-first (fresh content), fall back to cache
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
