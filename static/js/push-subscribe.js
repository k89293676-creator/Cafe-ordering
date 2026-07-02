/**
 * push-subscribe.js  — reusable Web Push subscription helper
 *
 * Call:
 *   cafePush.subscribeOwner()   — from the owner dashboard
 *   cafePush.subscribeTable(tableId, tableUrl)  — from the customer page
 *
 * Both functions silently no-op when:
 *   • the browser doesn't support Push / Service Workers
 *   • the user denies the Notifications permission
 *   • the server hasn't been configured with VAPID keys
 */
(function (global) {
  "use strict";

  /* Base-64url → Uint8Array (needed for applicationServerKey) */
  function urlBase64ToUint8Array(base64String) {
    var padding = "=".repeat((4 - (base64String.length % 4)) % 4);
    var base64  = (base64String + padding).replace(/-/g, "+").replace(/_/g, "/");
    var raw     = atob(base64);
    var out     = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
  }

  /* Fetch the server's VAPID public key. Returns null if unavailable. */
  async function getVapidKey() {
    try {
      var r = await fetch("/api/push/vapid-public-key", { cache: "no-store" });
      if (!r.ok) return null;
      var j = await r.json();
      return j.key || null;
    } catch (_) {
      return null;
    }
  }

  /* Register (or reuse) the service worker. Returns the registration. */
  async function getRegistration() {
    if (!("serviceWorker" in navigator)) return null;
    try {
      var reg = await navigator.serviceWorker.register("/static/js/sw.js", { scope: "/" });
      await navigator.serviceWorker.ready;
      return reg;
    } catch (_) {
      return null;
    }
  }

  /* Core subscribe logic — shared by both owner and table paths. */
  async function _subscribe(subscribeUrl, extraData) {
    if (!("PushManager" in window)) return;         /* browser too old */

    var permission = Notification.permission;
    if (permission === "denied") return;             /* user blocked it before */
    if (permission === "default") {
      permission = await Notification.requestPermission();
    }
    if (permission !== "granted") return;

    var vapidKey = await getVapidKey();
    if (!vapidKey) return;                           /* server not configured */

    var reg = await getRegistration();
    if (!reg || !reg.pushManager) return;

    /* Check whether we already have a matching subscription. */
    var existing = await reg.pushManager.getSubscription();

    /* Subscribe (or reuse existing). */
    var sub;
    try {
      sub = existing || await reg.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: urlBase64ToUint8Array(vapidKey),
      });
    } catch (_) {
      return;
    }

    /* Send the subscription object to our Flask backend. */
    var body = Object.assign(
      { endpoint: sub.endpoint, keys: { p256dh: btoa(String.fromCharCode(...new Uint8Array(sub.getKey("p256dh")))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, ""), auth: btoa(String.fromCharCode(...new Uint8Array(sub.getKey("auth")))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "") } },
      extraData || {}
    );
    try {
      await fetch(subscribeUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
    } catch (_) {}
  }

  global.cafePush = {
    /**
     * Subscribe the current browser session as the logged-in owner.
     * Call this on the owner dashboard after the page loads.
     */
    subscribeOwner: function () {
      _subscribe("/api/push/subscribe-owner", {});
    },

    /**
     * Subscribe the current browser session as a customer at a table.
     * @param {string} tableId  — the table identifier (from the QR URL)
     * @param {string} tableUrl — the current page URL, stored so tapping
     *                            the push notification reopens this page
     */
    subscribeTable: function (tableId, tableUrl) {
      _subscribe("/api/push/subscribe-table/" + encodeURIComponent(tableId), {
        tableUrl: tableUrl || window.location.pathname,
      });
    },
  };
})(window);
