"use strict";

// ---------------------------------------------------------------------------
// Tab switching — driven by data-tab attributes, no inline onclick handlers
// ---------------------------------------------------------------------------

const TAB_META = {
  overview: { title: "Overview", subtitle: "Welcome back" },
  tables:   { title: "Tables", subtitle: "Manage table QR codes" },
  menu:     { title: "Menu Management", subtitle: "Add and edit your menu items" },
  orders:   { title: "Orders", subtitle: "Track and complete customer orders" },
};

function switchTab(tabId) {
  document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
  document.querySelectorAll("[data-tab]").forEach((el) => el.classList.remove("active"));

  const panel = document.getElementById("tab-" + tabId);
  if (panel) panel.classList.add("active");
  document.querySelectorAll(`[data-tab="${tabId}"]`).forEach((el) => el.classList.add("active"));

  const meta = TAB_META[tabId];
  if (meta) {
    const titleEl = document.getElementById("topbar-title");
    const subtitleEl = document.getElementById("topbar-subtitle");
    if (titleEl) titleEl.textContent = meta.title;
    if (subtitleEl) subtitleEl.textContent = meta.subtitle;
  }

  history.replaceState(null, "", "#" + tabId);
}

// ---------------------------------------------------------------------------
// Edit form toggle — driven by data-edit-target attributes
// ---------------------------------------------------------------------------

function toggleEdit(formId) {
  const form = document.getElementById(formId);
  if (form) form.classList.toggle("open");
}

// ---------------------------------------------------------------------------
// Confirmation dialogs — driven by data-confirm attributes
// ---------------------------------------------------------------------------

function handleConfirmClicks(e) {
  const btn = e.target.closest("[data-confirm]");
  if (!btn) return;
  const msg = btn.getAttribute("data-confirm");
  if (msg && !window.confirm(msg)) {
    e.preventDefault();
    e.stopPropagation();
  }
}

// ---------------------------------------------------------------------------
// Event delegation for tab buttons
// ---------------------------------------------------------------------------

function handleTabClick(e) {
  const btn = e.target.closest("[data-tab]");
  if (!btn) return;
  const tabId = btn.getAttribute("data-tab");
  if (tabId && document.getElementById("tab-" + tabId)) {
    switchTab(tabId);
  }
}

// ---------------------------------------------------------------------------
// Event delegation for edit toggles
// ---------------------------------------------------------------------------

function handleEditToggle(e) {
  const btn = e.target.closest("[data-edit-target]");
  if (!btn) return;
  const target = btn.getAttribute("data-edit-target");
  if (target) toggleEdit(target);
}

// ---------------------------------------------------------------------------
// Real-time order updates via Server-Sent Events (SSE)
// ---------------------------------------------------------------------------

let knownPendingCount = parseInt(
  document.querySelector(".link-badge")?.textContent || "0",
  10
);

let eventSource = null;
let reconnectAttempts = 0;
const MAX_RECONNECT_ATTEMPTS = 5;

function updateOrderBadges(pendingCount) {
  // Update sidebar badge
  const linkBadge = document.querySelector(".sidebar-link[data-tab='orders'] .link-badge");
  const tabCount = document.querySelector(".tab-btn[data-tab='orders'] .tab-count");

  if (pendingCount > 0) {
    if (linkBadge) {
      linkBadge.textContent = pendingCount;
    } else {
      const ordersLink = document.querySelector(".sidebar-link[data-tab='orders']");
      if (ordersLink) {
        const badge = document.createElement("span");
        badge.className = "link-badge";
        badge.textContent = pendingCount;
        ordersLink.appendChild(badge);
      }
    }
    if (tabCount) {
      tabCount.textContent = pendingCount;
    } else {
      const ordersTab = document.querySelector(".tab-btn[data-tab='orders']");
      if (ordersTab) {
        const span = document.createElement("span");
        span.className = "tab-count";
        span.textContent = pendingCount;
        ordersTab.appendChild(span);
      }
    }
  } else {
    linkBadge?.remove();
    tabCount?.remove();
  }

  // Also update the pending stat card
  const statCards = document.querySelectorAll(".stat-card");
  statCards.forEach((card) => {
    const label = card.querySelector(".stat-label");
    if (label && label.textContent.trim() === "Pending Orders") {
      const val = card.querySelector(".stat-value");
      if (val) val.textContent = pendingCount;
    }
  });
}

function showNewOrderBanner(newCount) {
  const existing = document.getElementById("new-order-banner");
  if (existing) existing.remove();

  const banner = document.createElement("div");
  banner.id = "new-order-banner";
  banner.className = "new-order-banner";
  banner.innerHTML = `
    <span>New order${newCount > 1 ? "s" : ""} received!</span>
    <div style="display:flex;gap:0.5rem;align-items:center;">
      <button class="btn btn-primary btn-sm" id="refresh-orders-btn">Refresh Dashboard</button>
      <button class="btn btn-ghost btn-sm" id="dismiss-banner-btn" style="color:inherit;">X</button>
    </div>
  `;

  const content = document.querySelector(".dashboard-content");
  if (content) content.prepend(banner);

  document.getElementById("refresh-orders-btn")?.addEventListener("click", () => {
    window.location.reload();
  });
  document.getElementById("dismiss-banner-btn")?.addEventListener("click", () => {
    banner.remove();
  });

  // Auto-dismiss after 30 seconds
  setTimeout(() => banner.remove(), 30000);
}

function playNotificationSound() {
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.frequency.value = 880;
    gain.gain.setValueAtTime(0.1, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.3);
    osc.start(ctx.currentTime);
    osc.stop(ctx.currentTime + 0.3);
  } catch (_) {}
}

function connectSSE() {
  if (eventSource) {
    eventSource.close();
  }
  
  eventSource = new EventSource("/api/events/orders");
  
  eventSource.addEventListener("connected", (e) => {
    reconnectAttempts = 0;
    console.log("[v0] SSE connected for order updates");
  });
  
  eventSource.addEventListener("order_update", (e) => {
    try {
      const data = JSON.parse(e.data);
      const newPendingCount = data.pendingCount || 0;
      
      if (newPendingCount > knownPendingCount) {
        const diff = newPendingCount - knownPendingCount;
        showNewOrderBanner(diff);
        playNotificationSound();
      }
      
      knownPendingCount = newPendingCount;
      updateOrderBadges(newPendingCount);
    } catch (_) {}
  });
  
  eventSource.addEventListener("heartbeat", () => {
    // Connection is alive, nothing to do
  });
  
  eventSource.onerror = () => {
    eventSource.close();
    eventSource = null;
    
    // Attempt to reconnect with exponential backoff
    if (reconnectAttempts < MAX_RECONNECT_ATTEMPTS) {
      reconnectAttempts++;
      const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), 30000);
      console.log(`[v0] SSE disconnected, reconnecting in ${delay}ms...`);
      setTimeout(connectSSE, delay);
    } else {
      console.log("[v0] SSE max reconnect attempts reached, falling back to polling");
      // Fallback to polling if SSE keeps failing
      setInterval(pollOrdersFallback, 20000);
    }
  };
}

async function pollOrdersFallback() {
  try {
    const res = await fetch("/api/orders?v=" + Date.now(), { cache: "no-store" });
    if (!res.ok) return;
    const data = await res.json();
    const orders = data.orders || [];
    const pendingOrders = orders.filter((o) => o.status !== "completed");
    const pendingCount = pendingOrders.length;

    if (pendingCount > knownPendingCount) {
      const newCount = pendingCount - knownPendingCount;
      showNewOrderBanner(newCount);
      playNotificationSound();
    }

    knownPendingCount = pendingCount;
    updateOrderBadges(pendingCount);
  } catch (_) {}
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

document.addEventListener("DOMContentLoaded", () => {
  document.addEventListener("click", handleTabClick);
  document.addEventListener("click", handleEditToggle);
  document.addEventListener("click", handleConfirmClicks);

  // Restore tab from URL hash
  const hash = window.location.hash.replace("#", "");
  if (hash && TAB_META[hash]) {
    switchTab(hash);
  }

  // Start real-time updates via SSE (with polling fallback)
  if (typeof EventSource !== "undefined") {
    connectSSE();
  } else {
    // Fallback for browsers without SSE support
    setInterval(pollOrdersFallback, 20000);
  }
});

// Clean up SSE connection when leaving page
window.addEventListener("beforeunload", () => {
  if (eventSource) {
    eventSource.close();
  }
});
