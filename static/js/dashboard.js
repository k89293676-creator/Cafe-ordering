"use strict";

// ---------------------------------------------------------------------------
// Tab switching
// ---------------------------------------------------------------------------

const TAB_TITLES = {
  overview: { title: "Overview", sub: "Your cafe at a glance" },
  tables:   { title: "Tables",   sub: "Manage your table QR codes" },
  menu:     { title: "Menu",     sub: "Build and manage your menu" },
  orders:   { title: "Orders",   sub: "Live order management" },
  feedback: { title: "Reviews",  sub: "Guest feedback and ratings" },
  "table-calls": { title: "Table Calls", sub: "Live customer requests from the floor" },
};

function switchTab(tabId) {
  // Panels
  document.querySelectorAll(".tab-panel").forEach(panel => {
    panel.classList.toggle("active", panel.id === `tab-${tabId}`);
  });

  // Tab bar buttons
  document.querySelectorAll(".tab-btn[data-tab]").forEach(btn => {
    btn.classList.toggle("active", btn.dataset.tab === tabId);
  });

  // Sidebar links
  document.querySelectorAll(".sidebar-link[data-tab]").forEach(btn => {
    btn.classList.toggle("active", btn.dataset.tab === tabId);
  });

  // Topbar title
  const info = TAB_TITLES[tabId] || {};
  const topbarTitle = document.getElementById("topbar-title");
  const topbarSub = document.getElementById("topbar-subtitle");
  if (topbarTitle && info.title) topbarTitle.textContent = info.title;
  if (topbarSub && info.sub) topbarSub.textContent = info.sub;

  // Update URL hash
  history.replaceState(null, "", `#${tabId}`);
}

// Wire up all tab buttons (sidebar + tab bar)
document.querySelectorAll("[data-tab]").forEach(btn => {
  btn.addEventListener("click", () => switchTab(btn.dataset.tab));
});

// Activate tab from hash on load
function activateTabFromHash() {
  const hash = location.hash.replace("#", "");
  if (hash && document.getElementById(`tab-${hash}`)) {
    switchTab(hash);
  } else {
    switchTab("overview");
  }
}

// ---------------------------------------------------------------------------
// Confirm dialogs for destructive actions
// ---------------------------------------------------------------------------
document.querySelectorAll("[data-confirm]").forEach(btn => {
  btn.addEventListener("click", (e) => {
    if (!confirm(btn.dataset.confirm || "Are you sure?")) {
      e.preventDefault();
      e.stopImmediatePropagation();
    }
  });
});

// ---------------------------------------------------------------------------
// Upload tab switching
// ---------------------------------------------------------------------------
document.querySelectorAll(".upload-tab-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    const target = btn.dataset.uploadTab;
    document.querySelectorAll(".upload-tab-btn").forEach(b => b.classList.toggle("active", b.dataset.uploadTab === target));
    document.getElementById("upload-tab-image")?.style.setProperty("display", target === "image" ? "block" : "none");
    document.getElementById("upload-tab-json")?.style.setProperty("display", target === "json" ? "block" : "none");
  });
});

// ---------------------------------------------------------------------------
// File drop zone
// ---------------------------------------------------------------------------
const dropZone = document.getElementById("file-drop-zone");
const fileInput = document.getElementById("menu-file-input");
const fileSelectedName = document.getElementById("file-selected-name");

if (dropZone && fileInput) {
  dropZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropZone.style.borderColor = "var(--primary)";
    dropZone.style.background = "var(--primary-light)";
  });

  dropZone.addEventListener("dragleave", () => {
    dropZone.style.borderColor = "";
    dropZone.style.background = "";
  });

  dropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropZone.style.borderColor = "";
    dropZone.style.background = "";
    if (e.dataTransfer.files.length) {
      fileInput.files = e.dataTransfer.files;
      showFileName(e.dataTransfer.files[0].name);
    }
  });

  fileInput.addEventListener("change", () => {
    if (fileInput.files.length) showFileName(fileInput.files[0].name);
  });

  function showFileName(name) {
    if (fileSelectedName) {
      fileSelectedName.textContent = name;
      fileSelectedName.style.display = "block";
    }
  }
}

// ---------------------------------------------------------------------------
// Menu item edit toggle
// ---------------------------------------------------------------------------
document.querySelectorAll("[data-edit-target]").forEach(btn => {
  btn.addEventListener("click", () => {
    const form = document.getElementById(btn.dataset.editTarget);
    if (!form) return;
    const visible = form.style.display === "grid";
    form.style.display = visible ? "none" : "grid";
  });
});

// ---------------------------------------------------------------------------
// SSE — Server-Sent Events for real-time order updates
// ---------------------------------------------------------------------------

let sseReconnectDelay = 2000;
let sseReconnectCount = 0;
const SSE_MAX_RECONNECTS = 10;
let sseConnected = false;
let sseSource = null;

function connectSSE() {
  if (sseSource) sseSource.close();

  try {
    sseSource = new EventSource("/api/orders/stream");
  } catch {
    return;
  }

  sseSource.onopen = () => {
    sseConnected = true;
    sseReconnectDelay = 2000;
    sseReconnectCount = 0;
    updateSSEIndicator(true);
  };

  sseSource.onmessage = (event) => {
    try {
      const payload = JSON.parse(event.data);
      handleSSEEvent(payload);
    } catch {}
  };

  sseSource.onerror = () => {
    sseConnected = false;
    updateSSEIndicator(false);
    sseSource.close();
    sseReconnectCount++;
    if (sseReconnectCount >= SSE_MAX_RECONNECTS) {
      console.error("[SSE] Max reconnection attempts reached. Live order updates disabled — reload the page to retry.");
      return;
    }
    // Exponential backoff reconnect (capped at 30 s)
    setTimeout(() => {
      sseReconnectDelay = Math.min(sseReconnectDelay * 2, 30000);
      connectSSE();
    }, sseReconnectDelay);
  };
}

let pendingReload = null;

function scheduleRefresh(delayMs) {
  if (pendingReload) return; // already scheduled
  pendingReload = setTimeout(() => {
    pendingReload = null;
    location.reload();
  }, delayMs || 4000);
}

function handleSSEEvent(payload) {
  if (!payload || !payload.type) return;
  if (payload.type === "new_order") {
    showNewOrderBanner(payload.data);
    scheduleRefresh(4000);
  } else if (payload.type === "order_updated") {
    // Update the status badge in-place if the order row exists in the DOM
    const data = payload.data || {};
    const updated = updateOrderRowInPlace(data.id, data.status);
    if (!updated) {
      // Row not in current view — schedule a quiet refresh
      scheduleRefresh(2000);
    }
  }
}

function updateOrderRowInPlace(orderId, newStatus) {
  if (!orderId || !newStatus) return false;
  const STATUS_LABELS = {
    pending: "Pending",
    preparing: "Preparing",
    ready: "Ready",
    completed: "Completed",
    cancelled: "Cancelled",
  };
  const STATUS_CLASSES = {
    pending: "badge-pending",
    preparing: "badge-preparing",
    ready: "badge-ready",
    completed: "badge-done",
    cancelled: "badge-cancelled",
  };
  // Find order row by data attribute or by ID pattern
  const row = document.querySelector(`[data-order-id="${orderId}"]`);
  if (!row) return false;
  const badge = row.querySelector(".status-badge, [class*='badge-']");
  if (badge) {
    badge.textContent = STATUS_LABELS[newStatus] || newStatus;
    badge.className = badge.className.replace(/badge-\w+/, "");
    badge.classList.add(STATUS_CLASSES[newStatus] || "badge-pending");
  }
  return true;
}

function showNewOrderBanner(data) {
  const banner = document.getElementById("new-order-banner");
  if (!banner) return;
  banner.style.cssText = "display:block;position:fixed;top:0;left:0;right:0;z-index:9999;background:var(--primary);color:white;text-align:center;padding:0.875rem 1rem;font-weight:600;font-size:0.9375rem;box-shadow:0 4px 12px rgba(0,0,0,0.15);animation:slide-down 0.3s ease;cursor:pointer;";
  banner.innerHTML = `&#128276; New order from ${escDash(data?.tableName || "a table")} — tap to refresh`;
  banner.onclick = () => location.reload();
  setTimeout(() => { banner.style.display = "none"; }, 6000);
}

function updateSSEIndicator(connected) {
  // Update the live badge if present
  const liveBadge = document.querySelector(".live-badge");
  if (liveBadge) liveBadge.style.opacity = connected ? "1" : "0.4";
}

function escDash(str) {
  return String(str || "").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// ---------------------------------------------------------------------------
// Auto-refresh fallback (every 60s) if SSE is not connected
// ---------------------------------------------------------------------------
setInterval(() => {
  if (!sseConnected) location.reload();
}, 60000);

// ---------------------------------------------------------------------------
// select element styling (for the menu item category selector)
// ---------------------------------------------------------------------------
document.querySelectorAll("select").forEach(sel => {
  sel.style.cssText = "width:100%;padding:0.75rem 1rem;border:1.5px solid var(--border);border-radius:var(--radius);font-family:inherit;font-size:0.9375rem;outline:none;cursor:pointer;background:var(--surface);color:var(--text-primary);";
});

// ---------------------------------------------------------------------------
// textarea styling
// ---------------------------------------------------------------------------
document.querySelectorAll("textarea").forEach(ta => {
  ta.style.cssText = "width:100%;padding:0.75rem 1rem;border:1.5px solid var(--border);border-radius:var(--radius);font-family:inherit;font-size:0.875rem;outline:none;resize:vertical;color:var(--text-primary);background:var(--surface);box-sizing:border-box;";
});

// ---------------------------------------------------------------------------
// Mobile sidebar toggle (hamburger)
// ---------------------------------------------------------------------------
const _sidebarToggle  = document.getElementById("sidebar-toggle");
const _sidebarEl      = document.querySelector(".sidebar");
const _sidebarOverlay = document.getElementById("sidebar-overlay");

function _openSidebar() {
  _sidebarEl?.classList.add("sidebar--open");
  _sidebarOverlay?.classList.add("sidebar-overlay--visible");
  document.body.style.overflow = "hidden";
}

function _closeSidebar() {
  _sidebarEl?.classList.remove("sidebar--open");
  _sidebarOverlay?.classList.remove("sidebar-overlay--visible");
  document.body.style.overflow = "";
}

_sidebarToggle?.addEventListener("click", _openSidebar);
_sidebarOverlay?.addEventListener("click", _closeSidebar);

// Close sidebar when any sidebar link is clicked on mobile
document.querySelectorAll(".sidebar-link[data-tab], .sidebar-link[href]").forEach(btn => {
  btn.addEventListener("click", () => {
    if (window.innerWidth <= 900) _closeSidebar();
  });
});

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------
document.addEventListener("DOMContentLoaded", () => {
  activateTabFromHash();
  connectSSE();
});

// Add slide-down animation
const style = document.createElement("style");
style.textContent = `@keyframes slide-down{from{transform:translateY(-100%)}to{transform:translateY(0)}}`;
document.head.appendChild(style);
