"use strict";

// ---------------------------------------------------------------------------
// DOM references
// ---------------------------------------------------------------------------
const menuContainer   = document.getElementById("menu-container");
const cartItemsEl     = document.getElementById("cart-items");
const totalDisplay    = document.getElementById("order-total");
const itemCountDisplay= document.getElementById("item-count");
const cartBadge       = document.getElementById("cart-badge");
const checkoutForm    = document.getElementById("checkout-form");
const responseBox     = document.getElementById("checkout-response");
const tableIdInput    = document.getElementById("table-id");
const clearCartButton = document.getElementById("clear-cart");
const searchInput     = document.getElementById("menu-search");
const catNav          = document.getElementById("cat-nav");
const cartPanel       = document.getElementById("cart-panel");
const cartFab         = document.getElementById("cart-fab");
const cartFabBadge    = document.getElementById("cart-fab-badge");
const cartFabTotal    = document.getElementById("cart-fab-total");
const cartToggleBtn   = document.getElementById("cart-toggle-btn");
const cartCloseBtn    = document.getElementById("cart-close-btn");

let menuData = [];
let cart = [];
let orderStatusInterval = null;

function fmt(amount) { return amount.toFixed(2); }

// ---------------------------------------------------------------------------
// Cart panel toggle (mobile)
// ---------------------------------------------------------------------------
function openCart() {
  cartPanel?.classList.add("cart-panel--open");
  document.body.classList.add("cart-open");
}
function closeCart() {
  cartPanel?.classList.remove("cart-panel--open");
  document.body.classList.remove("cart-open");
}

cartToggleBtn?.addEventListener("click", openCart);
cartCloseBtn?.addEventListener("click", closeCart);

// Tap backdrop to close on mobile
document.addEventListener("click", (e) => {
  if (document.body.classList.contains("cart-open")) {
    if (!cartPanel?.contains(e.target) && e.target !== cartToggleBtn && !cartToggleBtn?.contains(e.target)) {
      closeCart();
    }
  }
});

cartFab?.addEventListener("click", openCart);

// ---------------------------------------------------------------------------
// Category navigation
// ---------------------------------------------------------------------------
function buildCategoryNav(categories) {
  if (!catNav || !categories.length) return;

  catNav.innerHTML = categories.map((cat) =>
    `<button class="cat-pill" data-cat="${cat.id}">${cat.name}</button>`
  ).join("");

  catNav.querySelectorAll(".cat-pill").forEach((btn) => {
    btn.addEventListener("click", () => {
      const id = btn.dataset.cat;
      const target = document.getElementById("cat-section-" + id);
      if (target) {
        const offset = document.getElementById("order-nav-wrap")?.offsetHeight || 0;
        const top = target.getBoundingClientRect().top + window.scrollY - offset - 8;
        window.scrollTo({ top, behavior: "smooth" });
      }
      setActivePill(id);
    });
  });

  setupScrollSpy(categories);
}

function setActivePill(catId) {
  catNav?.querySelectorAll(".cat-pill").forEach((btn) => {
    btn.classList.toggle("cat-pill--active", btn.dataset.cat === catId);
  });
}

function setupScrollSpy(categories) {
  const navHeight = document.getElementById("order-nav-wrap")?.offsetHeight || 80;
  const observer = new IntersectionObserver(
    (entries) => {
      const visible = entries.filter((e) => e.isIntersecting);
      if (visible.length) {
        const top = visible.reduce((a, b) =>
          a.boundingClientRect.top < b.boundingClientRect.top ? a : b
        );
        const id = top.target.id.replace("cat-section-", "");
        setActivePill(id);
        scrollPillIntoView(id);
      }
    },
    { rootMargin: `-${navHeight + 4}px 0px -60% 0px`, threshold: 0 }
  );

  categories.forEach((cat) => {
    const el = document.getElementById("cat-section-" + cat.id);
    if (el) observer.observe(el);
  });
}

function scrollPillIntoView(catId) {
  const pill = catNav?.querySelector(`[data-cat="${catId}"]`);
  if (pill && catNav) {
    pill.scrollIntoView({ block: "nearest", inline: "center", behavior: "smooth" });
  }
}

// ---------------------------------------------------------------------------
// Menu rendering
// ---------------------------------------------------------------------------
function cartQtyForItem(itemId) {
  return cart.find((e) => e.id === itemId)?.quantity || 0;
}

function renderMenu() {
  const query = searchInput?.value.trim().toLowerCase() || "";
  if (!menuData.length) {
    menuContainer.innerHTML = '<div class="menu-no-items"><span>🍽️</span><p>No menu items available yet.</p></div>';
    return;
  }

  const filtered = menuData
    .map((cat) => ({
      ...cat,
      items: cat.items.filter((item) => {
        if (!query) return true;
        const text = `${item.name} ${item.description || ""} ${(item.tags || []).join(" ")}`.toLowerCase();
        return text.includes(query) || cat.name.toLowerCase().includes(query);
      }),
    }))
    .filter((cat) => cat.items.length > 0);

  if (!filtered.length) {
    menuContainer.innerHTML = '<div class="menu-no-items"><span>🔍</span><p>No items match your search.</p></div>';
    catNav && (catNav.style.display = "none");
    return;
  }

  catNav && (catNav.style.display = "");

  menuContainer.innerHTML = filtered.map((cat) => `
    <section class="menu-category" id="cat-section-${cat.id}">
      <div class="menu-category-title">${cat.name}
        <span class="cat-item-count">${cat.items.length}</span>
      </div>
      <div class="menu-items">
        ${cat.items.map((item) => {
          const inCart = cartQtyForItem(item.id);
          const tagsHtml = item.tags && item.tags.length
            ? `<div class="item-tags">${item.tags.map((t) => `<span class="item-tag">${t}</span>`).join("")}</div>`
            : "";
          return `
            <div class="menu-item" data-item-id="${item.id}">
              <div class="menu-item-body">
                <div class="menu-item-info">
                  <h4>${item.name}</h4>
                  ${item.description ? `<p class="item-desc">${item.description}</p>` : ""}
                  ${tagsHtml}
                </div>
                <div class="menu-item-price-row">
                  <span class="item-price">₹${fmt(item.price)}</span>
                </div>
              </div>
              <div class="menu-item-action">
                ${inCart > 0
                  ? `<div class="item-qty-stepper">
                       <button class="qty-step-btn" data-action="decrease" data-id="${item.id}">−</button>
                       <span class="qty-step-val">${inCart}</span>
                       <button class="qty-step-btn qty-step-btn--add" data-action="increase" data-id="${item.id}">+</button>
                     </div>`
                  : `<button class="add-btn" data-id="${item.id}">+ Add</button>`
                }
              </div>
            </div>
          `;
        }).join("")}
      </div>
    </section>
  `).join("");

  // Bind add buttons
  menuContainer.querySelectorAll(".add-btn").forEach((btn) => {
    btn.addEventListener("click", () => addToCart(btn.dataset.id));
  });

  // Bind stepper buttons
  menuContainer.querySelectorAll(".qty-step-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const id = btn.dataset.id;
      const action = btn.dataset.action;
      if (action === "increase") { addToCart(id); }
      else { decreaseItem(id); }
    });
  });
}

// ---------------------------------------------------------------------------
// Cart management
// ---------------------------------------------------------------------------
function renderCart() {
  const totalItems = cart.reduce((s, e) => s + e.quantity, 0);
  const total = cart.reduce((s, e) => s + e.lineTotal, 0);

  if (cartBadge) cartBadge.textContent = totalItems;
  if (itemCountDisplay) itemCountDisplay.textContent = totalItems;
  if (totalDisplay) totalDisplay.textContent = fmt(total);

  // FAB
  if (cartFabBadge) cartFabBadge.textContent = totalItems;
  if (cartFabTotal) cartFabTotal.textContent = fmt(total);
  if (cartFab) cartFab.classList.toggle("cart-fab--visible", totalItems > 0);

  // Cart toggle badge
  if (cartToggleBtn) {
    const badge = cartToggleBtn.querySelector(".cart-toggle-badge");
    if (badge) badge.textContent = totalItems;
    cartToggleBtn.classList.toggle("has-items", totalItems > 0);
  }

  if (!cart.length) {
    cartItemsEl.innerHTML = `
      <div class="cart-empty-state">
        <div class="cart-empty-icon">🛒</div>
        <p>Your cart is empty</p>
        <span>Browse the menu and add items</span>
      </div>
    `;
    return;
  }

  cartItemsEl.innerHTML = cart.map((entry) => `
    <div class="cart-item">
      <div class="cart-item-info">
        <div class="cart-item-name">${entry.name}</div>
        <div class="cart-item-unit">₹${fmt(entry.price)} each</div>
      </div>
      <div class="cart-item-right">
        <div class="cart-item-controls">
          <button class="qty-btn" data-action="decrease" data-id="${entry.id}">−</button>
          <span class="qty-value">${entry.quantity}</span>
          <button class="qty-btn" data-action="increase" data-id="${entry.id}">+</button>
        </div>
        <span class="cart-item-total">₹${fmt(entry.lineTotal)}</span>
        <button class="remove-btn" data-action="remove" data-id="${entry.id}" title="Remove">✕</button>
      </div>
    </div>
  `).join("");

  cartItemsEl.querySelectorAll("[data-action]").forEach((el) => {
    el.addEventListener("click", () => {
      const id = el.dataset.id;
      const action = el.dataset.action;
      if (action === "increase") addToCart(id);
      else if (action === "decrease") changeQty(id, -1);
      else if (action === "remove") removeItem(id);
    });
  });
}

function addToCart(itemId) {
  const item = menuData.flatMap((c) => c.items).find((i) => i.id === itemId);
  if (!item) return;
  const existing = cart.find((e) => e.id === itemId);
  if (existing) {
    existing.quantity += 1;
    existing.lineTotal = existing.quantity * existing.price;
  } else {
    cart.push({ id: item.id, name: item.name, price: item.price, quantity: 1, lineTotal: item.price });
  }
  renderCart();
  renderMenu(); // re-render to update steppers
}

function decreaseItem(itemId) {
  const entry = cart.find((e) => e.id === itemId);
  if (!entry) return;
  if (entry.quantity <= 1) removeItem(itemId);
  else changeQty(itemId, -1);
  renderMenu();
}

function changeQty(itemId, delta) {
  const entry = cart.find((e) => e.id === itemId);
  if (!entry) return;
  entry.quantity = Math.max(1, entry.quantity + delta);
  entry.lineTotal = entry.quantity * entry.price;
  renderCart();
}

function removeItem(itemId) {
  cart = cart.filter((e) => e.id !== itemId);
  renderCart();
  renderMenu();
}

function clearCart() {
  cart = [];
  renderCart();
  renderMenu();
}

// ---------------------------------------------------------------------------
// Menu loading
// ---------------------------------------------------------------------------
async function loadMenu() {
  try {
    const tableId = tableIdInput?.value || "";
    const params = new URLSearchParams({ table_id: tableId, v: Date.now() }).toString();
    const res = await fetch("/api/menu?" + params, {
      cache: "no-store",
      headers: { "Cache-Control": "no-cache" },
    });
    if (!res.ok) throw new Error("Failed to load menu.");
    const data = await res.json();
    menuData = data.categories || [];
    buildCategoryNav(menuData);
    renderMenu();
    // Activate first pill
    if (menuData.length) setActivePill(menuData[0].id);
  } catch (err) {
    menuContainer.innerHTML = `<div class="menu-no-items"><span>⚠️</span><p>${err.message}</p></div>`;
  }
}

// ---------------------------------------------------------------------------
// Order status tracker
// ---------------------------------------------------------------------------
function getStatusInfo(status) {
  switch (status) {
    case "pending":   return { icon: "⏳", label: "Order received",    desc: "Waiting to be prepared",           cls: "status-pending" };
    case "preparing": return { icon: "👨‍🍳", label: "Being prepared",    desc: "Your order is being prepared",       cls: "status-preparing" };
    case "ready":     return { icon: "🔔", label: "Ready for pickup!",  desc: "Your order is ready — come collect!", cls: "status-ready" };
    case "completed": return { icon: "✅", label: "Completed",          desc: "Thank you! Enjoy your order.",       cls: "status-completed" };
    default:          return { icon: "📋", label: status,               desc: "",                                   cls: "" };
  }
}

function buildStatusHTML(order) {
  const s = getStatusInfo(order.status);
  const steps = ["pending", "preparing", "ready", "completed"];
  const currentStep = steps.indexOf(order.status);

  const stepsHTML = steps.map((step, i) => {
    const info = getStatusInfo(step);
    const done   = i < currentStep;
    const active = i === currentStep;
    return `<div class="status-step ${done ? "done" : ""} ${active ? "active" : ""}">
      <div class="status-step-dot">${done ? "✓" : info.icon}</div>
      <div class="status-step-label">${info.label}</div>
    </div>`;
  }).join('<div class="status-step-line"></div>');

  const itemsList = order.items.map((i) =>
    `<div class="order-line"><span>${i.name} × ${i.quantity}</span><span>₹${i.lineTotal.toFixed(2)}</span></div>`
  ).join("");

  const isFinished = order.status === "completed";

  return `
    <div class="order-status-tracker">
      <div class="order-status-top">
        <div class="order-status-id">Order #${order.id}</div>
        <div class="order-status-customer">Hi, ${order.customerName || "there"}!</div>
      </div>
      <div class="order-status-steps">${stepsHTML}</div>
      <div class="order-status-current ${s.cls}">
        <span class="order-status-current-icon">${s.icon}</span>
        <div>
          <div class="order-status-current-label">${s.label}</div>
          <div class="order-status-current-desc">${s.desc}</div>
        </div>
      </div>
      <div class="order-items-summary">
        ${itemsList}
        <div style="display:flex;justify-content:space-between;align-items:center;margin-top:0.5rem;padding-top:0.5rem;border-top:1px solid var(--border);font-weight:700;">
          <span>Total</span>
          <span>₹${order.total.toFixed(2)}</span>
        </div>
      </div>
      ${isFinished
        ? `<button class="btn btn-primary btn-full" style="margin-top:1rem;" id="new-order-btn">Place Another Order</button>`
        : `<p class="order-status-hint">Auto-refreshing every 10 s…</p>`
      }
    </div>
  `;
}

function showOrderTracker(order) {
  if (orderStatusInterval) clearInterval(orderStatusInterval);

  const cartFooter = document.getElementById("cart-footer");
  const cartItemsWrap = document.getElementById("cart-items-wrap");
  if (cartFooter) cartFooter.style.display = "none";
  if (cartItemsWrap) cartItemsWrap.innerHTML = buildStatusHTML(order);

  const newOrderBtn = document.getElementById("new-order-btn");
  if (newOrderBtn) newOrderBtn.addEventListener("click", resetCart);

  if (order.status !== "completed") {
    orderStatusInterval = setInterval(async () => {
      try {
        const res = await fetch(`/api/order/${order.id}`);
        if (!res.ok) return;
        const data = await res.json();
        if (cartItemsWrap) cartItemsWrap.innerHTML = buildStatusHTML(data.order);
        const btn = document.getElementById("new-order-btn");
        if (btn) btn.addEventListener("click", resetCart);
        if (data.order.status === "completed") {
          clearInterval(orderStatusInterval);
          orderStatusInterval = null;
        }
      } catch (_) {}
    }, 10000);
  }
}

function resetCart() {
  if (orderStatusInterval) { clearInterval(orderStatusInterval); orderStatusInterval = null; }
  cart = [];
  window.location.reload();
}

// ---------------------------------------------------------------------------
// Checkout
// ---------------------------------------------------------------------------
checkoutForm?.addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!cart.length) {
    showResponse("Please add items to your order first.", "error");
    return;
  }

  const customerName = document.getElementById("customer-name").value.trim() || "Guest";
  const tableId = tableIdInput.value;
  const payload = {
    customerName,
    tableId,
    items: cart.map((entry) => ({ id: entry.id, quantity: entry.quantity })),
  };

  const submitBtn = document.getElementById("checkout-btn");
  if (submitBtn) { submitBtn.disabled = true; submitBtn.textContent = "Placing order…"; }

  try {
    const res = await fetch("/api/checkout", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const json = await res.json();
    if (!res.ok) {
      showResponse(json.description || "Failed to place order.", "error");
      if (submitBtn) { submitBtn.disabled = false; submitBtn.textContent = "Place Order →"; }
    } else {
      openCart();
      showOrderTracker(json.order);
    }
  } catch (err) {
    showResponse("Network error. Please try again.", "error");
    if (submitBtn) { submitBtn.disabled = false; submitBtn.textContent = "Place Order →"; }
  }
});

function showResponse(msg, type) {
  if (!responseBox) return;
  responseBox.textContent = msg;
  responseBox.className = "checkout-response visible " + (type === "error" ? "alert alert-error" : "alert alert-success");
}

clearCartButton?.addEventListener("click", clearCart);
searchInput?.addEventListener("input", renderMenu);

loadMenu();
