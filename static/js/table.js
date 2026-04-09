const menuContainer = document.getElementById("menu-container");
const cartItemsEl = document.getElementById("cart-items");
const totalDisplay = document.getElementById("order-total");
const itemCountDisplay = document.getElementById("item-count");
const cartBadge = document.getElementById("cart-badge");
const checkoutForm = document.getElementById("checkout-form");
const responseBox = document.getElementById("checkout-response");
const tableIdInput = document.getElementById("table-id");
const clearCartButton = document.getElementById("clear-cart");
const searchInput = document.getElementById("menu-search");
const cartSection = document.querySelector(".cart-section");

let menuData = [];
let cart = [];
let orderStatusInterval = null;

function fmt(amount) {
  return amount.toFixed(2);
}

// ---------------------------------------------------------------------------
// Menu rendering
// ---------------------------------------------------------------------------

function renderMenu() {
  const query = searchInput?.value.trim().toLowerCase() || "";
  if (!menuData.length) {
    menuContainer.innerHTML = '<p style="color:var(--text-muted);text-align:center;padding:2rem;">No menu items available yet.</p>';
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
    menuContainer.innerHTML = '<p style="color:var(--text-muted);text-align:center;padding:2rem;">No items match your search.</p>';
    return;
  }

  menuContainer.innerHTML = filtered
    .map((cat) => `
      <div class="menu-category">
        <div class="menu-category-title">${cat.name}</div>
        <div class="menu-items">
          ${cat.items.map((item) => `
            <div class="menu-item">
              <div class="menu-item-info">
                <h4>${item.name}</h4>
                ${item.description ? `<p class="item-desc">${item.description}</p>` : ""}
                ${item.tags && item.tags.length ? `<div class="item-tags">${item.tags.map((t) => `<span class="item-tag">${t}</span>`).join("")}</div>` : ""}
              </div>
              <div class="menu-item-right">
                <span class="item-price">$${fmt(item.price)}</span>
                <button class="add-btn" data-id="${item.id}">+ Add</button>
              </div>
            </div>
          `).join("")}
        </div>
      </div>
    `).join("");

  menuContainer.querySelectorAll(".add-btn").forEach((btn) => {
    btn.addEventListener("click", () => addToCart(btn.dataset.id));
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

  if (!cart.length) {
    cartItemsEl.innerHTML = '<p style="color:var(--text-muted);font-size:0.875rem;text-align:center;padding:1rem 0;">Your cart is empty</p>';
    return;
  }

  cartItemsEl.innerHTML = cart.map((entry) => `
    <div class="cart-item">
      <div class="cart-item-name">${entry.name}</div>
      <div class="cart-item-controls">
        <button class="qty-btn" data-action="decrease" data-id="${entry.id}">−</button>
        <span class="qty-value">${entry.quantity}</span>
        <button class="qty-btn" data-action="increase" data-id="${entry.id}">+</button>
      </div>
      <span class="cart-item-total">$${fmt(entry.lineTotal)}</span>
      <button class="remove-btn" data-action="remove" data-id="${entry.id}" title="Remove">✕</button>
    </div>
  `).join("");

  cartItemsEl.querySelectorAll("[data-action]").forEach((el) => {
    el.addEventListener("click", () => {
      const id = el.dataset.id;
      const action = el.dataset.action;
      if (action === "increase") changeQty(id, 1);
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
}

function clearCart() {
  cart = [];
  renderCart();
}

// ---------------------------------------------------------------------------
// Menu loading
// ---------------------------------------------------------------------------

async function loadMenu() {
  try {
    const res = await fetch("/api/menu?v=" + Date.now(), {
      cache: "no-store",
      headers: { "Cache-Control": "no-cache" },
    });
    if (!res.ok) throw new Error("Failed to load menu.");
    const data = await res.json();
    menuData = data.categories || [];
    renderMenu();
  } catch (err) {
    menuContainer.innerHTML = `<p style="color:var(--danger);text-align:center;padding:2rem;">${err.message}</p>`;
  }
}

// ---------------------------------------------------------------------------
// Order status tracker — replaces cart panel after successful checkout
// ---------------------------------------------------------------------------

function getStatusInfo(status) {
  switch (status) {
    case "pending":   return { icon: "⏳", label: "Order received", desc: "Waiting to be prepared", cls: "status-pending" };
    case "preparing": return { icon: "👨‍🍳", label: "Being prepared", desc: "Your order is being cooked", cls: "status-preparing" };
    case "ready":     return { icon: "🔔", label: "Ready for pickup!", desc: "Your order is ready. Please collect it.", cls: "status-ready" };
    case "completed": return { icon: "✅", label: "Completed", desc: "Thank you! Enjoy your order.", cls: "status-completed" };
    default:          return { icon: "📋", label: status, desc: "", cls: "" };
  }
}

function buildStatusHTML(order) {
  const s = getStatusInfo(order.status);
  const steps = ["pending", "preparing", "ready", "completed"];
  const currentStep = steps.indexOf(order.status);

  const stepsHTML = steps.map((step, i) => {
    const info = getStatusInfo(step);
    const done = i < currentStep;
    const active = i === currentStep;
    return `<div class="status-step ${done ? "done" : ""} ${active ? "active" : ""}">
      <div class="status-step-dot">${done ? "✓" : info.icon}</div>
      <div class="status-step-label">${info.label}</div>
    </div>`;
  }).join('<div class="status-step-line"></div>');

  const itemsList = order.items.map((i) =>
    `<div class="order-line"><span>${i.name} × ${i.quantity}</span><span>$${i.lineTotal.toFixed(2)}</span></div>`
  ).join("");

  const isFinished = order.status === "completed";

  return `
    <div class="order-status-tracker">
      <div class="order-status-top">
        <div class="order-status-id">Order #${order.id}</div>
        <div class="order-status-customer">Hi, ${order.customerName}!</div>
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
          <span>$${order.total.toFixed(2)}</span>
        </div>
      </div>

      ${isFinished
        ? `<button class="btn btn-primary btn-full" style="margin-top:1rem;" id="new-order-btn">Place Another Order</button>`
        : `<p class="order-status-hint">Auto-refreshing every 10 seconds…</p>`
      }
    </div>
  `;
}

function showOrderTracker(order) {
  if (orderStatusInterval) clearInterval(orderStatusInterval);

  const cartBody = cartSection.querySelector(".cart-body");
  cartBody.innerHTML = buildStatusHTML(order);

  const newOrderBtn = cartBody.querySelector("#new-order-btn");
  if (newOrderBtn) newOrderBtn.addEventListener("click", resetCart);

  if (order.status !== "completed") {
    orderStatusInterval = setInterval(async () => {
      try {
        const res = await fetch(`/api/order/${order.id}`);
        if (!res.ok) return;
        const data = await res.json();
        cartBody.innerHTML = buildStatusHTML(data.order);
        const btn = cartBody.querySelector("#new-order-btn");
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
  // Restore the original cart panel by reloading the page
  window.location.reload();
}

// ---------------------------------------------------------------------------
// Checkout form submission
// ---------------------------------------------------------------------------

checkoutForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!cart.length) {
    showResponse("Please add items to your order before checking out.", "error");
    return;
  }

  const customerName = document.getElementById("customer-name").value.trim() || "Guest";
  const tableId = tableIdInput.value;
  const payload = {
    customerName,
    tableId,
    items: cart.map((entry) => ({ id: entry.id, quantity: entry.quantity })),
  };

  const submitBtn = checkoutForm.querySelector('button[type="submit"]');
  submitBtn.disabled = true;
  submitBtn.textContent = "Placing order…";

  try {
    const res = await fetch("/api/checkout", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const json = await res.json();
    if (!res.ok) {
      showResponse(json.description || "Failed to place order.", "error");
      submitBtn.disabled = false;
      submitBtn.textContent = "Place Order";
    } else {
      // Replace cart panel with live order status tracker
      showOrderTracker(json.order);
    }
  } catch (err) {
    showResponse("Network error. Please try again.", "error");
    submitBtn.disabled = false;
    submitBtn.textContent = "Place Order";
  }
});

function showResponse(msg, type) {
  responseBox.textContent = msg;
  responseBox.className = "checkout-response visible " + (type === "error" ? "alert alert-error" : "alert alert-success");
}

clearCartButton?.addEventListener("click", clearCart);
searchInput?.addEventListener("input", renderMenu);

loadMenu();
