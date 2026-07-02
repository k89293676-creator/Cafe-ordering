const menuContainer = document.getElementById("menu");
const cartContainer = document.getElementById("cart");
const totalDisplay = document.getElementById("order-total");
const itemCountDisplay = document.getElementById("item-count");
const checkoutForm = document.getElementById("checkout-form");
const responseBox = document.getElementById("checkout-response");
const clearCartButton = document.getElementById("clear-cart");
const searchInput = document.getElementById("menu-search");

let menuData = [];
let cart = [];

function fmt(amount) {
  return amount.toFixed(2);
}

function renderMenu() {
  if (!menuData.length) {
    menuContainer.innerHTML = '<p style="color:var(--text-muted);">No menu items available.</p>';
    return;
  }

  const query = searchInput?.value.trim().toLowerCase() || "";
  const categories = menuData
    .map((cat) => ({
      ...cat,
      items: cat.items.filter((item) => {
        if (!query) return true;
        const text = `${item.name} ${item.description || ""} ${(item.tags || []).join(" ")}`.toLowerCase();
        return text.includes(query) || cat.name.toLowerCase().includes(query);
      }),
    }))
    .filter((cat) => cat.items.length > 0);

  if (!categories.length) {
    menuContainer.innerHTML = '<p style="color:var(--text-muted);">No items match your search.</p>';
    return;
  }

  menuContainer.innerHTML = categories
    .map(
      (cat) => `
      <div class="menu-category">
        <div class="menu-category-title">${cat.name}</div>
        <div class="menu-items">
          ${cat.items
            .map(
              (item) => `
            <div class="menu-item">
              <div class="menu-item-info">
                <h4>${item.name}</h4>
                ${item.description ? `<p class="item-desc">${item.description}</p>` : ""}
              </div>
              <div class="menu-item-right">
                <span class="item-price">₹${fmt(item.price)}</span>
                <button class="add-btn" data-id="${item.id}">+ Add</button>
              </div>
            </div>
          `
            )
            .join("")}
        </div>
      </div>
    `
    )
    .join("");

  menuContainer.querySelectorAll(".add-btn").forEach((btn) => {
    btn.addEventListener("click", () => addToCart(btn.dataset.id));
  });
}

function renderCart() {
  const total = cart.reduce((s, e) => s + e.lineTotal, 0);
  if (totalDisplay) totalDisplay.textContent = fmt(total);
  if (itemCountDisplay) itemCountDisplay.textContent = cart.reduce((s, e) => s + e.quantity, 0);

  if (!cart.length) {
    if (cartContainer) cartContainer.innerHTML = "<p>Your cart is empty.</p>";
    return;
  }

  cartContainer.innerHTML = cart
    .map(
      (entry) => `
      <div class="cart-item">
        <div class="cart-item-info">
          <span>${entry.name}</span>
          <span>₹${fmt(entry.lineTotal)}</span>
        </div>
        <div class="cart-item-actions">
          <button class="qty-btn" data-action="decrease" data-id="${entry.id}">−</button>
          <span class="qty-value">${entry.quantity}</span>
          <button class="qty-btn" data-action="increase" data-id="${entry.id}">+</button>
          <button class="remove-btn" data-action="remove" data-id="${entry.id}">✕</button>
        </div>
      </div>
    `
    )
    .join("");

  cartContainer.querySelectorAll("[data-action]").forEach((el) => {
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

async function loadMenu() {
  try {
    const res = await fetch("/api/menu?v=" + Date.now(), {
      cache: "no-store",
      headers: { "Cache-Control": "no-cache" },
    });
    if (!res.ok) throw new Error("Unable to load menu.");
    const data = await res.json();
    menuData = data.categories || [];
    renderMenu();
  } catch (err) {
    if (menuContainer) menuContainer.innerHTML = `<p style="color:var(--danger);">${err.message}</p>`;
  }
}

if (checkoutForm) {
  checkoutForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!cart.length) {
      responseBox.textContent = "Please add items to your order first.";
      responseBox.className = "response error";
      return;
    }

    const customerName = document.getElementById("customer-name").value.trim() || "Guest";
    const payload = {
      customerName,
      items: cart.map((entry) => ({ id: entry.id, quantity: entry.quantity })),
    };

    const res = await fetch("/api/checkout", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const json = await res.json();
    if (!res.ok) {
      responseBox.textContent = json.description || "Failed to place order.";
      responseBox.className = "response error";
      return;
    }

    responseBox.innerHTML = `<strong>${json.message}</strong><p>Order #${json.order.id} placed for ${json.order.customerName}.</p>`;
    responseBox.className = "response success";
    cart = [];
    renderCart();
    checkoutForm.reset();
  });
}

loadMenu();
searchInput?.addEventListener("input", renderMenu);
clearCartButton?.addEventListener("click", clearCart);
