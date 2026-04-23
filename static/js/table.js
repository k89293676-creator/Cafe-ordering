/* ==========================================
   CAFE 11:11 — Table Ordering Page v3
   ========================================== */
"use strict";

/* ── Constants injected by template ── */
const TABLE_ID  = (window.CAFE_TABLE_ID  || "").trim();
const CAFE_NAME = (window.CAFE_NAME      || "Cafe 11:11").trim();

/* ── State ── */
let menuData      = [];   // [{id, name, items:[...]}]
let cart          = {};   // { itemId: {item, qty} }
let feedbackRating = 0;
let currentOrderId = null;
let pollTimer      = null;
let orderDone      = false;
let lastName       = "Guest";
let reviewsShown   = false;
let activeCat      = "";
let activeFilter   = "";   // dietary filter: "vegan" | "gluten-free" | "nut-free" | ""
let tipPercent     = 0;    // 0 = no tip, otherwise percentage or custom
let customTip      = 0;
let favourites     = JSON.parse(localStorage.getItem("cafe_favourites") || "[]");

/* ── Tiny helpers ── */
const $  = id  => document.getElementById(id);
const qs = sel => document.querySelector(sel);

function fmt(n) { return parseFloat(n || 0).toFixed(2); }
function csrfHeaders(extra = {}) {
  const token = document.querySelector('meta[name="csrf-token"]')?.content || "";
  return token ? { ...extra, "X-CSRFToken": token } : extra;
}

function totalQty()   { return Object.values(cart).reduce((s, e) => s + e.qty, 0); }
function totalPrice() { return Object.values(cart).reduce((s, e) => s + e.item.price * e.qty, 0); }
function getTipAmount() {
  const sub = totalPrice();
  if (customTip > 0) return customTip;
  if (tipPercent > 0) return Math.round(sub * tipPercent) / 100;
  return 0;
}
function grandTotal() { return totalPrice() + getTipAmount(); }

function esc(s) {
  return String(s ?? "")
    .replace(/&/g,"&amp;").replace(/</g,"&lt;")
    .replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

/* ── Auto image generator ──
 * When an item has no explicit image_url, generate one from the item's name
 * so the menu always has visuals. Uses Pollinations AI (which understands the
 * item name directly) with a deterministic seed so the same item always shows
 * the same image. On error, falls back to a clean SVG placeholder that shows
 * the item name — never random unrelated photos.
 */
function _slug(s) {
  return String(s || "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
}
function _hash(s) {
  let h = 0;
  for (let i = 0; i < s.length; i++) { h = (h * 31 + s.charCodeAt(i)) | 0; }
  return Math.abs(h);
}
function autoImageUrl(item) {
  // Use Pollinations AI's default (turbo) model — it's free, fast, and doesn't
  // require an API token (unlike `flux`, which now gates many requests). Seed
  // is deterministic per item so the same dish always shows the same image.
  const prompt = encodeURIComponent(
    `${item.name}, professional food photography, restaurant dish, natural light, close-up, appetizing, high detail`
  );
  // image_seed lets owners "regenerate" the AI image — bumping it produces a
  // brand-new picture for the same dish without changing the item's identity.
  const seedBase = item.image_seed != null
    ? Number(item.image_seed) || 0
    : _hash(item.id || item.name);
  const seed = Math.abs(seedBase) % 999983;
  return `https://image.pollinations.ai/prompt/${prompt}?width=400&height=250&nologo=true&nofeed=true&seed=${seed}`;
}
function autoImageUrlBackup(item) {
  // LoremFlickr serves real Flickr photos for keywords. Deterministic via lock.
  // Used as a second-tier fallback before the SVG placeholder.
  const kw = _slug(item.name).split("-").filter(Boolean).slice(0, 3).join(",") || "food";
  const seedBase = item.image_seed != null
    ? Number(item.image_seed) || 0
    : _hash(item.id || item.name);
  const lock = Math.abs(seedBase) % 9999;
  return `https://loremflickr.com/400/250/${encodeURIComponent(kw + ",food")}?lock=${lock}`;
}
function fallbackImageUrl(item) {
  // Deterministic SVG placeholder: a soft gradient (color picked from the item
  // name hash) with the item name centered. This is reliable, always on-topic,
  // and never shows unrelated photos. Returned as a data URI so it works offline.
  const name = String(item.name || "Menu Item");
  const palettes = [
    ["#fde2e4", "#fad2e1"], ["#e2ece9", "#bee1e6"], ["#fff1e6", "#f7d6a4"],
    ["#dbeafe", "#bfdbfe"], ["#ede9fe", "#ddd6fe"], ["#dcfce7", "#bbf7d0"],
    ["#fef3c7", "#fde68a"], ["#fee2e2", "#fecaca"], ["#e0f2fe", "#bae6fd"],
    ["#f5d0fe", "#f0abfc"]
  ];
  const [c1, c2] = palettes[_hash(name) % palettes.length];
  // Wrap long names onto two lines
  const words = name.split(/\s+/);
  let line1 = name, line2 = "";
  if (name.length > 14 && words.length > 1) {
    const mid = Math.ceil(words.length / 2);
    line1 = words.slice(0, mid).join(" ");
    line2 = words.slice(mid).join(" ");
  }
  const safe = (s) => String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
  const svg = `<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 400 250'>
    <defs><linearGradient id='g' x1='0' y1='0' x2='1' y2='1'>
      <stop offset='0%' stop-color='${c1}'/><stop offset='100%' stop-color='${c2}'/>
    </linearGradient></defs>
    <rect width='400' height='250' fill='url(#g)'/>
    <text x='200' y='${line2 ? 118 : 135}' text-anchor='middle' font-family='-apple-system,Segoe UI,Roboto,sans-serif' font-size='26' font-weight='700' fill='#1f2937'>${safe(line1)}</text>
    ${line2 ? `<text x='200' y='150' text-anchor='middle' font-family='-apple-system,Segoe UI,Roboto,sans-serif' font-size='26' font-weight='700' fill='#1f2937'>${safe(line2)}</text>` : ""}
  </svg>`;
  return "data:image/svg+xml;utf8," + encodeURIComponent(svg);
}

function showToast(msg, ms = 2800) {
  document.querySelectorAll(".cafe-toast").forEach(t => t.remove());
  const t = document.createElement("div");
  t.className = "cafe-toast";
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => {
    t.style.transition = "opacity 0.3s";
    t.style.opacity = "0";
    setTimeout(() => t.remove(), 350);
  }, ms);
}

function setResp(el, msg, type) {
  if (!el) return;
  el.textContent = msg;
  el.className = "o-resp" + (type ? " o-resp--" + type : "");
  if (type) setTimeout(() => { if (el.textContent === msg) { el.textContent = ""; el.className = "o-resp"; } }, 5000);
}

/* ── Cart open/close ── */
function openCart() {
  qs(".o-cart")?.classList.add("is-open");
  document.body.classList.add("cart-is-open");
}

function closeCart() {
  qs(".o-cart")?.classList.remove("is-open");
  document.body.classList.remove("cart-is-open");
}

/* ── Menu loading ── */
async function loadMenu() {
  const mc = $("menu-container");
  if (!mc) return;
  mc.innerHTML = `<div class="o-loading"><div class="o-spinner"></div><span>Loading menu…</span></div>`;

  try {
    const res = await fetch(`/api/menu?table_id=${encodeURIComponent(TABLE_ID)}`);
    if (!res.ok) throw new Error("HTTP " + res.status);
    const data = await res.json();
    menuData = (data.categories || []).filter(c => c.items && c.items.length > 0);
    buildCatNav();
    renderMenu();
  } catch (err) {
    console.error("[cafe] menu load failed:", err);
    mc.innerHTML = `<div class="o-empty">
      <div class="o-empty__icon">🍽</div>
      <p>Menu unavailable</p>
      <span>Please ask a staff member for assistance.</span>
    </div>`;
  }
}

/* ── Category nav ── */
function buildCatNav() {
  const nav = $("cat-nav");
  if (!nav) return;
  nav.innerHTML = "";

  const all = document.createElement("button");
  all.className = "o-cat o-cat--active";
  all.textContent = "All";
  all.dataset.cat = "";
  all.addEventListener("click", () => setCat(""));
  nav.appendChild(all);

  menuData.forEach(cat => {
    const btn = document.createElement("button");
    btn.className = "o-cat";
    btn.textContent = cat.name;
    btn.dataset.cat = cat.id;
    btn.addEventListener("click", () => setCat(cat.id));
    nav.appendChild(btn);
  });
}

function setCat(id) {
  activeCat = id;
  document.querySelectorAll("#cat-nav .o-cat").forEach(b => {
    b.classList.toggle("o-cat--active", b.dataset.cat === id);
  });
  renderMenu();
}

/* ── Menu render ── */
function renderMenu() {
  const mc = $("menu-container");
  if (!mc) return;

  const q = ($("search-input")?.value || "").toLowerCase().trim();
  const cats = activeCat ? menuData.filter(c => c.id === activeCat) : menuData;

  const visible = cats.map(cat => ({
    ...cat,
    items: cat.items.filter(item => {
      if (!item.available && item.available !== undefined) return item.available !== false;
      const matchesSearch = !q || `${item.name} ${item.description || ""} ${(item.tags || []).join(" ")}`.toLowerCase().includes(q);
      const matchesFilter = !activeFilter || (item.dietary_tags || item.tags || []).includes(activeFilter);
      return matchesSearch && matchesFilter;
    })
  })).filter(c => c.items.length > 0);

  if (!visible.length) {
    mc.innerHTML = `<div class="o-empty">
      <div class="o-empty__icon">🔍</div>
      <p>No results</p><span>Try a different search</span>
    </div>`;
    return;
  }

  mc.innerHTML = visible.map(cat => `
    <div class="o-section">
      <h2 class="o-section__title">
        ${esc(cat.name)}
        <span class="o-section__count">${cat.items.length} item${cat.items.length !== 1 ? "s" : ""}</span>
      </h2>
      <div class="o-grid">
        ${cat.items.map(item => itemCard(item)).join("")}
      </div>
    </div>`).join("");

  /* Wire item buttons */
  mc.querySelectorAll("[data-item]").forEach(el => {
    const id   = el.dataset.item;
    const item = findItem(id);
    if (!item) return;
    el.querySelector(".js-add")?.addEventListener("click",  () => cartAdd(id, item));
    el.querySelector(".js-inc")?.addEventListener("click",  () => cartChange(id,  1));
    el.querySelector(".js-dec")?.addEventListener("click",  () => cartChange(id, -1));
  });
}

function itemCard(item) {
  const qty  = cart[item.id]?.qty || 0;
  const avail = item.available !== false;

  const actionHtml = !avail
    ? `<button class="o-add o-add--sold-out" disabled>Sold out</button>`
    : qty === 0
      ? `<button class="o-add js-add">+ Add</button>`
      : `<div class="o-stepper">
           <button class="o-stepper__btn js-dec" aria-label="Remove">−</button>
           <span class="o-stepper__val">${qty}</span>
           <button class="o-stepper__btn js-inc" aria-label="Add">+</button>
         </div>`;

  const popularBadge = item.popular ? `<span class="o-popular-badge">🔥 Popular</span>` : "";
  const imgSrc = item.image_url || autoImageUrl(item);
  // Three-tier fallback: explicit/AI image → LoremFlickr photo → SVG placeholder.
  // Each fallback step rebinds onerror so the chain always lands on the SVG,
  // which is a data URI and can never fail.
  const backupUrl = item.image_url ? "" : autoImageUrlBackup(item);
  const finalUrl  = fallbackImageUrl(item);
  const onerrAttr = backupUrl
    ? `this.onerror=function(){this.onerror=null;this.src='${esc(finalUrl)}';};this.src='${esc(backupUrl)}';`
    : `this.onerror=null;this.src='${esc(finalUrl)}';`;
  const imgHtml = `<img class="o-item__img" src="${esc(imgSrc)}" alt="${esc(item.name)}" loading="lazy"
                        onerror="${onerrAttr}" />`;

  return `
    <div class="o-item${avail ? "" : " o-item--sold-out"}" data-item="${esc(item.id)}">
      ${imgHtml}
      <div class="o-item__body">
        <div class="o-item__name">
          ${popularBadge}${esc(item.name)}
          ${avail ? "" : `<span class="o-sold-badge">Sold out</span>`}
        </div>
        ${item.description ? `<p class="o-item__desc">${esc(item.description)}</p>` : ""}
        ${item.tags?.length ? `<div class="o-item__tags">${item.tags.map(t => `<span class="o-item__tag">${esc(t)}</span>`).join("")}</div>` : ""}
        ${item.dietary_tags?.length ? `<div class="o-item__dietary">${item.dietary_tags.map(t => `<span class="o-diet-badge o-diet-badge--${esc(t.replace(/\s+/g,"-"))}">${esc(t)}</span>`).join("")}</div>` : ""}
        ${item.prep_time ? `<div class="o-item__prep">⏱ ~${esc(item.prep_time)} min</div>` : ""}
        ${item.modifiers?.length ? `<div class="o-item__modifiers">${item.modifiers.map(m => `<span class="o-modifier">+ ${esc(m.name)} ₹${fmt(m.price)}</span>`).join("")}</div>` : ""}
      </div>
      <div class="o-item__footer">
        <span class="o-item__price">₹${fmt(item.price)}</span>
        ${actionHtml}
      </div>
    </div>`;
}

function findItem(id) {
  for (const cat of menuData) {
    const it = cat.items.find(i => i.id === id);
    if (it) return it;
  }
  return null;
}

/* ── Cart operations ── */
function cartAdd(id, item) {
  if (!item || item.available === false) return;
  cart[id] = cart[id] ? { item, qty: cart[id].qty + 1 } : { item, qty: 1 };
  syncCart();
  renderMenu();
}

function cartChange(id, delta) {
  if (!cart[id]) return;
  cart[id].qty += delta;
  if (cart[id].qty <= 0) delete cart[id];
  syncCart();
  renderMenu();
}

function cartClear() {
  cart = {};
  syncCart();
  renderMenu();
}

/* ── Sync cart display ── */
function syncCart() {
  const qty   = totalQty();
  const price = totalPrice();

  /* Header badge */
  const badge = $("cart-badge");
  if (badge) badge.textContent = qty;
  const headerBtn = qs(".o-cart-btn");
  if (headerBtn) headerBtn.classList.toggle("is-empty", qty === 0);

  /* FAB */
  const fab = $("cart-fab");
  if (fab) {
    fab.classList.toggle("o-fab--show", qty > 0);
    const fbadge = $("fab-badge");
    const fprice = $("fab-price");
    if (fbadge) fbadge.textContent = qty;
    if (fprice) fprice.textContent = fmt(grandTotal());
  }

  /* Cart header count pill */
  const pill = $("cart-count-pill");
  if (pill) {
    if (qty > 0) { pill.textContent = qty + " item" + (qty !== 1 ? "s" : ""); pill.style.display = ""; }
    else pill.style.display = "none";
  }

  /* Totals */
  const itemCountEl = $("cart-item-count");
  const totalEl     = $("cart-total");
  if (itemCountEl) itemCountEl.textContent = qty;
  const tip = getTipAmount();
  const grand = price + tip;
  if (totalEl) totalEl.textContent = fmt(grand);
  // Update tip display if elements exist
  const tipEl = $("cart-tip-amount");
  if (tipEl) tipEl.textContent = tip > 0 ? "₹" + fmt(tip) : "—";
  const subtotalEl = $("cart-subtotal");
  if (subtotalEl) subtotalEl.textContent = fmt(price);
  // Update FAB price
  const fabPrice = $("fab-price");
  if (fabPrice) fabPrice.textContent = fmt(grand);

  /* Items list */
  const listEl = $("cart-items");
  if (!listEl) return;

  if (qty === 0) {
    listEl.innerHTML = `<div class="o-cart__empty">
      <div class="o-cart__empty-icon">🛒</div>
      <p>Nothing added yet</p>
      <span>Browse the menu and tap + Add</span>
    </div>`;
    return;
  }

  listEl.innerHTML = Object.entries(cart).map(([id, { item, qty }]) => `
    <div class="o-cart-item">
      <div class="o-cart-item__info">
        <div class="o-cart-item__name">${esc(item.name)}</div>
        <div class="o-cart-item__unit">₹${fmt(item.price)} each</div>
      </div>
      <div class="o-cart-item__right">
        <div class="o-cart-item__controls">
          <button class="o-qty-btn" data-id="${esc(id)}" data-d="-1" aria-label="Remove one">−</button>
          <span class="o-qty-val">${qty}</span>
          <button class="o-qty-btn" data-id="${esc(id)}" data-d="1"  aria-label="Add one">+</button>
        </div>
        <div class="o-cart-item__total">₹${fmt(item.price * qty)}</div>
        <button class="o-cart-item__rm" data-rm="${esc(id)}" aria-label="Remove ${esc(item.name)}">✕</button>
      </div>
    </div>`).join("");

  listEl.querySelectorAll(".o-qty-btn").forEach(btn => {
    btn.addEventListener("click", () => cartChange(btn.dataset.id, parseInt(btn.dataset.d)));
  });
  listEl.querySelectorAll("[data-rm]").forEach(btn => {
    btn.addEventListener("click", () => { delete cart[btn.dataset.rm]; syncCart(); renderMenu(); });
  });
}

/* ── Checkout ── */
async function placeOrder(name) {
  const qty = totalQty();
  if (qty === 0) { setResp($("checkout-resp"), "Add items to your order first.", "error"); return; }

  const btn = $("place-order-btn");
  if (btn?.disabled) return;
  if (btn) { btn.disabled = true; btn.textContent = "Placing order…"; }
  lastName = name || "Guest";

  const tipAmt = getTipAmount();
  const payload = {
    tableId:       TABLE_ID,
    customerName:  lastName,
    customerEmail: ($("customer-email")?.value || "").trim(),
    customerPhone: ($("customer-phone")?.value || "").trim(),
    notes:         ($("order-notes")?.value || "").trim(),
    tip:           Math.round(tipAmt * 100) / 100,
    items: Object.entries(cart).map(([id, { qty }]) => ({ id, quantity: qty })),
  };

  try {
    const res  = await fetch("/api/checkout", {
      method:  "POST",
      headers: csrfHeaders({ "Content-Type": "application/json" }),
      body:    JSON.stringify(payload),
    });
    const data = await res.json();

    if (res.ok && data.checkoutUrl) {
      window.location.href = data.checkoutUrl;
      return;
    }

    if (res.ok && data.order) {
      currentOrderId = data.order.id;
      cartClear();
      closeCart();
      showTracker(data.order);
      return;
    }

    /* Error from server */
    const msg = data.description || data.error || data.message || "Something went wrong — please try again.";
    setResp($("checkout-resp"), msg, "error");
    if (btn) { btn.disabled = false; btn.textContent = "Place Order →"; }

  } catch {
    setResp($("checkout-resp"), "Network error. Please check your connection.", "error");
    if (btn) { btn.disabled = false; btn.textContent = "Place Order →"; }
  }
}

/* ── Order status tracker ── */
const STATUS = {
  pending:   { emoji:"⏳", label:"Order received",  desc:"We've got your order and will start preparing shortly.", step:0 },
  preparing: { emoji:"👨‍🍳", label:"Being prepared", desc:"Your order is in the kitchen!",                         step:1 },
  ready:     { emoji:"✅", label:"Ready to collect", desc:"Your order is ready! Please collect from the counter.",  step:2 },
  completed: { emoji:"🎉", label:"Completed",        desc:"Thank you for dining with us! Enjoy your meal.",         step:3 },
  cancelled: { emoji:"❌", label:"Cancelled",        desc:"This order was cancelled. Please speak with staff.",      step:-1 },
};
const STEPS = ["Received","Preparing","Ready","Done"];

function trackerHtml(order) {
  const s  = order.status || "pending";
  const si = STATUS[s] || STATUS.pending;

  const stepsHtml = STEPS.map((lbl, i) => {
    const cls = i < si.step ? "o-step is-done" : i === si.step ? "o-step is-active" : "o-step";
    const dot = i < si.step ? "✓" : (i + 1);
    const line = i < STEPS.length - 1
      ? `<div class="o-step-line${i < si.step ? " is-done" : ""}"></div>`
      : "";
    return `<div class="${cls}">
      <div class="o-step__dot">${dot}</div>
      <div class="o-step__lbl">${lbl}</div>
    </div>${line}`;
  }).join("");

  const itemsHtml = (order.items || []).map(it => `
    <div class="o-tracker__line">
      <span>${esc(it.name)} × ${it.quantity}</span>
      <span>₹${fmt(it.lineTotal || 0)}</span>
    </div>`).join("");

  const cancelBtn = s === "pending"
    ? `<button class="o-tracker__cancel-btn" id="cancel-btn" data-oid="${esc(String(order.id))}">Cancel order</button>`
    : "";

  const pickupHtml = order.pickupCode
    ? `<div style="text-align:center;margin:1rem 0;padding:1rem;background:#f0fdf4;border:2px dashed #10b981;border-radius:.75rem;">
        <div style="font-size:.7rem;font-weight:700;color:#065f46;letter-spacing:.08em;text-transform:uppercase;margin-bottom:.35rem;">Pickup Code</div>
        <div style="font-size:2.2rem;font-weight:900;font-family:monospace;letter-spacing:.18em;color:#059669;">${esc(order.pickupCode)}</div>
        <div style="font-size:.75rem;color:#6b7280;margin-top:.3rem;">Show at the counter when paying</div>
      </div>`
    : "";

  return `<div class="o-tracker" id="tracker-root">
    <div class="o-tracker__id">Order #${esc(String(order.id))}</div>
    <div class="o-tracker__hi">Hi, ${esc(order.customerName || "Guest")}!</div>
    ${pickupHtml}
    <div class="o-steps" id="tracker-steps">${stepsHtml}</div>
    <div class="o-tracker__card" id="tracker-card">
      <div class="o-tracker__emoji" id="tracker-emoji">${si.emoji}</div>
      <div>
        <div class="o-tracker__status-lbl" id="tracker-lbl">${si.label}</div>
        <div class="o-tracker__status-desc" id="tracker-desc">${si.desc}</div>
      </div>
    </div>
    <p class="o-tracker__hint" id="tracker-hint">Updates in real time as your order progresses.</p>
    <div class="o-tracker__summary">
      ${itemsHtml}
      <div class="o-tracker__line o-tracker__line--total">
        <span>Total</span>
        <span class="o-tracker__total-val">₹${fmt(order.total || 0)}</span>
      </div>
    </div>
    ${cancelBtn}
    <button class="o-tracker__new-btn" id="new-order-btn">Order Something Else</button>
  </div>`;
}

function showTracker(order) {
  const cart = qs(".o-cart");
  if (!cart) return;

  /* Swap cart panel content */
  cart.innerHTML = `
    <div class="o-drag-handle" aria-hidden="true"></div>
    <div class="o-cart__head">
      <h2 class="o-cart__title">Your Order</h2>
      <button class="o-cart__close" id="tracker-close-btn" aria-label="Close">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M18 6L6 18M6 6l12 12"/></svg>
      </button>
    </div>
    ${trackerHtml(order)}`;

  $("tracker-close-btn")?.addEventListener("click", closeCart);
  $("new-order-btn")?.addEventListener("click", resetToOrdering);
  $("cancel-btn")?.addEventListener("click", function() {
    const oid = this.dataset.oid || currentOrderId;
    if (oid && confirm("Cancel this order?")) cancelOrder(oid);
  });

  openCart();
  startPolling(order.id);
}

function patchTrackerStatus(status) {
  const si = STATUS[status] || STATUS.pending;

  /* Remove cancel button if no longer pending */
  if (status !== "pending") $("cancel-btn")?.remove();

  /* Update steps */
  const stepsEl = $("tracker-steps");
  stepsEl?.querySelectorAll(".o-step").forEach((el, i) => {
    el.className = i < si.step ? "o-step is-done" : i === si.step ? "o-step is-active" : "o-step";
    const dot = el.querySelector(".o-step__dot");
    if (dot) dot.innerHTML = i < si.step ? "✓" : String(i + 1);
  });
  stepsEl?.querySelectorAll(".o-step-line").forEach((el, i) => {
    el.classList.toggle("is-done", i < si.step);
  });

  const emojiEl = $("tracker-emoji");
  const lblEl   = $("tracker-lbl");
  const descEl  = $("tracker-desc");
  if (emojiEl) emojiEl.textContent = si.emoji;
  if (lblEl)   lblEl.textContent   = si.label;
  if (descEl)  descEl.textContent  = si.desc;

  if ((status === "ready" || status === "completed") && !orderDone) {
    orderDone = true;
    const hint = $("tracker-hint");
    if (hint) hint.textContent = "Your order is ready! Come back again soon.";

    /* Show "Leave a Review" button */
    const newBtn = $("new-order-btn");
    if (newBtn && !$("leave-review-btn")) {
      const rb = document.createElement("button");
      rb.id = "leave-review-btn";
      rb.className = "o-tracker__new-btn";
      rb.style.cssText = "background:transparent;border:2px solid var(--gold);color:var(--gold);margin-top:0.5rem;";
      rb.textContent = "★ Leave a Review";
      rb.addEventListener("click", () => { closeCart(); openFeedback(); });
      newBtn.insertAdjacentElement("afterend", rb);
    }
    showReviews();
  }
}

/* ── Polling ── */
function startPolling(orderId) {
  stopPolling();
  pollTimer = setInterval(async () => {
    try {
      const res = await fetch(`/api/orders/${orderId}`);
      if (!res.ok) return;
      const data = await res.json();
      const status = data.order?.status;
      if (!status) return;
      patchTrackerStatus(status);
      if (status === "completed" || status === "cancelled") stopPolling();
    } catch {}
  }, 5000);
}

function stopPolling() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
}

/* ── Cancel order ── */
async function cancelOrder(orderId) {
  const btn = $("cancel-btn");
  if (btn) { btn.disabled = true; btn.textContent = "Cancelling…"; }
  try {
    const res = await fetch(`/api/orders/${orderId}/cancel`, {
      method: "POST", headers: csrfHeaders({ "Content-Type": "application/json" }), body: "{}"
    });
    const data = await res.json();
    if (res.ok) {
      showToast("Order cancelled.");
      patchTrackerStatus("cancelled");
      btn?.remove();
    } else {
      showToast(data.description || data.error || "Could not cancel order.");
      if (btn) { btn.disabled = false; btn.textContent = "Cancel order"; }
    }
  } catch {
    showToast("Network error.");
    if (btn) { btn.disabled = false; btn.textContent = "Cancel order"; }
  }
}

/* ── Reset to ordering ── */
function resetToOrdering() {
  stopPolling();
  currentOrderId = null;
  orderDone      = false;
  reviewsShown   = false;

  const revSection = $("reviews-section");
  if (revSection) revSection.classList.add("o-reviews--hidden");

  /* Rebuild the cart panel */
  const cartEl = qs(".o-cart");
  if (!cartEl) return;

  cartEl.innerHTML = `
    <div class="o-drag-handle" aria-hidden="true"></div>
    <div class="o-cart__head">
      <h2 class="o-cart__title">
        Your Order
        <span class="o-cart__count-pill" id="cart-count-pill" style="display:none"></span>
      </h2>
      <button class="o-cart__close" id="cart-close-btn" aria-label="Close cart">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M18 6L6 18M6 6l12 12"/></svg>
      </button>
    </div>
    <div class="o-cart__body" id="cart-body">
      <div class="o-cart__items" id="cart-items"></div>
    </div>
    <div class="o-cart__foot" id="cart-foot">
      <div class="o-cart__totals">
        <div class="o-cart__row">
          <span>Items</span>
          <span id="cart-item-count">0</span>
        </div>
        <div class="o-cart__row o-cart__row--total">
          <span>Total</span>
          <span class="o-cart__total-val">₹<span id="cart-total">0.00</span></span>
        </div>
      </div>
      <div class="o-cart__actions">
        <button id="clear-cart-btn" class="o-clear-btn" type="button">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/></svg>
          Clear cart
        </button>
      </div>
      <form id="checkout-form" novalidate>
        <input
          id="customer-name"
          class="o-name-input"
          type="text"
          placeholder="Your name (optional)"
          autocomplete="name"
          maxlength="80"
        />
        <input
          id="customer-email"
          class="o-name-input"
          type="email"
          placeholder="Email for receipt (optional)"
          autocomplete="email"
          maxlength="254"
        />
        <button type="submit" class="o-place-btn" id="place-order-btn">Place Order →</button>
      </form>
      <div id="checkout-resp" class="o-resp"></div>
    </div>`;

  wireCartPanel(cartEl);
  syncCart();
  closeCart();
}

function wireCartPanel(root) {
  root.querySelector("#cart-close-btn")?.addEventListener("click", closeCart);
  root.querySelector("#clear-cart-btn")?.addEventListener("click", () => {
    if (totalQty() > 0) cartClear();
  });
  const form = root.querySelector("#checkout-form");
  form?.addEventListener("submit", async e => {
    e.preventDefault();
    const name = (root.querySelector("#customer-name")?.value || "").trim() || "Guest";
    await placeOrder(name);
  });
}

/* ── Reviews ── */
function showReviews() {
  if (reviewsShown) return;
  reviewsShown = true;
  const sec = $("reviews-section");
  if (!sec) return;
  loadReviews().then(() => {
    sec.classList.remove("o-reviews--hidden");
    setTimeout(() => sec.scrollIntoView({ behavior: "smooth", block: "start" }), 400);
  });
}

async function loadReviews() {
  const list = $("review-list");
  const summ = $("reviews-summary");
  if (!list) return;
  try {
    const res  = await fetch(`/api/feedback?table_id=${encodeURIComponent(TABLE_ID)}`);
    if (!res.ok) throw new Error();
    const data = await res.json();
    const items = data.feedback || [];
    const avg   = data.average  || 0;
    const total = data.total    || 0;

    if (summ && total > 0) {
      const stars = Math.round(avg);
      summ.innerHTML = `
        <div class="o-reviews__avg-num">${avg}</div>
        <div class="o-reviews__stars">${"★".repeat(stars)}${"☆".repeat(5 - stars)}</div>
        <div class="o-reviews__count">${total} review${total !== 1 ? "s" : ""}</div>`;
    }

    if (!items.length) {
      list.innerHTML = `<p style="text-align:center;color:var(--text-3);font-size:0.9rem;padding:1.5rem;">Be the first to leave a review!</p>`;
      return;
    }

    list.innerHTML = items.map(fb => {
      const stars = parseInt(fb.rating) || 0;
      const init  = (fb.customerName || "G")[0].toUpperCase();
      return `<div class="o-review">
        <div class="o-review__top">
          <div class="o-review__avatar">${esc(init)}</div>
          <div>
            <div class="o-review__name">${esc(fb.customerName || "Guest")}</div>
            <div class="o-review__stars">${"★".repeat(stars)}${"☆".repeat(5 - stars)}</div>
          </div>
          <div class="o-review__date">${(fb.createdAt || "").slice(0,10)}</div>
        </div>
        ${fb.comment ? `<div class="o-review__body">"${esc(fb.comment)}"</div>` : ""}
      </div>`;
    }).join("");
  } catch {
    list.innerHTML = `<p style="text-align:center;color:var(--text-3);font-size:0.9rem;">Reviews unavailable right now.</p>`;
  }
}

/* ── Feedback modal ── */
function openFeedback() {
  feedbackRating = 0;
  updateStars(0);
  const ta = $("feedback-comment");
  if (ta) ta.value = "";
  const resp = $("feedback-resp");
  if (resp) { resp.textContent = ""; }
  const bg = $("feedback-modal-bg");
  if (bg) { bg.classList.add("is-open"); document.body.classList.add("feedback-open"); }
}

function closeFeedback() {
  $("feedback-modal-bg")?.classList.remove("is-open");
  document.body.classList.remove("feedback-open");
}

function updateStars(val) {
  document.querySelectorAll("#feedback-stars .o-star-btn").forEach(btn => {
    btn.classList.toggle("selected", parseInt(btn.dataset.val) <= val);
  });
}

/* ── Global event delegation ── */
document.addEventListener("click", async e => {
  const t = e.target;

  /* Cart open/close */
  if (t.closest("#header-cart-btn"))       { const o = qs(".o-cart"); o?.classList.contains("is-open") ? closeCart() : openCart(); return; }
  if (t.closest("#cart-fab"))               { openCart(); return; }
  if (t.closest("#cart-close-btn"))         { closeCart(); return; }
  if (t.closest(".o-backdrop"))             { closeCart(); return; }

  /* Feedback */
  if (t.closest("#open-feedback-btn") || t.closest("#reviews-feedback-btn")) { openFeedback(); return; }
  if (t.closest("#feedback-close-btn") || t.id === "feedback-modal-bg")       { closeFeedback(); return; }

  /* Feedback stars */
  const starBtn = t.closest("#feedback-stars .o-star-btn");
  if (starBtn) { feedbackRating = parseInt(starBtn.dataset.val); updateStars(feedbackRating); return; }

  /* Feedback submit */
  if (t.id === "feedback-submit-btn") {
    const resp = $("feedback-resp");
    if (!feedbackRating) { if (resp) resp.textContent = "Please select a rating."; return; }
    t.disabled = true; t.textContent = "Sending…";

    const payload = {
      tableId:      TABLE_ID,
      customerName: ($("customer-name")?.value || "").trim() || lastName || "Guest",
      rating:       feedbackRating,
      comment:      ($("feedback-comment")?.value || "").trim(),
    };
    try {
      const res  = await fetch("/api/feedback", { method:"POST", headers: csrfHeaders({"Content-Type":"application/json"}), body: JSON.stringify(payload) });
      const data = await res.json();
      if (res.ok) {
        if (resp) resp.textContent = "✓ Thank you for your feedback!";
        setTimeout(() => { closeFeedback(); loadReviews(); }, 1600);
      } else {
        if (resp) resp.textContent = data.description || data.error || "Something went wrong.";
      }
    } catch {
      if (resp) resp.textContent = "Network error. Please try again.";
    }
    t.disabled = false; t.textContent = "Send Feedback";
    return;
  }
});

/* ── Checkout form submit (fallback) ── */
document.addEventListener("submit", async e => {
  if (e.target.id !== "checkout-form") return;
  e.preventDefault();
  const name = (e.target.querySelector("#customer-name")?.value || "").trim() || "Guest";
  await placeOrder(name);
});

/* ── Star hover effects ── */
document.addEventListener("mouseover", e => {
  if (e.target.closest("#feedback-stars .o-star-btn")) updateStars(parseInt(e.target.closest(".o-star-btn").dataset.val));
});
document.addEventListener("mouseout", e => {
  if (e.target.closest("#feedback-stars")) updateStars(feedbackRating);
});

/* ── Search ── */
document.addEventListener("input", e => {
  if (e.target.id === "search-input") renderMenu();
});

/* ── ESC key ── */
document.addEventListener("keydown", e => {
  if (e.key !== "Escape") return;
  if ($("feedback-modal-bg")?.classList.contains("is-open")) { closeFeedback(); return; }
  if (qs(".o-cart.is-open")) closeCart();
});

/* ── Nav offset for sticky cart ── */
function setNavH() {
  const h1 = qs(".o-header")?.offsetHeight  || 0;
  const h2 = qs(".o-subnav")?.offsetHeight || 0;
  document.documentElement.style.setProperty("--nav-h", (h1 + h2) + "px");
}

/* ── Init ── */
document.addEventListener("DOMContentLoaded", () => {
  setNavH();
  const cartEl = qs(".o-cart");
  if (cartEl) wireCartPanel(cartEl);
  syncCart();
  loadMenu();

  /* ── Dietary filter buttons ── */
  document.querySelectorAll(".js-diet-filter").forEach(btn => {
    btn.addEventListener("click", () => {
      const val = btn.dataset.filter || "";
      activeFilter = activeFilter === val ? "" : val;
      document.querySelectorAll(".js-diet-filter").forEach(b => {
        b.classList.toggle("o-cat--active", b.dataset.filter === activeFilter);
      });
      renderMenu();
    });
  });

  /* ── Tip selector ── */
  document.querySelectorAll(".js-tip-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".js-tip-btn").forEach(b => b.classList.remove("is-selected"));
      btn.classList.add("is-selected");
      const val = btn.dataset.tip;
      if (val === "custom") {
        tipPercent = 0;
        const customInput = $("tip-custom-input");
        if (customInput) {
          customInput.style.display = "block";
          customTip = parseFloat(customInput.value) || 0;
        }
      } else {
        tipPercent = parseInt(val) || 0;
        customTip = 0;
        const ci = $("tip-custom-input");
        if (ci) ci.style.display = "none";
      }
      syncCart();
    });
  });

  const customTipInput = $("tip-custom-input");
  if (customTipInput) {
    customTipInput.addEventListener("input", () => {
      customTip = parseFloat(customTipInput.value) || 0;
      syncCart();
    });
  }

  /* ── Favourites ── */
  function saveFavourite(label) {
    const items = Object.entries(cart).map(([id, {item, qty}]) => ({id, name: item.name, price: item.price, quantity: qty}));
    if (!items.length) { showToast("Add items before saving a favourite."); return; }
    const fav = { name: label || "My Order", items, savedAt: new Date().toISOString() };
    favourites = [fav, ...favourites.filter(f => f.name !== fav.name)].slice(0, 5);
    localStorage.setItem("cafe_favourites", JSON.stringify(favourites));
    showToast("Saved as favourite!");
    renderFavourites();
  }

  function renderFavourites() {
    const container = $("favourites-list");
    if (!container) return;
    if (!favourites.length) {
      container.innerHTML = "<p class='o-fav-empty'>No saved orders yet.</p>";
      return;
    }
    container.innerHTML = favourites.map((fav, i) => `
      <div class="o-fav-item">
        <div>
          <span class="o-fav-item__name">${esc(fav.name)}</span>
          <span class="o-fav-item__meta"> · ${fav.items.length} item(s)</span>
        </div>
        <button class="o-fav-reorder" data-idx="${i}">Order again</button>
      </div>`).join("");
    container.querySelectorAll(".o-fav-reorder").forEach(btn => {
      btn.addEventListener("click", () => {
        const fav = favourites[parseInt(btn.dataset.idx)];
        if (!fav) return;
        cart = {};
        fav.items.forEach(it => {
          const menuItem = findItem(it.id);
          if (menuItem) cart[it.id] = { item: menuItem, qty: it.quantity };
        });
        syncCart();
        renderMenu();
        openCart();
        showToast("Favourite order loaded!");
      });
    });
  }

  const saveFavBtn = $("save-fav-btn");
  if (saveFavBtn) {
    saveFavBtn.addEventListener("click", () => {
      const name = $("customer-name")?.value.trim() || "My Order";
      saveFavourite(name);
    });
  }

  renderFavourites();
});

window.addEventListener("resize", setNavH);
