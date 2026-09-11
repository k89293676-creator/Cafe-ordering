"""POS enhancements: Loyalty, KDS, Split/Merge, Purchase Orders — Toast/Square parity."""
from __future__ import annotations
import secrets
from datetime import datetime, timedelta, timezone
from flask import Blueprint, flash, jsonify, redirect, render_template, request, session, url_for
from sqlalchemy import func as _f

from app.extensions import db, limiter
from app.services.auth import logged_in_owner_id, logged_in_owner_obj
from app.utils.security import login_required, log_security

bp = Blueprint("pos", __name__)

# ── Loyalty ────────────────────────────────────────────────────────────────

def _ensure_loyalty_account(owner_id: int, phone: str, name: str = "", email: str = ""):
    from app.models.pos import LoyaltyAccount
    phone = (phone or "").strip()[:30]
    if not phone:
        return None
    acc = LoyaltyAccount.query.filter_by(owner_id=owner_id, customer_phone=phone).first()
    if not acc:
        acc = LoyaltyAccount(owner_id=owner_id, customer_phone=phone, customer_name=name, customer_email=email, points=0)
        db.session.add(acc)
        db.session.flush()
    return acc

def _tier_for_points(p: int) -> str:
    if p >= 5000: return "platinum"
    if p >= 2000: return "gold"
    if p >= 500: return "silver"
    return "bronze"

@bp.route("/owner/loyalty", methods=["GET"])
@login_required
def loyalty_dashboard():
    from app.models.pos import LoyaltyAccount
    owner_id = logged_in_owner_id()
    owner = logged_in_owner_obj()
    q = (request.args.get("q") or "").strip().lower()[:64]
    query = LoyaltyAccount.query.filter_by(owner_id=owner_id)
    if q:
        query = query.filter((LoyaltyAccount.customer_phone.ilike(f"%{q}%")) | (LoyaltyAccount.customer_name.ilike(f"%{q}%")))
    accounts = query.order_by(LoyaltyAccount.points.desc()).limit(200).all()
    # stats
    total_members = LoyaltyAccount.query.filter_by(owner_id=owner_id).count()
    total_points = db.session.query(_f.coalesce(_f.sum(LoyaltyAccount.points),0)).filter_by(owner_id=owner_id).scalar() or 0
    tiers = {"bronze":0,"silver":0,"gold":0,"platinum":0}
    for a in LoyaltyAccount.query.filter_by(owner_id=owner_id).all():
        tiers[_tier_for_points(a.points or 0)] += 1
    return render_template("pos/loyalty.html", owner=owner, accounts=accounts, q=q, total_members=total_members, total_points=int(total_points), tiers=tiers, owner_username=owner.username if owner else "")

@bp.route("/owner/loyalty/adjust", methods=["POST"])
@login_required
@limiter.limit("60 per hour")
def loyalty_adjust():
    from app.models.pos import LoyaltyAccount, LoyaltyTransaction
    owner_id = logged_in_owner_id()
    phone = (request.form.get("phone") or "").strip()[:30]
    delta_raw = request.form.get("delta") or "0"
    reason = (request.form.get("reason") or "").strip()[:200]
    try:
        delta = int(delta_raw)
    except: 
        flash("Invalid points amount.", "error")
        return redirect(url_for("pos.loyalty_dashboard"))
    if not phone or delta == 0:
        flash("Phone and non-zero delta required.", "error")
        return redirect(url_for("pos.loyalty_dashboard"))
    acc = _ensure_loyalty_account(owner_id, phone)
    if not acc:
        flash("Invalid phone.", "error")
        return redirect(url_for("pos.loyalty_dashboard"))
    acc.points = max(0, (acc.points or 0) + delta)
    acc.tier = _tier_for_points(acc.points)
    db.session.add(LoyaltyTransaction(owner_id=owner_id, account_id=acc.id, points=delta, type="adjust", reason=reason))
    db.session.commit()
    log_security("LOYALTY_ADJUST", f"phone={phone} delta={delta}")
    flash(f"{'Added' if delta>0 else 'Deducted'} {abs(delta)} points for {phone}. Now {acc.points} ({acc.tier}).", "success")
    return redirect(url_for("pos.loyalty_dashboard"))

@bp.route("/api/loyalty/lookup", methods=["GET"])
@login_required
def loyalty_lookup():
    from app.models.pos import LoyaltyAccount
    owner_id = logged_in_owner_id()
    phone = (request.args.get("phone") or "").strip()[:30]
    if not phone:
        return jsonify(ok=False, error="phone required"), 400
    acc = LoyaltyAccount.query.filter_by(owner_id=owner_id, customer_phone=phone).first()
    if not acc:
        return jsonify(ok=True, found=False, points=0, tier="bronze")
    return jsonify(ok=True, found=True, points=acc.points, tier=acc.tier, name=acc.customer_name)

# Earn on order completion — called from order status flow
def loyalty_earn_for_order(owner_id: int, order_id: int, customer_phone: str, total: float):
    if not customer_phone or not total:
        return
    try:
        from app.models.pos import LoyaltyAccount, LoyaltyTransaction
        # 1 point per ₹1 (or $1) — rounded down
        points = int(float(total) // 1)
        if points <=0:
            return
        acc = _ensure_loyalty_account(owner_id, customer_phone)
        if not acc:
            return
        acc.points = (acc.points or 0) + points
        acc.total_spent = float(acc.total_spent or 0) + float(total)
        acc.visit_count = (acc.visit_count or 0) + 1
        acc.tier = _tier_for_points(acc.points)
        db.session.add(LoyaltyTransaction(owner_id=owner_id, account_id=acc.id, order_id=order_id, points=points, type="earn", reason=f"order #{order_id}"))
        db.session.commit()
    except Exception:
        try: db.session.rollback()
        except: pass

# ── KDS (Kitchen Display) ────────────────────────────────────────────────
# Consolidated on templates/kitchen.html (the advanced view: filters+counts,
# sort, WebAudio chimes, table-calls sidebar, KOT print, urgency bars).
# /owner/kds is kept as a redirect so old bookmarks keep working; the
# /api/kds/* JSON endpoints stay for backward compatibility.

@bp.route("/owner/kds", methods=["GET"])
@login_required
def kds_view():
    return redirect(url_for("web_owner.kitchen"))

@bp.route("/api/kds/orders", methods=["GET"])
@login_required
def kds_orders():
    from app.models import Order
    owner_id = logged_in_owner_id()
    # Active kitchen tickets: pending/preparing/ready
    orders = Order.query.filter(Order.owner_id==owner_id, Order.status.in_(["pending","preparing","ready"])).order_by(Order.created_at.asc()).all()
    now = datetime.now(timezone.utc)
    out=[]
    for o in orders:
        created = o.created_at
        if created and created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        age_s = int((now - created).total_seconds()) if created else 0
        out.append({
            "id": o.id, "tableId": o.table_id or "", "tableName": o.table_name or o.table_id or "Counter",
            "customerName": o.customer_name or "Guest", "status": o.status, "items": o.items or [],
            "total": float(o.total or 0), "createdAt": o.created_at.isoformat() if o.created_at else None,
            "ageSeconds": age_s, "ageLabel": f"{age_s//60}m {age_s%60}s" if age_s>60 else f"{age_s}s",
            "isStuck": age_s > 900, # 15 min
        })
    return jsonify(ok=True, orders=out, count=len(out))

@bp.route("/api/kds/orders/<int:order_id>/bump", methods=["POST"])
@login_required
def kds_bump(order_id: int):
    from app.models import Order
    owner_id = logged_in_owner_id()
    order = Order.query.filter_by(id=order_id, owner_id=owner_id).first()
    if not order:
        return jsonify(ok=False, error="not found"), 404
    # Bump: move to next status or completed
    nxt = {"pending":"preparing","preparing":"ready","ready":"completed"}.get(order.status or "pending", "completed")
    order.status = nxt
    db.session.commit()
    log_security("KDS_BUMP", f"order_id={order_id} -> {nxt}")
    return jsonify(ok=True, status=nxt)

# ── Split / Merge ────────────────────────────────────────────────────────
# NOTE: lives under /owner/orders/* (not /owner/billing/*) — split posts a
# form to this endpoint; the billing blueprint owns /owner/billing/*.

@bp.route("/owner/orders/<int:order_id>/split", methods=["POST"])
@login_required
def split_bill(order_id: int):
    from app.models import Order
    owner_id = logged_in_owner_id()
    order = Order.query.filter_by(id=order_id, owner_id=owner_id).first()
    if not order or order.payment_status != "unpaid":
        flash("Only unpaid tabs can be split.", "error")
        return redirect(url_for("billing.owner_billing_order_detail", order_id=order_id))
    items = order.items or []
    # Expect form: split_indices = "0,1" and new table/customer, or split_amount
    indices_raw = (request.form.get("split_indices") or "").strip()
    if not indices_raw:
        flash("Select at least one item to split.", "error")
        return redirect(url_for("billing.owner_billing_order_detail", order_id=order_id))
    try:
        idxs = [int(x.strip()) for x in indices_raw.split(",") if x.strip()!=""]
    except:
        flash("Invalid split selection.", "error")
        return redirect(url_for("billing.owner_billing_order_detail", order_id=order_id))
    idxs = [i for i in idxs if 0 <= i < len(items)]
    if not idxs:
        flash("No valid items selected.", "error")
        return redirect(url_for("billing.owner_billing_order_detail", order_id=order_id))
    # Create new order with selected items
    remaining = [it for j,it in enumerate(items) if j not in idxs]
    moving = [items[j] for j in idxs]
    if not moving or not remaining:
        flash("Splitting must leave at least one item in each tab.", "error")
        return redirect(url_for("billing.owner_billing_order_detail", order_id=order_id))
    try:
        # Compute totals
        def _sum(its): return round(sum(float(it.get("price",0))*int(it.get("quantity",1)) for it in its),2)
        move_total = _sum(moving)
        remain_total = _sum(remaining)
        # Update original
        order.items = remaining
        order.total = remain_total
        order.subtotal = remain_total
        # New order
        new_order = Order(
            owner_id=owner_id, cafe_id=order.cafe_id, table_id=order.table_id, table_name=(order.table_name or "") + " (split)",
            customer_name=request.form.get("customer_name") or order.customer_name or "Guest",
            customer_phone=order.customer_phone, customer_email=order.customer_email,
            items=moving, total=move_total, subtotal=move_total, status="pending",
            payment_status="unpaid", origin="split"
        )
        db.session.add(new_order)
        db.session.flush()
        db.session.commit()
        log_security("BILL_SPLIT", f"order_id={order_id} new_id={new_order.id} items={idxs}")
        flash(f"Split {len(moving)} item(s) to new tab #{new_order.id} — {len(remaining)} remain in #{order_id}.", "success")
        return redirect(url_for("billing.owner_billing_order_detail", order_id=new_order.id))
    except Exception as e:
        try: db.session.rollback()
        except: pass
        flash(f"Split failed: {e}", "error")
        return redirect(url_for("billing.owner_billing_order_detail", order_id=order_id))

@bp.route("/owner/tables/merge", methods=["POST"])
@login_required
def merge_tables():
    from app.models import Order
    owner_id = logged_in_owner_id()
    left_id = request.form.get("left_table") or ""
    right_id = request.form.get("right_table") or ""
    if not left_id or not right_id or left_id==right_id:
        flash("Pick two different tables to merge.", "error")
        return redirect(url_for("tables_overview.view"))
    # Find open orders on each table
    left_order = Order.query.filter_by(owner_id=owner_id, table_id=left_id, payment_status="unpaid").filter(Order.status.notin_(["cancelled","voided","completed"])).order_by(Order.created_at.desc()).first()
    right_order = Order.query.filter_by(owner_id=owner_id, table_id=right_id, payment_status="unpaid").filter(Order.status.notin_(["cancelled","voided","completed"])).order_by(Order.created_at.desc()).first()
    if not left_order or not right_order:
        flash("Both tables need an open tab to merge.", "error")
        return redirect(url_for("tables_overview.view"))
    try:
        merged_items = (left_order.items or []) + (right_order.items or [])
        left_order.items = merged_items
        left_order.total = round(sum(float(it.get("price",0))*int(it.get("quantity",1)) for it in merged_items),2)
        left_order.subtotal = left_order.total
        left_order.table_name = (left_order.table_name or left_id) + f" + {right_order.table_name or right_id}"
        db.session.delete(right_order)
        db.session.commit()
        log_security("TABLE_MERGE", f"left={left_id} right={right_id} into {left_order.id}")
        flash(f"Merged table {right_id} into {left_id} — tab #{left_order.id} now has {len(merged_items)} items.", "success")
    except Exception as e:
        try: db.session.rollback()
        except: pass
        flash(f"Merge failed: {e}", "error")
    return redirect(url_for("tables_overview.view"))

# ── Purchase Orders ──────────────────────────────────────────────────────

@bp.route("/owner/purchasing", methods=["GET"])
@login_required
def purchasing_dashboard():
    from app.models.pos import PurchaseOrder, Supplier
    owner_id = logged_in_owner_id()
    owner = logged_in_owner_obj()
    pos = PurchaseOrder.query.filter_by(owner_id=owner_id).order_by(PurchaseOrder.created_at.desc()).limit(50).all()
    suppliers = Supplier.query.filter_by(owner_id=owner_id).all()
    # low stock ingredients for quick PO
    from app.models import Ingredient
    low = Ingredient.query.filter(Ingredient.owner_id==owner_id, Ingredient.stock <= Ingredient.low_stock_threshold).all()
    return render_template("pos/purchasing.html", owner=owner, pos=pos, suppliers=suppliers, low_stock=low, owner_username=owner.username if owner else "")

@bp.route("/owner/purchasing/suppliers", methods=["POST"])
@login_required
def purchasing_add_supplier():
    from app.models.pos import Supplier
    owner_id = logged_in_owner_id()
    name = (request.form.get("name") or "").strip()[:100]
    if not name:
        flash("Supplier name required.", "error")
        return redirect(url_for("pos.purchasing_dashboard"))
    s = Supplier(owner_id=owner_id, name=name, contact=(request.form.get("contact") or "")[:100], phone=(request.form.get("phone") or "")[:30])
    db.session.add(s)
    db.session.commit()
    flash(f"Supplier {name} added.", "success")
    return redirect(url_for("pos.purchasing_dashboard"))

@bp.route("/owner/purchasing/create", methods=["POST"])
@login_required
def purchasing_create():
    from app.models.pos import PurchaseOrder, PurchaseOrderItem
    from app.models import Ingredient
    owner_id = logged_in_owner_id()
    supplier_name = (request.form.get("supplier_name") or "").strip()[:100]
    notes = (request.form.get("notes") or "").strip()[:500]
    po = PurchaseOrder(owner_id=owner_id, supplier_name=supplier_name, notes=notes, status="draft", total_cost=0)
    db.session.add(po)
    db.session.flush()
    total=0.0
    # Auto-add low stock items if requested
    if request.form.get("auto_low")=="on":
        low = Ingredient.query.filter(Ingredient.owner_id==owner_id, Ingredient.stock <= Ingredient.low_stock_threshold).all()
        for ing in low[:20]:
            qty = max(0, float(ing.low_stock_threshold or 5)*2 - float(ing.stock or 0))
            qty = round(qty,3)
            if qty<=0: continue
            cost = float(ing.cost_per_unit or 0)
            line = round(qty*cost,2)
            db.session.add(PurchaseOrderItem(po_id=po.id, ingredient_id=ing.id, ingredient_name=ing.name, quantity=qty, unit=ing.unit or "unit", unit_cost=cost, line_total=line))
            total+=line
    po.total_cost = round(total,2)
    db.session.commit()
    flash(f"PO #{po.id} created — {len(po.id and [] )} items.", "success")
    return redirect(url_for("pos.purchasing_dashboard"))

@bp.route("/owner/purchasing/<int:po_id>/receive", methods=["POST"])
@login_required
def purchasing_receive(po_id: int):
    from app.models.pos import PurchaseOrder, PurchaseOrderItem
    from app.models import Ingredient
    owner_id = logged_in_owner_id()
    po = PurchaseOrder.query.filter_by(id=po_id, owner_id=owner_id).first()
    if not po or po.status not in ("draft","ordered"):
        flash("PO not receivable.", "error")
        return redirect(url_for("pos.purchasing_dashboard"))
    # Mark received and bump stock
    for item in PurchaseOrderItem.query.filter_by(po_id=po.id).all():
        ing = db.session.get(Ingredient, item.ingredient_id) if item.ingredient_id else Ingredient.query.filter_by(owner_id=owner_id, name=item.ingredient_name).first()
        if ing:
            ing.stock = float(ing.stock or 0) + float(item.quantity or 0)
    po.status = "received"
    po.received_at = datetime.now(timezone.utc)
    db.session.commit()
    flash(f"PO #{po.id} received — stock updated.", "success")
    return redirect(url_for("pos.purchasing_dashboard"))

# ── Staff roles / clock ──────────────────────────────────────────────────

@bp.route("/owner/staff/clock", methods=["POST"])
@login_required
def staff_clock():
    # Minimal clock-in/out stub — logs to audit, Toast parity for tip pooling prep
    action = (request.form.get("action") or "").strip()  # in/out
    pin = (request.form.get("pin") or "").strip()[:10]
    from app.models.staff import Employee
    owner_id = logged_in_owner_id()
    # Find employee by pin
    emp = Employee.query.filter_by(owner_id=owner_id, pin_code=pin).first() if pin else None
    who = emp.name if emp else "Owner"
    log_security("STAFF_CLOCK", f"{who} {action} pin={bool(pin)}")
    flash(f"{who} clocked {action}.", "success" if action in ("in","out") else "info")
    return redirect(request.referrer or url_for("employees.view"))
