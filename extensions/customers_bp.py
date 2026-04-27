"""Customer account system — register, login, order history."""
from __future__ import annotations

import re

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from app import Order, bcrypt, db, limiter
from .models import Customer

bp = Blueprint("customers", __name__)

_EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")


def _current_customer() -> Customer | None:
    cid = session.get("customer_id")
    if not cid:
        return None
    return db.session.get(Customer, cid)


@bp.route("/customer/register", methods=["GET", "POST"])
@limiter.limit("10 per hour")
def customer_register():
    if request.method == "POST":
        name = str(request.form.get("name", "")).strip()[:100]
        email = str(request.form.get("email", "")).strip().lower()[:254]
        phone = str(request.form.get("phone", "")).strip()[:30]
        password = str(request.form.get("password", ""))
        confirm = str(request.form.get("confirm", ""))

        error = None
        if not email or not _EMAIL_RE.fullmatch(email):
            error = "Please enter a valid email address."
        elif len(password) < 6:
            error = "Password must be at least 6 characters."
        elif password != confirm:
            error = "Passwords do not match."
        elif Customer.query.filter_by(email=email).first():
            error = "An account with that email already exists."

        if error:
            flash(error, "error")
            return render_template("customer_register.html", name=name, email=email, phone=phone)

        pw_hash = bcrypt.generate_password_hash(password).decode("utf-8")
        customer = Customer(email=email, name=name, phone=phone, password_hash=pw_hash)
        db.session.add(customer)
        db.session.commit()

        session["customer_id"] = customer.id
        flash("Account created! Welcome, " + (name or email) + ".", "success")
        return redirect(url_for("customers.customer_orders"))

    return render_template("customer_register.html", name="", email="", phone="")


@bp.route("/customer/login", methods=["GET", "POST"])
@limiter.limit("20 per hour")
def customer_login():
    if request.method == "POST":
        email = str(request.form.get("email", "")).strip().lower()[:254]
        password = str(request.form.get("password", ""))

        customer = Customer.query.filter_by(email=email).first()
        if not customer or not bcrypt.check_password_hash(customer.password_hash, password):
            flash("Invalid email or password.", "error")
            return render_template("customer_login.html", email=email)

        session["customer_id"] = customer.id
        flash("Welcome back, " + (customer.name or customer.email) + "!", "success")
        return redirect(url_for("customers.customer_orders"))

    return render_template("customer_login.html", email="")


@bp.route("/customer/logout", methods=["GET", "POST"])
def customer_logout():
    session.pop("customer_id", None)
    flash("You've been logged out.", "success")
    return redirect(url_for("customers.customer_login"))


@bp.route("/customer/orders")
def customer_orders():
    customer = _current_customer()
    if not customer:
        flash("Please log in to view your orders.", "error")
        return redirect(url_for("customers.customer_login"))

    orders = (
        Order.query
        .filter(Order.customer_email == customer.email)
        .order_by(Order.created_at.desc())
        .limit(50)
        .all()
    )

    order_list = []
    for o in orders:
        order_list.append({
            "id": o.id,
            "tableName": o.table_name or "Counter",
            "status": o.status or "pending",
            "total": float(o.total or 0),
            "pickupCode": o.pickup_code or "",
            "items": o.items if isinstance(o.items, list) else [],
            "createdAt": o.created_at.isoformat() if o.created_at else "",
        })

    return render_template("customer_orders.html", customer=customer, orders=order_list, points=customer.points)
