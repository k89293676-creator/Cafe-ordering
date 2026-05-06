"""Feedback API — /api/v1/feedback."""
from __future__ import annotations

import re

from flask import Blueprint, abort, jsonify, request

from app.extensions import limiter
from app.services.orders import save_feedback_entry
from app.services.tables import load_tables
from app.services.orders import _db_get_order
from app.utils.security import api_login_required
from app.utils.serializers import _safe_text

bp = Blueprint("api_v1_feedback", __name__)


@bp.route("/api/v1/feedback", methods=["POST"])
@bp.route("/api/feedback", methods=["POST"])
@limiter.limit("5 per minute; 20 per hour")
def submit_feedback():
    if not request.is_json:
        abort(400, description="JSON required.")
    payload = request.get_json(silent=True) or {}
    table_id = _safe_text(payload.get("tableId"), max_len=64) or None
    customer_name = _safe_text(payload.get("customerName"), max_len=100, default="Guest")
    order_id = payload.get("orderId")
    rating = payload.get("rating")
    comment = _safe_text(payload.get("comment"), max_len=1000)

    try:
        rating = int(rating)
        if rating < 1 or rating > 5:
            raise ValueError
    except (TypeError, ValueError):
        abort(400, description="Rating must be an integer between 1 and 5.")

    owner_id = None
    cafe_id = None
    if table_id and re.fullmatch(r"[a-zA-Z0-9\-]{1,64}", table_id):
        table = next((t for t in load_tables() if t["id"] == table_id), None)
        if table:
            owner_id = table.get("ownerId")
            cafe_id = table.get("cafeId")

    if order_id:
        order = _db_get_order(int(order_id))
        if order:
            owner_id = owner_id or order.get("ownerId")
            cafe_id = cafe_id or order.get("cafeId")

    entry = {
        "ownerId": owner_id,
        "cafeId": cafe_id,
        "orderId": int(order_id) if order_id else None,
        "tableId": table_id,
        "customerName": customer_name,
        "rating": rating,
        "comment": comment,
    }
    saved = save_feedback_entry(entry)
    return {"message": "Thank you for your feedback!", "feedback": saved}, 201


@bp.route("/api/v1/feedback/summary")
@bp.route("/api/feedback/summary")
@api_login_required
def feedback_summary():
    from app.models import Feedback
    from app.services.auth import logged_in_owner_id
    owner_id = logged_in_owner_id()
    feedback_list = Feedback.query.filter_by(owner_id=owner_id).all()
    avg = 0.0
    if feedback_list:
        avg = round(sum(f.rating for f in feedback_list) / len(feedback_list), 1)
    breakdown = {str(i): sum(1 for f in feedback_list if f.rating == i) for i in range(1, 6)}
    return jsonify(average=avg, count=len(feedback_list), breakdown=breakdown)
