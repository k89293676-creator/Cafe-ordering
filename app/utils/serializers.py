"""Dict serializers for ORM models — used by routes and services."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any


def _iso(dt: datetime | None) -> str:
    if dt is None:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _parse_dt(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _safe_text(value: Any, max_len: int = 500, default: str = "") -> str:
    if value is None:
        return default
    s = str(value)
    s = "".join(ch for ch in s if ch == "\t" or ch == "\n" or (ord(ch) >= 0x20 and ord(ch) != 0x7F))
    s = s.replace("<", "").replace(">", "")
    s = s.strip()
    if max_len and len(s) > max_len:
        s = s[:max_len]
    return s or default


def _wants_json() -> bool:
    from flask import request
    if request.is_json:
        return True
    if request.path.startswith("/api/"):
        return True
    best = request.accept_mimetypes.best_match(["application/json", "text/html"])
    return best == "application/json"


def _order_dict(order: Any) -> dict:
    return {
        "id": order.id,
        "ownerId": order.owner_id,
        "cafeId": order.cafe_id,
        "tableId": order.table_id,
        "tableName": order.table_name or "",
        "customerName": order.customer_name or "Guest",
        "customerEmail": order.customer_email or "",
        "customerPhone": order.customer_phone or "",
        "customerId": order.customer_id,
        "items": order.items or [],
        "modifiers": order.modifiers or {},
        "subtotal": float(order.subtotal or 0),
        "tip": float(order.tip or 0),
        "total": float(order.total or 0),
        "discount": float(order.discount or 0),
        "tax": float(order.tax or 0),
        "serviceCharge": float(order.service_charge or 0),
        "status": order.status or "pending",
        "paymentStatus": order.payment_status or "unpaid",
        "paymentMethod": order.payment_method or "",
        "invoiceNumber": order.invoice_number or "",
        "pickupCode": order.pickup_code or "",
        "origin": order.origin or "table",
        "notes": order.notes or "",
        "voidReason": order.void_reason or "",
        "refundAmount": float(order.refund_amount or 0),
        "refundReason": order.refund_reason or "",
        "paymentsBreakdown": order.payments_breakdown or [],
        "createdAt": _iso(order.created_at),
        "updatedAt": _iso(order.updated_at),
        "paidAt": _iso(order.paid_at) if order.paid_at else None,
    }


def _owner_dict(owner: Any) -> dict:
    return {
        "id": owner.id,
        "username": owner.username,
        "email": owner.email or "",
        "cafeName": owner.cafe_name or "",
        "cafeId": owner.cafe_id,
        "isActive": owner.is_active,
        "isSuperadmin": owner.is_superadmin,
        "totpEnabled": owner.totp_enabled or False,
        "phone": owner.phone or "",
        "approvalStatus": owner.approval_status or "active",
        "planTier": owner.plan_tier or "free",
        "createdAt": _iso(owner.created_at),
    }


def _cafe_dict(cafe: Any) -> dict:
    return {
        "id": cafe.id,
        "name": cafe.name or "",
        "slug": cafe.slug or "",
        "isActive": cafe.is_active,
        "createdAt": _iso(cafe.created_at),
    }


def _feedback_dict(f: Any) -> dict:
    return {
        "id": f.id,
        "ownerId": f.owner_id,
        "cafeId": f.cafe_id,
        "orderId": f.order_id,
        "tableId": f.table_id,
        "customerName": f.customer_name or "Guest",
        "rating": int(f.rating or 0),
        "comment": f.comment or "",
        "createdAt": _iso(f.created_at),
    }


def _settings_dict(settings: Any) -> dict:
    if settings is None:
        return {
            "logoUrl": "",
            "brandColor": "#4f46e5",
            "taxRatePercent": 0,
            "taxLabel": "GST",
            "gstin": "",
            "serviceChargePercent": 0,
            "invoicePrefix": "INV",
            "billingAddress": "",
            "billingPhone": "",
        }
    return {
        "logoUrl": settings.logo_url or "",
        "brandColor": settings.brand_color or "#4f46e5",
        "taxRatePercent": float(settings.tax_rate_percent or 0),
        "taxLabel": settings.tax_label or "GST",
        "gstin": settings.gstin or "",
        "serviceChargePercent": float(settings.service_charge_percent or 0),
        "invoicePrefix": settings.invoice_prefix or "INV",
        "billingAddress": settings.billing_address or "",
        "billingPhone": settings.billing_phone or "",
    }


def _safe_redirect_target(target: str | None, fallback: str) -> str:
    from urllib.parse import urljoin, urlparse
    from flask import request
    if not target:
        return fallback
    host_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    if test_url.scheme in {"http", "https"} and test_url.netloc == host_url.netloc:
        return target
    return fallback


def _no_store(response: Any) -> Any:
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response
