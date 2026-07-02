"""Models package — re-exports every ORM model for convenience.

Usage::

    from app.models import Owner, Order, Cafe, ...
"""
from __future__ import annotations

from app.models.core import Cafe, CafeTable, Ingredient, Menu, Owner, Settings
from app.models.orders import Feedback, OnlinePayment, Order
from app.models.billing import (
    BillingLog,
    CashDrawerCount,
    PaymentProviderCredential,
    WebhookEventLog,
)
from app.models.aggregator import AggregatorOrder, AggregatorPlatformCredential
from app.models.auth import AuditLog, Invitation, OwnerLead, RememberToken, SystemFlag
from app.models.staff import Customer, Employee, OrderEmployeeAssignment, TableCall

__all__ = [
    "Cafe",
    "CafeTable",
    "Ingredient",
    "Menu",
    "Owner",
    "Settings",
    "Order",
    "Feedback",
    "OnlinePayment",
    "BillingLog",
    "CashDrawerCount",
    "PaymentProviderCredential",
    "WebhookEventLog",
    "AggregatorOrder",
    "AggregatorPlatformCredential",
    "RememberToken",
    "OwnerLead",
    "SystemFlag",
    "Invitation",
    "AuditLog",
    "Customer",
    "Employee",
    "OrderEmployeeAssignment",
    "TableCall",
]
