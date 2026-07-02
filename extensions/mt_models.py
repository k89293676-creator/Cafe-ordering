"""Legacy compatibility shim.

These models were migrated to ``app.models`` (app/models/auth.py).
Re-exported here so any extension blueprint that does
``from extensions.mt_models import Invitation`` keeps working without
re-registering the SQLAlchemy table against the shared MetaData
(which caused "Table already defined" crashes at startup).
"""
from __future__ import annotations

from app.models import (
    AuditLog,
    Invitation,
)

__all__ = ["AuditLog", "Invitation"]
