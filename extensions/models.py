"""Legacy compatibility shim.

These models were migrated to ``app.models`` (app/models/staff.py).
Re-exported here so any extension blueprint that does
``from extensions.models import TableCall`` keeps working without
re-registering the SQLAlchemy table against the shared MetaData
(which caused "Table already defined" crashes at startup).
"""
from __future__ import annotations

from app.models import (
    Customer,
    Employee,
    OrderEmployeeAssignment,
    TableCall,
)

__all__ = ["Customer", "Employee", "OrderEmployeeAssignment", "TableCall"]
