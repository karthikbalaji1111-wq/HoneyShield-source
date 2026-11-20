"""Evidence-integrity verification (TENANT_ADMIN for own tenant; SYSTEM_ADMIN any tenant)."""
from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Query
from sqlalchemy import select

from app.api.dependencies import SessionDependency, TenantAdminRequired
from app.core.exceptions import TenantNotFoundError, ValidationError
from app.db.session import set_query_timeout
from app.models.enums import Role
from app.models.tenant import Tenant
from app.services import evidence

router = APIRouter(prefix="/evidence", tags=["evidence"])


@router.get("/verify", summary="Verify the tenant's evidence hash chain")
def verify(session: SessionDependency, user: TenantAdminRequired,
           tenant_slug: Annotated[str | None, Query(max_length=100)] = None) -> dict[str, Any]:
    if user.role == Role.SYSTEM_ADMIN:
        if not tenant_slug:
            raise ValidationError("tenant_slug is required for SYSTEM_ADMIN")
        tenant = session.scalar(select(Tenant).where(Tenant.slug == tenant_slug))
        if tenant is None:
            raise TenantNotFoundError("Tenant not found")
        tenant_id = tenant.id
    else:
        tenant_id = user.tenant_id
    from app.core.config import get_settings
    with set_query_timeout(session, get_settings().db_analytics_timeout_ms):
        result = evidence.verify_tenant(session, tenant_id)
    out = evidence.result_dict(result)
    out["note"] = ("Verification proves internal consistency. Compare head_seq/head_hash with an externally "
                   "stored checkpoint to detect a chain rewritten by a database administrator.")
    return out
