"""Audit history for investigators (M13). TENANT_ADMIN: own tenant. SYSTEM_ADMIN: all."""
from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Query
from pydantic import Field
from sqlalchemy import select

from app.api.dependencies import SessionDependency, SystemAdminRequired, TenantAdminRequired
from app.models.audit_log import AuditLog
from app.models.enums import Role
from app.schemas.base import SchemaBase

router = APIRouter(prefix="/audit-logs", tags=["audit"])


class AuditLogResponse(SchemaBase):
    id: int
    event_type: str
    severity: str
    message: str
    actor_source: str | None
    actor_user_id: int | None
    target_entity: str | None
    target_id: str | None
    tenant_id: int | None
    project_id: int | None
    metadata: dict[str, Any] | None = Field(validation_alias="event_metadata")
    created_at: datetime


@router.get("", response_model=list[AuditLogResponse], summary="List audit records (newest first)")
def list_audit_logs(
    session: SessionDependency,
    user: TenantAdminRequired,
    event_type: Annotated[str | None, Query(max_length=100)] = None,
    before_id: Annotated[int | None, Query(ge=1, description="Keyset cursor: records older than this id")] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
):
    stmt = select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)
    if user.role != Role.SYSTEM_ADMIN:
        stmt = stmt.where(AuditLog.tenant_id == user.tenant_id)
    if event_type:
        stmt = stmt.where(AuditLog.event_type == event_type)
    if before_id:
        stmt = stmt.where(AuditLog.id < before_id)
    return list(session.scalars(stmt))


@router.get("/verify", summary="Verify the audit log hash chain (SYSTEM_ADMIN)")
def verify_audit_chain(session: SessionDependency, user: SystemAdminRequired) -> dict[str, Any]:
    from app.core.config import get_settings
    from app.db.session import set_query_timeout
    from app.services import audit_chain

    with set_query_timeout(session, get_settings().db_analytics_timeout_ms):
        result = audit_chain.verify(session)
    out = audit_chain.result_dict(result)
    out["note"] = ("Records are sealed by the checkpointer; unsealed_records are recent records not yet "
                   "chained. Compare head_seq/head_hash with an exported checkpoint to detect a chain "
                   "rewritten by a database administrator.")
    return out
