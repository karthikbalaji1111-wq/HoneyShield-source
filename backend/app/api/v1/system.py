"""System health for system administrators: the watchdog's latest checks and the backup status."""
from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.dependencies import SystemAdminRequired
from app.db.session import get_db
from app.schemas.base import SchemaBase
from app.services.system_status import age_seconds, all_statuses

router = APIRouter(prefix="/system", tags=["health"])


class SystemStatusResponse(SchemaBase):
    watchdog: dict[str, Any] | None = None
    watchdog_age_seconds: int | None = None
    backup: dict[str, Any] | None = None
    checkpoint: dict[str, Any] | None = None


@router.get("/status", response_model=SystemStatusResponse,
            summary="Latest watchdog checks and backup status (system administrators)")
def system_status(_admin: SystemAdminRequired, session: Annotated[Session, Depends(get_db)]) -> SystemStatusResponse:
    rows = all_statuses(session)
    watchdog = rows.get("watchdog")
    age = age_seconds(watchdog)
    # The rows hold no secrets (file names, times, bucket/prefix location), so they are returned as is.
    backup = dict(rows["backup"].value) if "backup" in rows else None
    return SystemStatusResponse(
        watchdog=dict(watchdog.value) if watchdog else None,
        watchdog_age_seconds=int(age) if age is not None else None,
        backup=backup,
        checkpoint=dict(rows["checkpoint"].value) if "checkpoint" in rows else None,
    )
