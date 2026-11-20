"""Read and write the ``system_status`` rows (app/models/system_status.py)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.system_status import SystemStatus


def put_status(session: Session, key: str, value: dict[str, Any], *, commit: bool = True) -> None:
    """Insert or replace one component's status (an upsert, safe with several writers)."""
    now = datetime.now(timezone.utc)
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        from sqlalchemy.dialects.postgresql import insert
    else:
        from sqlalchemy.dialects.sqlite import insert
    stmt = insert(SystemStatus).values(key=key, value=value, updated_at=now)
    stmt = stmt.on_conflict_do_update(index_elements=[SystemStatus.key],
                                      set_={"value": stmt.excluded.value, "updated_at": now})
    session.execute(stmt)
    if commit:
        session.commit()


def get_status(session: Session, key: str) -> SystemStatus | None:
    return session.execute(select(SystemStatus).where(SystemStatus.key == key)).scalar_one_or_none()


def all_statuses(session: Session) -> dict[str, SystemStatus]:
    return {row.key: row for row in session.execute(select(SystemStatus)).scalars()}


def age_seconds(row: SystemStatus | None, now: datetime | None = None) -> float | None:
    if row is None:
        return None
    now = now or datetime.now(timezone.utc)
    updated = row.updated_at if row.updated_at.tzinfo else row.updated_at.replace(tzinfo=timezone.utc)
    return (now - updated).total_seconds()
