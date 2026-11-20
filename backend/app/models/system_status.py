"""Operational state the background services report for the watchdog and the console.

One row per component, keyed by a short name: ``watchdog`` (latest check results and notification
state), ``selftest_probe`` (the last self-test hit the ingest path received), ``backup`` (last
backup run), ``checkpoint`` (last evidence checkpoint cycle) and ``outbox_worker`` (alert worker
heartbeat). No evidence and no secrets are stored here.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, DateTime, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class SystemStatus(Base):
    __tablename__ = "system_status"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(timezone.utc), server_default=func.now())
