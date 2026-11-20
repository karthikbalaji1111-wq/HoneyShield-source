from __future__ import annotations

from datetime import date

from sqlalchemy import BigInteger, Boolean, Date, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.base import BaseModel


class Tenant(BaseModel):
    __tablename__ = "tenants"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)

    projects: Mapped[list["Project"]] = relationship(
        "Project",
        back_populates="tenant",
        cascade="all, delete-orphan",
    )


class TenantEventCount(Base):
    """Exact event total per tenant, maintained by PostgreSQL triggers (migration 20261118_01).

    Read-only for the application. On SQLite (tests, development) statistics count directly.
    """

    __tablename__ = "tenant_event_counts"

    tenant_id: Mapped[int] = mapped_column(Integer, ForeignKey("tenants.id"), primary_key=True)
    total: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0, server_default="0")


class TenantDailyEventCount(Base):
    """Events per tenant, UTC day and severity, maintained by PostgreSQL triggers (20261118_03).

    Read-only for the application; feeds the activity chart in O(days). SQLite counts directly.
    """

    __tablename__ = "tenant_daily_event_counts"

    tenant_id: Mapped[int] = mapped_column(Integer, ForeignKey("tenants.id"), primary_key=True)
    day: Mapped[date] = mapped_column(Date, primary_key=True, index=True)
    severity: Mapped[str] = mapped_column(String(16), primary_key=True)
    total: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0, server_default="0")
