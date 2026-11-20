from __future__ import annotations

from pathlib import Path
from typing import Annotated

from alembic.config import Config
from alembic.script import ScriptDirectory
from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from functools import lru_cache

from app.core.config import get_settings
from app.db import runtime_guard
from app.db.session import get_db
from app.schemas.health import HealthResponse

router = APIRouter(tags=["health"])


import logging

logger = logging.getLogger(__name__)


def _script_directory() -> ScriptDirectory:
    backend = Path(__file__).resolve().parents[3]
    config = Config()
    config.set_main_option("script_location", str(backend / "alembic"))
    return ScriptDirectory.from_config(config)


@lru_cache(maxsize=1)
def expected_migration_heads() -> frozenset[str]:
    """Parsed once per process; the scripts cannot change under a running image (HONEY-034)."""
    return frozenset(_script_directory().get_heads())


@lru_cache(maxsize=1)
def known_migration_revisions() -> frozenset[str]:
    """Every revision this image ships (its head and all ancestors)."""
    return frozenset(r.revision for r in _script_directory().walk_revisions())


def schema_is_compatible(actual: set[str]) -> bool:
    """Can this image serve against a database at revision ``actual``?

    * At this image's head: yes.
    * At a revision this image knows but is not its head: the database is BEHIND this code
      (migrations not applied yet): no.
    * At revisions this image does not know at all: a newer release has already migrated the
      database. Migrations are expand-first (docs/database_migration_runbook.md), so this image
      keeps working until it is replaced: yes. Refusing here made every old pod unready the
      moment a rolling upgrade's migration finished, leaving the edge with no backend (HTTP 502).
    """
    if actual == expected_migration_heads():
        return True
    if actual and actual.isdisjoint(known_migration_revisions()):
        logger.info("Database schema is ahead of this image (rolling upgrade in progress)")
        return True
    return False


def health_payload() -> dict[str, str]:
    return {"status": "healthy"}


@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Get service health",
    description="Reports whether the HoneyShield API is available.",
)
def health_check() -> HealthResponse:
    """Return the versioned service health payload."""
    return health_payload()


@router.get("/ready", response_model=HealthResponse, responses={503: {"model": HealthResponse}})
def readiness(session: Annotated[Session, Depends(get_db)]):
    """Check connectivity and migration revision; liveness remains DB-free."""
    try:
        # Minimal low-overhead connectivity check (F-017 / Phase 9)
        session.execute(text("SELECT 1"))

        actual = set(session.execute(text("SELECT version_num FROM alembic_version")).scalars())
        if not schema_is_compatible(actual):
            return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"status": "not_ready"})
        if get_settings().db_least_privilege_enforced:
            runtime_guard.ensure_least_privilege(session.get_bind())
    except (SQLAlchemyError, Exception) as exc:
        logger.warning("Readiness probe check failed: %s", type(exc).__name__)
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"status": "not_ready"})
    return {"status": "ready"}
