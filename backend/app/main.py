import logging
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI
from sqlalchemy.orm import Session

from app.api.auth.oidc import router as oidc_router
from app.api.auth.router import router as auth_router
from app.api.exception_handlers import register_exception_handlers
from app.api.v1.health import health_payload, readiness as v1_readiness
from app.api.v1.router import api_router
from app.api.ingestion.integrations import router as integration_ingest_router
from app.api.metrics import router as metrics_router
from app.api.internal.replay import router as internal_replay_router
from app.api.ingestion.router import router as ingestion_router
from app.core.config import get_settings
from app.core.logging import configure_logging
from app.db import runtime_guard
from app.db.session import engine, get_db
from app.middleware import register_middlewares
from app.schemas.health import HealthResponse
from app.services.event_broadcaster import get_broadcaster

settings = get_settings()
configure_logging(settings.log_level)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for graceful shutdown of real-time streaming and database connections."""
    get_broadcaster().reset()
    get_broadcaster().start_relay()  # cross-replica live stream when REDIS_URL is set
    if settings.db_least_privilege_enforced:
        try:
            runtime_guard.ensure_least_privilege(engine)
        except runtime_guard.PrivilegedRuntimeRoleError:
            raise  # refuse to serve with a role that can rewrite evidence
        except Exception as exc:  # database not reachable yet; readiness re-checks
            logging.getLogger(__name__).warning("Startup privilege check deferred: %s", type(exc).__name__)
    yield
    get_broadcaster().shutdown()
    try:
        engine.dispose()
    except Exception:
        pass


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Versioned REST API for HoneyShield deception security services.",
    lifespan=lifespan,
    docs_url="/docs" if settings.api_docs_enabled else None,
    redoc_url="/redoc" if settings.api_docs_enabled else None,
    openapi_url="/openapi.json" if settings.api_docs_enabled else None,
    openapi_tags=[
        {"name": "service", "description": "Service availability endpoints."},
        {"name": "health", "description": "Health and readiness endpoints."},
        {"name": "tenants", "description": "Tenant management endpoints."},
        {"name": "projects", "description": "Project management endpoints."},
        {"name": "honey-tokens", "description": "Honey-token lifecycle endpoints."},
        {
            "name": "detection-events",
            "description": "Detection-event recording and retrieval endpoints.",
        },
        {
            "name": "threat-intelligence",
            "description": "Threat intelligence derived from detection-event activity.",
        },
        {
            "name": "events-stream",
            "description": "Real-time event streaming via WebSocket and SSE.",
        },
    ],
)
register_middlewares(app)
register_exception_handlers(app)
app.include_router(auth_router)
app.include_router(oidc_router)
app.include_router(api_router, prefix=settings.api_v1_prefix)
app.include_router(ingestion_router)
app.include_router(integration_ingest_router)
app.include_router(metrics_router)
app.include_router(internal_replay_router)


@app.get(
    "/",
    response_model=dict[str, str],
    status_code=200,
    tags=["service"],
    summary="Get service status",
    description="Reports that the HoneyShield service is running.",
)
def read_root() -> dict[str, str]:
    """Return the service status payload."""
    return {"service": settings.app_name, "status": "running"}


@app.get(
    "/health",
    response_model=HealthResponse,
    status_code=200,
    tags=["health"],
    summary="Get service health",
    description="Reports whether the HoneyShield API is available.",
)
def health_check() -> HealthResponse:
    """Return the Docker-compatible service health payload."""
    return health_payload()


@app.get(
    "/ready",
    response_model=HealthResponse,
    responses={503: {"model": HealthResponse}},
    status_code=200,
    tags=["health"],
    summary="Get service readiness",
    description="Reports whether the HoneyShield service and its dependencies are ready to serve traffic.",
)
def readiness_check(session: Annotated[Session, Depends(get_db)]):
    """Root-level service readiness endpoint (mirrors /api/v1/ready)."""
    return v1_readiness(session=session)
