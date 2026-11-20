from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.alerting import router as alerting_router
from app.api.v1.api_keys import router as api_key_router
from app.api.v1.audit_logs import router as audit_log_router
from app.api.v1.detection_events import router as detection_event_router
from app.api.v1.events_stream import router as events_stream_router
from app.api.v1.evidence import router as evidence_router
from app.api.v1.health import router as health_router
from app.api.v1.system import router as system_router
from app.api.v1.users import router as user_router

from app.api.v1.honey_tokens import router as honey_token_router
from app.api.v1.integrations import router as integration_router
from app.api.v1.projects import router as project_router
from app.api.v1.tenants import router as tenant_router
from app.api.v1.threat_intelligence import router as threat_intelligence_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(tenant_router)
api_router.include_router(project_router)
api_router.include_router(honey_token_router)
api_router.include_router(detection_event_router)
api_router.include_router(events_stream_router)
api_router.include_router(threat_intelligence_router)
api_router.include_router(user_router)
api_router.include_router(integration_router)
api_router.include_router(alerting_router)
api_router.include_router(evidence_router)
api_router.include_router(audit_log_router)
api_router.include_router(api_key_router)
api_router.include_router(system_router)
