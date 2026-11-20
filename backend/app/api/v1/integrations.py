"""Control-plane management of customer-integration credentials (TENANT_ADMIN or above)."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.api.dependencies import OptionalUser, SessionDependency, TenantAdminRequired, get_audit_log_service
from app.schemas.integration import (
    IntegrationCredentialCreate,
    IntegrationCredentialCreated,
    IntegrationCredentialResponse,
)
from app.services.integration import IntegrationCredentialService

router = APIRouter(prefix="/projects/{project_domain}/integrations", tags=["integrations"])


def get_integration_credential_service(session: SessionDependency, current_user: OptionalUser = None
                                       ) -> IntegrationCredentialService:
    return IntegrationCredentialService(session, current_user=current_user,
                                        audit_service=get_audit_log_service(session, current_user))


Service = Annotated[IntegrationCredentialService, Depends(get_integration_credential_service)]


def _response(cred, model=IntegrationCredentialResponse, **extra):
    return model.model_validate({
        "public_id": cred.public_id, "label": cred.label, "scopes": cred.scopes, "is_active": cred.is_active,
        "created_at": cred.created_at, "revoked_at": cred.revoked_at, "last_used_at": cred.last_used_at, **extra,
    })


@router.post("", response_model=IntegrationCredentialCreated, status_code=status.HTTP_201_CREATED,
             summary="Create an integration credential",
             description="Creates a report-only credential for the project's detection middleware. "
                         "The signing secret is returned once and cannot be retrieved again.")
def create_integration(project_domain: str, payload: IntegrationCredentialCreate, service: Service,
                       _: TenantAdminRequired):
    cred, secret = service.create(project_domain, payload.label)
    return _response(cred, IntegrationCredentialCreated, secret=secret)


@router.get("", response_model=list[IntegrationCredentialResponse], summary="List integration credentials")
def list_integrations(project_domain: str, service: Service, _: TenantAdminRequired):
    return [_response(c) for c in service.list(project_domain)]


@router.post("/{integration_id}/revoke", response_model=IntegrationCredentialResponse,
             summary="Revoke an integration credential")
def revoke_integration(project_domain: str, integration_id: str, service: Service, _: TenantAdminRequired):
    return _response(service.revoke(project_domain, integration_id))
