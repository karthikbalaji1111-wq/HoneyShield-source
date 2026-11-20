"""Personal API keys (any signed-in user, for their own account; admins can see and revoke keys in scope)."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Request, status
from pydantic import Field

from app.api.dependencies import CurrentUser, SessionDependency, get_audit_log_service
from app.core.auth_exceptions import ForbiddenError
from app.schemas.base import SchemaBase
from app.services import api_keys

router = APIRouter(prefix="/api-keys", tags=["api-keys"])


class ApiKeyCreate(SchemaBase):
    name: str = Field(min_length=1, max_length=100, description="What uses this key, e.g. 'CI decoy rotation'.")
    scope: Literal["read", "write"] = Field(default="read", description="'read' allows GET only.")
    expires_in_days: int = Field(default=90, ge=1, le=api_keys.MAX_DAYS)


class ApiKeyResponse(SchemaBase):
    key_id: str
    name: str
    scope: str
    owner_user_id: int
    owner_email: str | None = None
    created_at: datetime
    expires_at: datetime
    last_used_at: datetime | None
    revoked_at: datetime | None


class ApiKeyCreated(ApiKeyResponse):
    api_key: str = Field(description="Send as 'Authorization: Bearer <api_key>'. Shown once.")


def _out(k, model=ApiKeyResponse, **extra):
    return model(key_id=k.public_id, name=k.name, scope=k.scope, owner_user_id=k.user_id,
                 owner_email=k.user.email if k.user else None, created_at=k.created_at, expires_at=k.expires_at,
                 last_used_at=k.last_used_at, revoked_at=k.revoked_at, **extra)


@router.post("", response_model=ApiKeyCreated, status_code=status.HTTP_201_CREATED,
             summary="Create a personal API key (shown once)")
def create_key(body: ApiKeyCreate, user: CurrentUser, session: SessionDependency, request: Request):
    if getattr(request.state, "auth_method", None) == "api_key":  # also refused centrally
        raise ForbiddenError("API keys cannot create API keys")
    raw, key = api_keys.create(session, user, body.name, body.scope, body.expires_in_days)
    get_audit_log_service(session, user).record_action(
        event_type="API_KEY_CREATED", severity="WARNING", message=f"API key {key.public_id} created by user ID {user.id}",
        actor_source="api", actor_user_id=user.id, target_entity="api_key", target_id=key.public_id,
        tenant_id=user.tenant_id, event_metadata={"name": key.name, "scope": key.scope,
                                                  "expires_at": key.expires_at.isoformat()})
    session.commit()
    session.refresh(key)
    return _out(key, ApiKeyCreated, api_key=raw)


@router.get("", response_model=list[ApiKeyResponse], summary="List API keys (own; admins: all in scope)")
def list_keys(user: CurrentUser, session: SessionDependency):
    return [_out(k) for k in session.scalars(api_keys.visible_to(user).limit(500))]


@router.delete("/{key_id}", response_model=ApiKeyResponse, summary="Revoke an API key")
def revoke_key(key_id: str, user: CurrentUser, session: SessionDependency):
    key = api_keys.revoke(session, user, key_id)
    get_audit_log_service(session, user).record_action(
        event_type="API_KEY_REVOKED", severity="WARNING", message=f"API key {key.public_id} revoked by user ID {user.id}",
        actor_source="api", actor_user_id=user.id, target_entity="api_key", target_id=key.public_id,
        tenant_id=key.tenant_id, event_metadata={"owner_user_id": key.user_id})
    session.commit()
    return _out(key)
