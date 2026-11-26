"""Version 1 honey-token API routes."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query, Response, status

from app.api.dependencies import CurrentUser, TenantAdminRequired, get_honey_token_service
from app.core.redaction import redact, token_secrets, viewer_sees_secrets
from app.schemas.error import ErrorResponse
from app.schemas.honey_token import (
    HoneyTokenCreate,
    HoneyTokenResponse,
    HoneyTokenRevoke,
    HoneyTokenRotate,
)
from app.services.bait_files import kinds_for, render, with_files
from app.services.honey_token import HoneyTokenService

router = APIRouter(prefix="/honey-tokens", tags=["honey-tokens"])


@router.get(
    "/types",
    summary="Decoy types available here",
    description="Every decoy type and whether this installation can watch it (DNS and AWS key decoys "
                "need their own service).",
)
def available_types(_user: CurrentUser) -> dict[str, dict[str, bool]]:
    from app.core.config import get_settings
    from app.models.enums import HoneyTokenType

    settings = get_settings()
    needs = {HoneyTokenType.DNS: bool(settings.dns_token_zone), HoneyTokenType.AWS_KEY: settings.aws_canary_enabled,
             HoneyTokenType.DOCUMENT: bool(settings.public_ingest_base_url)}
    return {"types": {t.value: needs.get(t, True) for t in HoneyTokenType}}


@router.get(
    "/{decoy_id}/files/{kind}",
    summary="Download a decoy as a ready-to-plant file",
    description="The decoy inside a file intruders look for: aws-credentials and env (AWS key), kubeconfig, "
                "ssh-config and env (DNS), env (API key), docx (document). TENANT_ADMIN or above; every "
                "download is audited.",
    response_class=Response,
    responses={status.HTTP_404_NOT_FOUND: {"model": ErrorResponse, "description": "No such active decoy."},
               status.HTTP_422_UNPROCESSABLE_CONTENT: {"model": ErrorResponse,
                                                        "description": "This decoy has no such file."}},
)
def download_bait_file(
    decoy_id: Annotated[str, Path(max_length=40, pattern=r"^[A-Za-z0-9_-]+$")],
    kind: Annotated[str, Path(max_length=32, pattern=r"^[a-z-]+$")],
    service: Annotated[HoneyTokenService, Depends(get_honey_token_service)],
    _: TenantAdminRequired,
) -> Response:
    from urllib.parse import quote

    token = service.get_by_decoy_id(decoy_id)
    bait = render(token, kind)
    service.record_file_download(token, kind)
    ascii_name = "".join(c if (c.isascii() and c.isalnum()) or c in "._-" else "_" for c in bait.filename)
    return Response(content=bait.content, media_type=bait.content_type, headers={
        "Content-Disposition": f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(bait.filename, safe='')}",
        "Cache-Control": "no-store",
    })


@router.post(
    "",
    response_model=HoneyTokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a honey token",
    description="Creates a honey token for an existing project.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {
            "model": ErrorResponse,
            "description": "Authentication required.",
        },
        status.HTTP_403_FORBIDDEN: {
            "model": ErrorResponse,
            "description": "TENANT_ADMIN role or above required.",
        },
        status.HTTP_404_NOT_FOUND: {
            "model": ErrorResponse,
            "description": "Owning project does not exist.",
        },
        status.HTTP_409_CONFLICT: {
            "model": ErrorResponse,
            "description": "Honey-token value already exists.",
        },
        status.HTTP_422_UNPROCESSABLE_CONTENT: {
            "model": ErrorResponse,
            "description": "Request or domain validation failed.",
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "model": ErrorResponse,
            "description": "Unexpected server error.",
        },
    },
)
def create_honey_token(
    payload: HoneyTokenCreate,
    service: Annotated[HoneyTokenService, Depends(get_honey_token_service)],
    _: TenantAdminRequired,
) -> HoneyTokenResponse:
    """Create and serialize a honey token. Requires TENANT_ADMIN or above."""
    return with_files(service.create_token(
        project_domain=payload.project_domain,
        token_type=payload.token_type,
        token_value=payload.token_value,
        label=payload.label,
        metadata=payload.metadata,
    ))


@router.get(
    "",
    response_model=list[HoneyTokenResponse],
    status_code=status.HTTP_200_OK,
    summary="List honey tokens",
    description="Lists honey tokens with optional project and activity filters.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {
            "model": ErrorResponse,
            "description": "Authentication required.",
        },
        status.HTTP_404_NOT_FOUND: {
            "model": ErrorResponse,
            "description": "Supplied project does not exist.",
        },
        status.HTTP_422_UNPROCESSABLE_CONTENT: {
            "model": ErrorResponse,
            "description": "Request or domain validation failed.",
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "model": ErrorResponse,
            "description": "Unexpected server error.",
        },
    },
)
def list_honey_tokens(
    service: Annotated[HoneyTokenService, Depends(get_honey_token_service)],
    user: CurrentUser,
    project_domain: Annotated[
        str | None,
        Query(
            max_length=253,
            description="Optional project domain used to scope results.",
        ),
    ] = None,
    active_only: Annotated[
        bool,
        Query(description="Whether to exclude revoked tokens."),
    ] = True,
    limit: Annotated[
        int,
        Query(ge=1, le=100, description="Maximum number of honey tokens to return."),
    ] = 50,
    offset: Annotated[
        int,
        Query(ge=0, description="Number of honey tokens to skip."),
    ] = 0,
) -> list[HoneyTokenResponse]:
    """List and serialize honey tokens. TENANT_USER viewers see masked values."""
    tokens = service.list_tokens(
        project_domain=project_domain,
        active_only=active_only,
        limit=limit,
        offset=offset,
    )
    last_hits = _last_triggered(service.session, [t.id for t in tokens])
    unmasked = viewer_sees_secrets(user)
    out = []
    for token in tokens:
        view = HoneyTokenResponse.model_validate(token)
        view.last_triggered_at = last_hits.get(token.id)
        if unmasked and token.is_active:
            view.files = kinds_for(token)
        if not unmasked:
            for secret in token_secrets(token):
                view.token_value = redact(view.token_value, secret)
                view.metadata = redact(view.metadata, secret)
        out.append(view)
    return out


def _last_triggered(session, token_ids: list[int]) -> dict:
    """Latest trigger per decoy. A correlated max() per token is answered from the
    (honey_token_id, triggered_at) index by reading one entry, however many events a decoy has;
    a GROUP BY over the same rows would read every event of a hot decoy."""
    if not token_ids:
        return {}
    from sqlalchemy import func, select
    from app.models.detection_event import DetectionEvent
    from app.models.honey_token import HoneyToken
    latest = (select(func.max(DetectionEvent.triggered_at))
              .where(DetectionEvent.honey_token_id == HoneyToken.id).scalar_subquery())
    rows = session.execute(select(HoneyToken.id, latest).where(HoneyToken.id.in_(token_ids)))
    return {tid: ts for tid, ts in rows if ts is not None}


@router.post(
    "/revoke",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke a honey token",
    description="Marks an existing honey token as inactive.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {
            "model": ErrorResponse,
            "description": "Authentication required.",
        },
        status.HTTP_403_FORBIDDEN: {
            "model": ErrorResponse,
            "description": "TENANT_ADMIN role or above required.",
        },
        status.HTTP_404_NOT_FOUND: {
            "model": ErrorResponse,
            "description": "Honey token does not exist.",
        },
        status.HTTP_422_UNPROCESSABLE_CONTENT: {
            "model": ErrorResponse,
            "description": "Request or domain validation failed.",
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "model": ErrorResponse,
            "description": "Unexpected server error.",
        },
    },
)
def revoke_honey_token(
    payload: HoneyTokenRevoke,
    service: Annotated[HoneyTokenService, Depends(get_honey_token_service)],
    _: TenantAdminRequired,
) -> None:
    """Revoke a honey token. Requires TENANT_ADMIN or above."""
    service.revoke_token(token_value=payload.token_value)


@router.post(
    "/rotate",
    response_model=HoneyTokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Rotate a honey token",
    description="Atomically revokes a token and creates its replacement.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {
            "model": ErrorResponse,
            "description": "Authentication required.",
        },
        status.HTTP_403_FORBIDDEN: {
            "model": ErrorResponse,
            "description": "TENANT_ADMIN role or above required.",
        },
        status.HTTP_404_NOT_FOUND: {
            "model": ErrorResponse,
            "description": "Existing honey token does not exist.",
        },
        status.HTTP_409_CONFLICT: {
            "model": ErrorResponse,
            "description": "Replacement honey-token value already exists.",
        },
        status.HTTP_422_UNPROCESSABLE_CONTENT: {
            "model": ErrorResponse,
            "description": "Request or domain validation failed.",
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "model": ErrorResponse,
            "description": "Unexpected server error.",
        },
    },
)
def rotate_honey_token(
    payload: HoneyTokenRotate,
    service: Annotated[HoneyTokenService, Depends(get_honey_token_service)],
    _: TenantAdminRequired,
) -> HoneyTokenResponse:
    """Rotate and serialize a honey token. Requires TENANT_ADMIN or above."""
    return with_files(service.rotate_token(
        old_token_value=payload.old_token_value,
        new_token_value=payload.new_token_value,
    ))
