"""User management endpoints."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, status

from app.api.dependencies import TenantAdminRequired, get_user_service
from app.schemas.user import (
    MfaResetRequest,
    PasswordResetIssued,
    PasswordResetIssueRequest,
    UserCreate,
    UserResponse,
    UserUpdate,
)
from app.services.user_service import UserService

router = APIRouter(prefix="/users", tags=["users"])

UserServiceDep = Annotated[UserService, Depends(get_user_service)]


@router.get(
    "",
    response_model=list[UserResponse],
    status_code=status.HTTP_200_OK,
    summary="List users",
    description="List users. SYSTEM_ADMIN retrieves all users; TENANT_ADMIN retrieves users in their tenant.",
)
def list_users(
    _admin: TenantAdminRequired,
    user_service: UserServiceDep,
    limit: Annotated[
        int,
        Query(ge=1, le=100, description="Maximum number of users to return."),
    ] = 50,
    offset: Annotated[
        int,
        Query(ge=0, description="Number of users to skip."),
    ] = 0,
) -> list[UserResponse]:
    """Retrieve all accessible users."""
    return user_service.list_users(limit=limit, offset=offset)


@router.get(
    "/{user_id}",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Get user",
    description="Retrieve a single user. Returns 404 if the user doesn't exist or belongs to another tenant.",
)
def get_user(
    user_id: int,
    _admin: TenantAdminRequired,
    user_service: UserServiceDep,
) -> UserResponse:
    """Retrieve a single user."""
    return user_service.get_user(user_id)


@router.post(
    "",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create user",
    description="Create a new user. TENANT_ADMIN can only create users within their own tenant.",
)
def create_user(
    body: UserCreate,
    _admin: TenantAdminRequired,
    user_service: UserServiceDep,
) -> UserResponse:
    """Create a new user."""
    return user_service.create_user(body)


@router.patch(
    "/{user_id}",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Update user",
    description="Update an existing user.",
)
def update_user(
    user_id: int,
    body: UserUpdate,
    _admin: TenantAdminRequired,
    user_service: UserServiceDep,
) -> UserResponse:
    """Update an existing user."""
    return user_service.update_user(user_id, body)


@router.post(
    "/{user_id}/deactivate",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Deactivate user",
    description="Deactivate a user account, instantly blocking their authentication.",
)
def deactivate_user(
    user_id: int,
    _admin: TenantAdminRequired,
    user_service: UserServiceDep,
) -> UserResponse:
    """Deactivate a user."""
    return user_service.deactivate_user(user_id)


@router.post(
    "/{user_id}/mfa/reset",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Reset a user's MFA",
    description=("Clears the user's MFA enrolment (authenticator app and passkeys; lost device) and revokes all "
                 "their sessions; they re-enrol at next login. Requires a reason (audited). Administrators "
                 "cannot reset their own MFA."),
)
def reset_user_mfa(
    user_id: int,
    body: MfaResetRequest,
    _admin: TenantAdminRequired,
    user_service: UserServiceDep,
    request: Request,
) -> UserResponse:
    from app.core.config import get_settings
    from app.core.ip_trust import extract_client_ip
    return user_service.reset_mfa(user_id, body.reason, extract_client_ip(request, get_settings()))


@router.post(
    "/{user_id}/password-reset",
    response_model=PasswordResetIssued,
    status_code=status.HTTP_201_CREATED,
    summary="Issue a single-use password reset link for a user",
    description=("Returns a link valid for 30 minutes and usable once; give it to the user out of band. "
                 "Completing it sets a new password and revokes every session; MFA is unchanged. "
                 "Requires a reason (audited). Not for your own account."),
)
def issue_password_reset(
    user_id: int,
    body: PasswordResetIssueRequest,
    _admin: TenantAdminRequired,
    user_service: UserServiceDep,
    request: Request,
) -> PasswordResetIssued:
    from app.core.config import get_settings
    from app.core.ip_trust import extract_client_ip
    url, expires = user_service.issue_password_reset(user_id, body.reason, str(request.base_url),
                                                     extract_client_ip(request, get_settings()))
    return PasswordResetIssued(reset_url=url, expires_at=expires)
