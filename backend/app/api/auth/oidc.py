"""OIDC single sign-on endpoints (app/services/oidc.py has the protocol details)."""
from __future__ import annotations

import logging
import urllib.parse

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import Field

from app.api.dependencies import SessionDependency, get_audit_log_service
from app.core.config import get_settings
from app.core.rate_limit import login_limiter
from app.schemas.auth import TokenResponse
from app.schemas.base import SchemaBase
from app.services import oidc

router = APIRouter(prefix="/auth/oidc", tags=["auth"])
logger = logging.getLogger(__name__)
CONSOLE = "/console/"
# Only these identifiers ever reach the browser (no IdP text is reflected).
PUBLIC_ERRORS = {"session_expired", "idp_error", "idp_unreachable", "idp_denied", "invalid_token", "no_email",
                 "email_unverified", "unknown_user", "account_disabled", "mfa_required", "invalid_code",
                 "not_configured"}


class OidcConfig(SchemaBase):
    enabled: bool
    display_name: str | None = None


class OidcExchange(SchemaBase):
    code: str = Field(min_length=10, max_length=100)


def _source(request: Request) -> str:
    from app.core.ip_trust import extract_client_ip
    return extract_client_ip(request, get_settings())


def _to_console(fragment: str) -> RedirectResponse:
    resp = RedirectResponse(CONSOLE + "#" + fragment, status_code=302)
    resp.delete_cookie(oidc.COOKIE_NAME, path=oidc.COOKIE_PATH)
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


def _fail(session, request: Request, err: oidc.OidcError) -> RedirectResponse:
    code = err.code if err.code in PUBLIC_ERRORS else "idp_error"
    try:
        get_audit_log_service(session, None).record_action(
            event_type="AUTH_SSO_FAILURE", severity="WARNING", message=f"SSO sign-in failed: {code}",
            actor_source=_source(request), event_metadata={"reason": code, "detail": err.detail[:200]})
        session.commit()
    except Exception:  # noqa: BLE001
        session.rollback()
    return _to_console("sso_error=" + urllib.parse.quote(code))


@router.get("/config", response_model=OidcConfig, summary="Whether SSO is offered (for the sign-in page)")
def config() -> OidcConfig:
    s = get_settings()
    return OidcConfig(enabled=s.oidc_enabled, display_name=s.oidc_display_name if s.oidc_enabled else None)


@router.get("/login", summary="Start SSO: redirect to the identity provider")
def login(request: Request, session: SessionDependency):
    s = get_settings()
    if not s.oidc_enabled:
        raise HTTPException(status_code=404, detail="Not Found")
    try:
        url, cookie = oidc.start(s)
    except oidc.OidcError as err:
        return _fail(session, request, err)
    resp = RedirectResponse(url, status_code=302)
    resp.set_cookie(oidc.COOKIE_NAME, cookie, max_age=oidc.FLOW_TTL, path=oidc.COOKIE_PATH, httponly=True,
                    secure=s.oidc_redirect_uri.startswith("https://"), samesite="lax")
    resp.headers["Cache-Control"] = "no-store"
    return resp


@router.get("/callback", summary="IdP redirect target; hands a one-time code to the console")
def callback(request: Request, session: SessionDependency, code: str = "", state: str = "", error: str = ""):
    s = get_settings()
    if not s.oidc_enabled:
        raise HTTPException(status_code=404, detail="Not Found")
    if error:
        return _fail(session, request, oidc.OidcError("idp_denied", error[:100]))
    try:
        user, amr, auth_time, claims = oidc.complete(session, s, code[:2048], state[:200],
                                                     request.cookies.get(oidc.COOKIE_NAME))
    except oidc.OidcError as err:
        return _fail(session, request, err)
    handoff = oidc.issue_login_code(session, user, amr, auth_time)
    get_audit_log_service(session, None).record_action(
        event_type="AUTH_LOGIN_SUCCESS", severity="INFO", message=f"User ID {user.id} signed in with SSO",
        actor_source=_source(request), actor_user_id=user.id, target_entity="user", target_id=str(user.id),
        tenant_id=user.tenant_id, event_metadata={"method": "oidc", "amr": amr, "idp_subject": str(claims["sub"])[:200]})
    session.commit()
    return _to_console("sso_code=" + handoff)


@router.post("/exchange", response_model=TokenResponse, summary="Exchange the one-time SSO code for a session")
def exchange(body: OidcExchange, request: Request, session: SessionDependency) -> TokenResponse:
    s = get_settings()
    if not s.oidc_enabled:
        raise HTTPException(status_code=404, detail="Not Found")
    allowed, retry = login_limiter.check_and_increment(f"sso-exchange:{_source(request)}", 10,
                                                       s.login_global_attempts_per_minute, window_seconds=60)
    if not allowed:
        raise HTTPException(status_code=429, detail="Too many attempts", headers={"Retry-After": str(retry)})
    from app.core.auth_exceptions import AuthenticationError
    from app.core.security import create_access_token, require_active_identity
    from app.models.user import User

    try:
        row = oidc.redeem_login_code(session, body.code)
    except oidc.OidcError:
        raise AuthenticationError("Invalid or expired sign-in code") from None
    user = session.get(User, row.user_id)
    if user is None:
        raise AuthenticationError("Invalid or expired sign-in code")
    require_active_identity(user)
    session.commit()
    return TokenResponse(access_token=create_access_token(subject=user.id, token_version=user.token_version,
                                                          amr=row.amr, auth_time=row.auth_time))
