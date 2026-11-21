"""OpenID Connect single sign-on (authorization code flow + PKCE).

Flow
1. ``/auth/oidc/login``: random state, nonce and PKCE verifier go into a short-lived signed
   cookie (HttpOnly, SameSite=Lax, path /auth/oidc) - no server-side storage, so any replica can
   finish the flow - and the browser is sent to the IdP.
2. ``/auth/oidc/callback``: the state must match the cookie; the code is exchanged at the token
   endpoint with the PKCE verifier and the client secret; the ID token is verified:
   * signature against the IdP's JWKS (asymmetric algorithms only: never HS*/none);
   * ``iss``, ``aud`` (and ``azp`` when there are several audiences), ``exp``, ``iat``;
   * ``nonce`` equal to the cookie's.
   The user must already exist and be active; they are matched by the (verified) email claim.
3. The callback redirects to the console with a one-time code (60 s, stored hashed) that the
   console exchanges for a session: the session token never appears in a URL or history.

MFA: an SSO session counts as MFA (``amr=mfa``) only if the ID token's ``amr`` claim names a
second factor, or OIDC_MFA=trust_idp. Otherwise it is a password-level session, and the usual
policy applies: a user with HoneyShield MFA enabled cannot use it, and roles that require MFA get
the enrolment-only session.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import ssl
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core import tls
from app.models.sso import SsoLoginCode
from app.models.user import User

COOKIE_NAME = "hs_oidc"
COOKIE_PATH = "/auth/oidc"
FLOW_TTL = 600
CODE_TTL = timedelta(seconds=60)
ALLOWED_ALGS = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512")
MFA_AMR_VALUES = {"mfa", "otp", "hwk", "swk", "fpt", "face", "sc", "pop", "iris", "retina", "vbm"}
DISCOVERY_TTL = 3600
MAX_BODY = 1024 * 1024
LEEWAY = 60


class OidcError(Exception):
    """A sign-in that must fail. ``code`` is a fixed identifier safe to show the user."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(detail or code)
        self.code = code
        self.detail = detail


# ------------------------------------------------------------------------------- HTTP

def _context(settings) -> ssl.SSLContext:
    return tls.client_context(settings.oidc_ca_file)


def _fetch_json(url: str, settings, data: dict[str, str] | None = None,
                headers: dict[str, str] | None = None) -> dict[str, Any]:
    if not url.startswith("https://") and settings.app_env.lower() in ("production", "prod", "staging"):
        raise OidcError("idp_error", "IdP endpoint must use https")
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers={"Accept": "application/json", **(headers or {})})
    if body is not None:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        # The scheme is checked above (https, or http only for a development IdP).
        with urllib.request.urlopen(req, timeout=10, context=_context(settings) if url.startswith("https") else None) as r:  # nosec B310
            raw = r.read(MAX_BODY + 1)
    except urllib.error.HTTPError as exc:
        raise OidcError("idp_error", f"IdP returned HTTP {exc.code}") from None
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise OidcError("idp_unreachable", type(exc).__name__) from None
    if len(raw) > MAX_BODY:
        raise OidcError("idp_error", "IdP response too large")
    try:
        doc = json.loads(raw)
    except ValueError:
        raise OidcError("idp_error", "IdP response is not JSON") from None
    if not isinstance(doc, dict):
        raise OidcError("idp_error", "IdP response is not an object")
    return doc


# ------------------------------------------------------------------- discovery and keys

@dataclass
class _Cache:
    issuer: str | None = None
    discovery: dict[str, Any] | None = None
    fetched_at: float = 0.0
    jwks: dict[str, Any] | None = None
    jwks_at: float = 0.0
    forced_at: float = 0.0


_cache = _Cache()
_lock = threading.Lock()


def reset_cache() -> None:
    global _cache
    with _lock:
        _cache = _Cache()


def discovery(settings) -> dict[str, Any]:
    with _lock:
        if _cache.discovery and _cache.issuer == settings.oidc_issuer and time.time() - _cache.fetched_at < DISCOVERY_TTL:
            return _cache.discovery
    issuer = settings.oidc_issuer.rstrip("/")
    doc = _fetch_json(issuer + "/.well-known/openid-configuration", settings)
    if doc.get("issuer", "").rstrip("/") != issuer:
        raise OidcError("idp_error", "Discovery issuer does not match OIDC_ISSUER")
    for field in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not isinstance(doc.get(field), str):
            raise OidcError("idp_error", f"Discovery document lacks {field}")
    with _lock:
        _cache.issuer, _cache.discovery, _cache.fetched_at = settings.oidc_issuer, doc, time.time()
        _cache.jwks, _cache.jwks_at = None, 0.0
    return doc


def _jwks(settings, force: bool = False) -> dict[str, Any]:
    with _lock:
        if _cache.jwks and not force:
            return _cache.jwks
        # Unknown kid: refetch (key rotation), but at most once per 30 s so tokens with random
        # kids cannot make us hammer the IdP.
        if force and time.time() - _cache.forced_at < 30:
            return _cache.jwks or {"keys": []}
        if force:
            _cache.forced_at = time.time()
    doc = _fetch_json(discovery(settings)["jwks_uri"], settings)
    if not isinstance(doc.get("keys"), list):
        raise OidcError("idp_error", "JWKS has no keys")
    with _lock:
        _cache.jwks, _cache.jwks_at = doc, time.time()
    return doc


def _signing_key(settings, kid: str | None, alg: str):
    for force in (False, True):  # a new kid triggers one refresh (key rotation)
        for jwk in _jwks(settings, force).get("keys", []):
            if kid is not None and jwk.get("kid") != kid:
                continue
            if jwk.get("use", "sig") != "sig":
                continue
            try:
                return jwt.PyJWK(jwk, algorithm=alg).key
            except (jwt.PyJWKError, jwt.InvalidKeyError, KeyError, ValueError):
                continue
    raise OidcError("invalid_token", "No matching IdP signing key")


# ----------------------------------------------------------------- flow cookie (state)

def _cookie_key() -> bytes:
    from app.core.config import get_settings

    return hmac.new(get_settings().jwt_secret_key.encode(), b"honeyshield-oidc-flow-v1", hashlib.sha256).digest()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def seal_flow(flow: dict[str, Any]) -> str:
    body = _b64(json.dumps(flow, separators=(",", ":")).encode())
    return body + "." + _b64(hmac.new(_cookie_key(), body.encode(), hashlib.sha256).digest())


def open_flow(value: str | None) -> dict[str, Any]:
    if not value or "." not in value or len(value) > 2048:
        raise OidcError("session_expired", "missing sign-in cookie")
    body, mac = value.rsplit(".", 1)
    expected = _b64(hmac.new(_cookie_key(), body.encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(mac, expected):
        raise OidcError("session_expired", "bad sign-in cookie")
    flow = json.loads(_unb64(body))
    if flow.get("exp", 0) < time.time():
        raise OidcError("session_expired", "sign-in took too long")
    return flow


def start(settings) -> tuple[str, str]:
    """Return (IdP authorization URL, sealed flow cookie value)."""
    doc = discovery(settings)
    state, nonce, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(24), secrets.token_urlsafe(48)
    challenge = _b64(hashlib.sha256(verifier.encode()).digest())
    params = {"response_type": "code", "client_id": settings.oidc_client_id,
              "redirect_uri": settings.oidc_redirect_uri, "scope": settings.oidc_scopes,
              "state": state, "nonce": nonce, "code_challenge": challenge, "code_challenge_method": "S256"}
    sep = "&" if "?" in doc["authorization_endpoint"] else "?"
    url = doc["authorization_endpoint"] + sep + urllib.parse.urlencode(params)
    return url, seal_flow({"state": state, "nonce": nonce, "verifier": verifier, "exp": int(time.time()) + FLOW_TTL})


# --------------------------------------------------------------------------- callback

def _validate_id_token(settings, id_token: str, nonce: str) -> dict[str, Any]:
    try:
        header = jwt.get_unverified_header(id_token)
    except jwt.InvalidTokenError:
        raise OidcError("invalid_token", "malformed ID token") from None
    alg = header.get("alg")
    supported = discovery(settings).get("id_token_signing_alg_values_supported") or ["RS256"]
    if alg not in ALLOWED_ALGS or alg not in supported:
        raise OidcError("invalid_token", f"ID token algorithm {alg!r} not allowed")
    key = _signing_key(settings, header.get("kid"), alg)
    try:
        claims = jwt.decode(id_token, key, algorithms=[alg], audience=settings.oidc_client_id,
                            issuer=discovery(settings)["issuer"], leeway=LEEWAY,
                            options={"require": ["iss", "sub", "aud", "exp", "iat"]})
    except jwt.InvalidTokenError as exc:
        raise OidcError("invalid_token", type(exc).__name__) from None
    aud = claims.get("aud")
    if isinstance(aud, list) and len(aud) > 1 and claims.get("azp") != settings.oidc_client_id:
        raise OidcError("invalid_token", "azp does not match")
    if not isinstance(claims.get("nonce"), str) or not hmac.compare_digest(claims["nonce"], nonce):
        raise OidcError("invalid_token", "nonce mismatch")
    return claims


def complete(session: Session, settings, code: str, state: str, cookie: str | None) -> tuple[User, str, int, dict]:
    """Finish the flow. Returns (user, amr, auth_time, claims)."""
    flow = open_flow(cookie)
    if not state or not hmac.compare_digest(state, flow["state"]):
        raise OidcError("session_expired", "state mismatch")
    if not code or len(code) > 2048:
        raise OidcError("idp_error", "no authorization code")
    doc = discovery(settings)
    basic = base64.b64encode(f"{urllib.parse.quote(settings.oidc_client_id, safe='')}:"
                             f"{urllib.parse.quote(settings.oidc_client_secret, safe='')}".encode()).decode()
    tokens = _fetch_json(doc["token_endpoint"], settings, data={
        "grant_type": "authorization_code", "code": code, "redirect_uri": settings.oidc_redirect_uri,
        "code_verifier": flow["verifier"], "client_id": settings.oidc_client_id,
    }, headers={"Authorization": f"Basic {basic}"})
    if not isinstance(tokens.get("id_token"), str):
        raise OidcError("idp_error", "token response has no id_token")
    claims = _validate_id_token(settings, tokens["id_token"], flow["nonce"])

    email = claims.get(settings.oidc_email_claim)
    if not isinstance(email, str) or "@" not in email or len(email) > 254:
        raise OidcError("no_email", f"ID token has no usable {settings.oidc_email_claim} claim")
    if settings.oidc_require_email_verified and claims.get("email_verified") is not True:
        raise OidcError("email_unverified", "IdP does not assert a verified email")
    from app.repositories.user_repository import UserRepository

    user = UserRepository(session).get_by_email(email.strip().lower())
    if user is None:
        raise OidcError("unknown_user", "no HoneyShield account for this email")
    if not user.is_active:
        raise OidcError("account_disabled", "account disabled")
    from app.core.security import AMR_MFA, AMR_PASSWORD

    amr_claim = claims.get("amr") if isinstance(claims.get("amr"), list) else []
    strong = settings.oidc_mfa == "trust_idp" or any(str(a).lower() in MFA_AMR_VALUES for a in amr_claim)
    amr = AMR_MFA if strong else AMR_PASSWORD
    if user.has_second_factor and amr != AMR_MFA:
        raise OidcError("mfa_required", "IdP did not assert MFA and this account uses HoneyShield MFA")
    # The HoneyShield session starts now. (The ID token's auth_time is when the user last signed in
    # at the IdP - possibly days ago with long IdP sessions - and would make SESSION_MAX_HOURS end
    # a fresh SSO session immediately.)
    return user, amr, int(time.time()), claims


# ------------------------------------------------------------------- one-time handoff code

def _code_hash(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


def issue_login_code(session: Session, user: User, amr: str, auth_time: int) -> str:
    code = secrets.token_urlsafe(32)
    session.add(SsoLoginCode(code_hash=_code_hash(code), user_id=user.id, amr=amr, auth_time=auth_time,
                             expires_at=datetime.now(timezone.utc) + CODE_TTL))
    session.flush()
    return code


def redeem_login_code(session: Session, code: str) -> SsoLoginCode:
    now = datetime.now(timezone.utc)
    if not code or len(code) > 100:
        raise OidcError("invalid_code")
    row = session.scalar(select(SsoLoginCode).where(SsoLoginCode.code_hash == _code_hash(code)).with_for_update())
    expires = row.expires_at if row is None or row.expires_at.tzinfo else row.expires_at.replace(tzinfo=timezone.utc)
    if row is None or row.used_at is not None or expires <= now:
        raise OidcError("invalid_code")
    claimed = session.execute(update(SsoLoginCode).where(SsoLoginCode.id == row.id, SsoLoginCode.used_at.is_(None))
                              .values(used_at=now)).rowcount
    if claimed != 1:
        raise OidcError("invalid_code")
    return row
