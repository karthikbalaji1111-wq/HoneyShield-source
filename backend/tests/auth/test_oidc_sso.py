"""OIDC single sign-on against a real (local) identity provider.

The mock IdP is an HTTP server on loopback with its own RSA signing key, a discovery document,
a JWKS endpoint and a token endpoint that enforces PKCE and client authentication. Every attack
case below goes through the real HTTP flow.
"""
from __future__ import annotations

import base64
import hashlib
import http.server
import json
import secrets
import threading
import time
import urllib.parse

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

from app.core.config import get_settings
from app.core.security import decode_access_token
from app.models.audit_log import AuditLog
from app.services import oidc

CLIENT_ID, CLIENT_SECRET = "honeyshield-test", "idp-client-secret-for-tests-0123456789abcdef"


class MockIdP:
    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = "k1"
        self.codes: dict[str, dict] = {}
        self.token_requests: list[dict] = []
        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"
        self.extra_keys: list[dict] = []
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def jwks(self):
        jwk = json.loads(RSAAlgorithm.to_jwk(self.key.public_key()))
        jwk.update({"kid": self.kid, "use": "sig", "alg": "RS256"})
        return {"keys": [jwk, *self.extra_keys]}

    def _handler(idp):
        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _json(self, code, doc):
                body = json.dumps(doc).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path == "/.well-known/openid-configuration":
                    return self._json(200, {"issuer": idp.base, "authorization_endpoint": idp.base + "/authorize",
                                            "token_endpoint": idp.base + "/token", "jwks_uri": idp.base + "/jwks",
                                            "id_token_signing_alg_values_supported": ["RS256", "ES256"]})
                if self.path == "/jwks":
                    return self._json(200, idp.jwks())
                self._json(404, {})

            def do_POST(self):
                form = dict(urllib.parse.parse_qsl(self.rfile.read(int(self.headers["Content-Length"])).decode()))
                idp.token_requests.append(form)
                auth = self.headers.get("Authorization", "")
                expected = "Basic " + base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
                if auth != expected:
                    return self._json(401, {"error": "invalid_client"})
                grant = idp.codes.pop(form.get("code"), None)
                if grant is None or form.get("grant_type") != "authorization_code":
                    return self._json(400, {"error": "invalid_grant"})
                challenge = base64.urlsafe_b64encode(hashlib.sha256(form["code_verifier"].encode()).digest()).decode().rstrip("=")
                if challenge != grant["challenge"]:
                    return self._json(400, {"error": "invalid_grant", "error_description": "PKCE"})
                return self._json(200, {"access_token": "at", "token_type": "Bearer", "id_token": grant["id_token"]})
        return H

    def sign(self, claims, key=None, alg="RS256", kid=None, headers=None):
        return jwt.encode(claims, key or self.key, algorithm=alg, headers={"kid": kid or self.kid, **(headers or {})})

    def authorize(self, auth_url, email, *, id_token=None, **claim_overrides):
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(auth_url).query))
        now = int(time.time())
        claims = {"iss": self.base, "sub": "idp-user-1", "aud": CLIENT_ID, "iat": now, "exp": now + 300,
                  "nonce": q["nonce"], "email": email, "email_verified": True, "auth_time": now - 5}
        claims.update(claim_overrides)
        claims = {k: v for k, v in claims.items() if v is not None}
        code = secrets.token_urlsafe(16)
        self.codes[code] = {"challenge": q["code_challenge"], "id_token": id_token or self.sign(claims)}
        return code, q

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


@pytest.fixture()
def idp(monkeypatch):
    p = MockIdP()
    s = get_settings()
    for k, v in (("oidc_issuer", p.base), ("oidc_client_id", CLIENT_ID), ("oidc_client_secret", CLIENT_SECRET),
                 ("oidc_redirect_uri", "http://testserver/auth/oidc/callback"), ("oidc_display_name", "Acme SSO"),
                 ("oidc_mfa", "amr_claim"), ("oidc_require_email_verified", True), ("oidc_email_claim", "email")):
        monkeypatch.setattr(s, k, v)
    oidc.reset_cache()
    yield p
    p.close()
    oidc.reset_cache()


def _start(client):
    r = client.get("/auth/oidc/login", follow_redirects=False)
    assert r.status_code == 302, r.text
    return r.headers["location"]


def _callback(client, code, state):
    r = client.get(f"/auth/oidc/callback?code={code}&state={state}", follow_redirects=False)
    assert r.status_code == 302
    return urllib.parse.urlsplit(r.headers["location"]).fragment


def _sign_in(client, idp, email, **kw):
    url = _start(client)
    code, q = idp.authorize(url, email, **kw)
    return _callback(client, code, q["state"])


def _error(fragment):
    assert fragment.startswith("sso_error="), fragment
    return fragment.split("=", 1)[1]


# ------------------------------------------------------------------------- happy path

def test_config_reports_sso(client, idp):
    assert client.get("/auth/oidc/config").json() == {"enabled": True, "display_name": "Acme SSO"}


def test_sso_disabled_by_default(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "oidc_issuer", None)
    assert client.get("/auth/oidc/config").json() == {"enabled": False, "display_name": None}
    assert client.get("/auth/oidc/login", follow_redirects=False).status_code == 404
    assert client.post("/auth/oidc/exchange", json={"code": "x" * 20}).status_code == 404


def test_full_sign_in_with_pkce_and_one_time_code(client, db_session, idp, user_a):
    url = _start(client)
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
    assert url.startswith(idp.base + "/authorize?")
    assert q["code_challenge_method"] == "S256" and q["response_type"] == "code" and "openid" in q["scope"]
    assert q["redirect_uri"] == "http://testserver/auth/oidc/callback" and q["client_id"] == CLIENT_ID
    cookie = client.cookies.get(oidc.COOKIE_NAME)
    assert cookie and "." in cookie                   # sealed and HMAC-protected; verifier never sent to the IdP
    assert "code_verifier" not in url
    code, _ = idp.authorize(url, user_a.email.upper())
    fragment = _callback(client, code, q["state"])
    assert fragment.startswith("sso_code=")
    assert idp.token_requests[-1]["code_verifier"] and idp.token_requests[-1]["redirect_uri"] == q["redirect_uri"]
    handoff = fragment.split("=", 1)[1]
    r = client.post("/auth/oidc/exchange", json={"code": handoff})
    assert r.status_code == 200
    token = r.json()["access_token"]
    claims = decode_access_token(token)
    assert claims["sub"] == str(user_a.id) and claims["amr"] == "pwd"
    assert abs(claims["auth_time"] - int(time.time())) <= 5       # HoneyShield sign-in time
    assert client.get("/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    # the handoff code is single use
    assert client.post("/auth/oidc/exchange", json={"code": handoff}).status_code == 401
    audit = db_session.query(AuditLog).filter_by(event_type="AUTH_LOGIN_SUCCESS", actor_user_id=user_a.id).all()
    assert any(a.event_metadata.get("method") == "oidc" for a in audit)


def test_idp_mfa_assertion_gives_an_mfa_session(client, idp, admin_a):
    fragment = _sign_in(client, idp, admin_a.email, amr=["pwd", "mfa"])
    token = client.post("/auth/oidc/exchange", json={"code": fragment.split("=", 1)[1]}).json()["access_token"]
    assert decode_access_token(token)["amr"] == "mfa"


def test_trusted_idp_gives_an_mfa_session(client, idp, admin_a, monkeypatch):
    monkeypatch.setattr(get_settings(), "oidc_mfa", "trust_idp")
    fragment = _sign_in(client, idp, admin_a.email)
    token = client.post("/auth/oidc/exchange", json={"code": fragment.split("=", 1)[1]}).json()["access_token"]
    assert decode_access_token(token)["amr"] == "mfa"


def test_mfa_policy_still_applies_to_password_level_sso(client, idp, admin_a, monkeypatch):
    monkeypatch.setattr(get_settings(), "mfa_required_roles", "TENANT_ADMIN")
    fragment = _sign_in(client, idp, admin_a.email)                       # no amr claim
    token = client.post("/auth/oidc/exchange", json={"code": fragment.split("=", 1)[1]}).json()["access_token"]
    h = {"Authorization": f"Bearer {token}"}
    assert client.get("/auth/me", headers=h).json()["mfa_enrollment_required"] is True
    assert client.get("/api/v1/projects", headers=h).status_code == 403


def test_honeyshield_mfa_users_need_an_idp_mfa_assertion(client, db_session, idp, admin_a):
    from app.core import mfa
    admin_a.mfa_enabled, admin_a.mfa_nonce = True, mfa.new_nonce()
    db_session.commit()
    assert _error(_sign_in(client, idp, admin_a.email)) == "mfa_required"
    assert _sign_in(client, idp, admin_a.email, amr=["hwk"]).startswith("sso_code=")


def test_key_rotation_is_followed(client, idp, user_a):
    new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    url = _start(client)                       # discovery + nothing cached for keys yet
    _sign_in(client, idp, user_a.email)        # caches the JWKS with k1
    old_key, idp.key, idp.kid = idp.key, new_key, "k2"
    assert _sign_in(client, idp, user_a.email).startswith("sso_code=")


def test_es256_tokens_are_accepted(client, idp, user_a):
    ec_key = ec.generate_private_key(ec.SECP256R1())
    jwk = json.loads(ECAlgorithm.to_jwk(ec_key.public_key()))
    jwk.update({"kid": "ec1", "use": "sig", "alg": "ES256"})
    idp.extra_keys.append(jwk)
    url = _start(client)
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
    now = int(time.time())
    token = idp.sign({"iss": idp.base, "sub": "s", "aud": CLIENT_ID, "iat": now, "exp": now + 60, "nonce": q["nonce"],
                      "email": user_a.email, "email_verified": True}, key=ec_key, alg="ES256", kid="ec1")
    code, _ = idp.authorize(url, user_a.email, id_token=token)
    assert _callback(client, code, q["state"]).startswith("sso_code=")


# ------------------------------------------------------------------------- attacks

def _forged(idp, url, user_email, **changes):
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
    now = int(time.time())
    claims = {"iss": idp.base, "sub": "s", "aud": CLIENT_ID, "iat": now, "exp": now + 60, "nonce": q["nonce"],
              "email": user_email, "email_verified": True}
    claims.update(changes)
    return {k: v for k, v in claims.items() if v is not None}


@pytest.mark.parametrize("case,expected", [
    ("wrong_audience", "invalid_token"),
    ("wrong_issuer", "invalid_token"),
    ("expired", "invalid_token"),
    ("wrong_nonce", "invalid_token"),
    ("no_nonce", "invalid_token"),
    ("other_key", "invalid_token"),
    ("hs256_with_client_secret", "invalid_token"),
    ("alg_none", "invalid_token"),
    ("multi_aud_without_azp", "invalid_token"),
    ("unverified_email", "email_unverified"),
    ("no_email", "no_email"),
    ("unknown_user", "unknown_user"),
])
def test_forged_or_invalid_id_tokens_are_refused(client, db_session, idp, user_a, case, expected):
    url = _start(client)
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
    claims = _forged(idp, url, user_a.email)
    key, alg, headers = None, "RS256", None
    if case == "wrong_audience":
        claims["aud"] = "someone-else"
    elif case == "wrong_issuer":
        claims["iss"] = "https://evil.example"
    elif case == "expired":
        claims["exp"] = int(time.time()) - 3600
    elif case == "wrong_nonce":
        claims["nonce"] = "attacker-nonce"
    elif case == "no_nonce":
        claims.pop("nonce")
    elif case == "other_key":
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif case == "multi_aud_without_azp":
        claims["aud"] = [CLIENT_ID, "other-client"]
    elif case == "unverified_email":
        claims["email_verified"] = False
    elif case == "no_email":
        claims.pop("email")
    elif case == "unknown_user":
        claims["email"] = "stranger@tenant-a.com"
    if case == "hs256_with_client_secret":
        token = jwt.encode(claims, CLIENT_SECRET, algorithm="HS256", headers={"kid": idp.kid})
    elif case == "alg_none":
        token = jwt.encode(claims, None, algorithm="none")
    else:
        token = idp.sign(claims, key=key, alg=alg, headers=headers)
    code, _ = idp.authorize(url, user_a.email, id_token=token)
    assert _error(_callback(client, code, q["state"])) == expected
    assert db_session.query(AuditLog).filter_by(event_type="AUTH_SSO_FAILURE").count() == 1


def test_state_must_match_the_browser_cookie(client, idp, user_a):
    url = _start(client)
    code, q = idp.authorize(url, user_a.email)
    assert _error(_callback(client, code, "attacker-state")) == "session_expired"


def test_callback_without_the_flow_cookie_is_refused(client, idp, user_a):
    """Login CSRF: a victim's browser cannot be made to finish an attacker's sign-in."""
    url = _start(client)
    code, q = idp.authorize(url, user_a.email)
    client.cookies.clear()
    assert _error(_callback(client, code, q["state"])) == "session_expired"


def test_tampered_flow_cookie_is_refused(client, idp, user_a):
    url = _start(client)
    code, q = idp.authorize(url, user_a.email)
    value = client.cookies.get(oidc.COOKIE_NAME)
    client.cookies.set(oidc.COOKIE_NAME, value[:-3] + "AAA", path=oidc.COOKIE_PATH)
    assert _error(_callback(client, code, q["state"])) == "session_expired"


def test_pkce_verifier_is_required_by_the_idp(client, idp, user_a):
    url = _start(client)
    code, q = idp.authorize(url, user_a.email)
    idp.codes[code]["challenge"] = "a-challenge-from-a-different-flow"
    assert _error(_callback(client, code, q["state"])) == "idp_error"


def test_disabled_accounts_cannot_sign_in(client, db_session, idp, user_a):
    user_a.is_active = False
    db_session.commit()
    assert _error(_sign_in(client, idp, user_a.email)) == "account_disabled"


def test_idp_errors_are_not_reflected(client, idp):
    r = client.get("/auth/oidc/callback?error=<script>alert(1)</script>", follow_redirects=False)
    assert urllib.parse.urlsplit(r.headers["location"]).fragment == "sso_error=idp_denied"


def test_unreachable_idp_fails_closed(client, idp, monkeypatch):
    monkeypatch.setattr(get_settings(), "oidc_issuer", "http://127.0.0.1:1")
    oidc.reset_cache()
    r = client.get("/auth/oidc/login", follow_redirects=False)
    assert urllib.parse.urlsplit(r.headers["location"]).fragment == "sso_error=idp_unreachable"


def test_expired_handoff_code_is_refused(client, db_session, idp, user_a):
    from datetime import datetime, timedelta, timezone

    from app.models.sso import SsoLoginCode
    fragment = _sign_in(client, idp, user_a.email)
    row = db_session.query(SsoLoginCode).one()
    row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db_session.commit()
    assert client.post("/auth/oidc/exchange", json={"code": fragment.split("=", 1)[1]}).status_code == 401
    assert row.code_hash != fragment.split("=", 1)[1]           # stored hashed


def test_settings_validation(monkeypatch):
    from app.core.config import Settings
    with pytest.raises(ValueError, match="OIDC_CLIENT_ID"):
        Settings(jwt_secret_key="x" * 40, oidc_issuer="https://idp.example")
    full = dict(oidc_client_id="c", oidc_client_secret="s", oidc_redirect_uri="https://a/cb")
    with pytest.raises(ValueError, match="openid"):
        Settings(jwt_secret_key="x" * 40, oidc_issuer="https://idp.example", oidc_scopes="email profile", **full)
    assert Settings(jwt_secret_key="x" * 40, oidc_issuer="http://idp.local", **full).oidc_enabled


def test_random_kids_cannot_make_us_hammer_the_idp(client, idp, user_a):
    _sign_in(client, idp, user_a.email)
    jwks_hits = []
    original = oidc._fetch_json
    def counting(url, settings, **kw):
        if url.endswith("/jwks"):
            jwks_hits.append(url)
        return original(url, settings, **kw)
    import unittest.mock as um
    with um.patch.object(oidc, "_fetch_json", counting):
        for _ in range(5):
            url = _start(client)
            claims = _forged(idp, url, user_a.email)
            token = idp.sign(claims, kid=f"random-{secrets.token_hex(4)}")
            code, q = idp.authorize(url, user_a.email, id_token=token)
            _callback(client, code, q["state"])
    assert len(jwks_hits) <= 1


def test_long_idp_sessions_do_not_shorten_the_honeyshield_session(client, idp, user_a):
    """Regression: an IdP auth_time from days ago must not make the new session renew-expired."""
    fragment = _sign_in(client, idp, user_a.email, auth_time=int(time.time()) - 5 * 24 * 3600)
    token = client.post("/auth/oidc/exchange", json={"code": fragment.split("=", 1)[1]}).json()["access_token"]
    r = client.post("/auth/refresh", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
