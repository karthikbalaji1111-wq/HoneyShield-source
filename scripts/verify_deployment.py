#!/usr/bin/env python3
"""End-to-end verification of a running HoneyShield deployment (stdlib only).

Exercises the real edge (TLS, both virtual hosts, Nginx limits) and the real backend,
database and worker:

  * host separation and route allowlists on the ingest host
  * HTTP->HTTPS redirect, TLS 1.0/1.1 refused, security headers
  * tenant + tenant-admin + project creation, all five decoy types
  * URL / LINK / PIXEL artifacts followed through the ingest host -> PUBLIC_INGEST events
  * API_KEY and FORM_FIELD via the signed customer hook -> CUSTOMER_HOOK events
  * spoofed X-Forwarded-For is ignored
  * per-type severity, viewer masking, evidence and audit chain verification, password reset,
    API keys, CSV export, session renewal, SSO configuration,
    metrics, shared state across replicas (--expect-replicas)
  * operator MFA: admins are forced to enrol (TOTP), login needs the second factor
  * edge rate limiting on the ingest host

It creates a uniquely named tenant on each run and never deletes anything.

Usage (local verification stack):
  HS_VERIFY_ADMIN_PASSWORD=... python3 scripts/verify_deployment.py \\
      --control-host app.honeyshield.test --ingest-host ingest.honeyshield.test \\
      --connect 127.0.0.1:18443 --http-connect 127.0.0.1:18080 --cacert ca.crt \\
      --admin-email admin@example.com [--metrics-token ...] [--totp-secret-file admin.totp]

When the system admin must use MFA, --totp-secret-file holds its base32 TOTP secret. If the
admin has not enrolled yet, the script enrols it and writes the secret there (mode 600) --
store it in your password manager / authenticator afterwards.
"""
from __future__ import annotations

import argparse
import base64
import struct
import hashlib
import hmac
import http.client
import json
import os
import re
import secrets
import socket
import ssl
import sys
import time
from datetime import datetime, timezone

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    RESULTS.append((name, bool(ok), detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}{(' - ' + detail) if detail else ''}")
    return ok


class Edge:
    def __init__(self, connect: str, cacert: str | None):
        host, port = connect.rsplit(":", 1)
        self.addr, self.port = host, int(port)
        self.ctx = ssl.create_default_context(cafile=cacert) if cacert else ssl.create_default_context()

    def request(self, vhost: str, method: str, path: str, body: bytes | None = None,
                headers: dict | None = None, sni: str | None = None) -> tuple[int, dict, bytes]:
        sock = socket.create_connection((self.addr, self.port), timeout=15)
        tls = self.ctx.wrap_socket(sock, server_hostname=sni or vhost)
        conn = http.client.HTTPSConnection(vhost, self.port, timeout=15)
        conn.sock = tls
        hdrs = {"Host": vhost, **(headers or {})}
        if body is not None:
            hdrs.setdefault("Content-Type", "application/json")
        try:
            conn.request(method, path, body=body, headers=hdrs)
            resp = conn.getresponse()
            return resp.status, {k.lower(): v for k, v in resp.getheaders()}, resp.read()
        except (http.client.RemoteDisconnected, ConnectionResetError):
            return 0, {}, b""
        finally:
            conn.close()

    def json(self, vhost, method, path, payload=None, token=None, expect=None):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        body = json.dumps(payload).encode() if payload is not None else None
        status, _, raw = self.request(vhost, method, path, body, headers)
        data = json.loads(raw) if raw and raw[:1] in b"[{" else None
        if expect is not None and status != expect:
            raise RuntimeError(f"{method} {path} -> {status}: {raw[:300]!r}")
        return status, data


# ----------------------------------------------------------------------------- TOTP (RFC 6238)
_LAST_STEP: dict[str, int] = {}


def totp_now(secret_b32: str, account: str) -> str:
    """Current code, waiting for a fresh 30 s step if this account already used the current one."""
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))
    while int(time.time() // 30) <= _LAST_STEP.get(account, -1):
        time.sleep(1)
    step = int(time.time() // 30)
    _LAST_STEP[account] = step
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    return str((struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF) % 1_000_000).zfill(6)


def enrol_mfa(edge: "Edge", vhost: str, token: str, password: str, account: str) -> tuple[str, str]:
    """Run setup + enable for a pending session; return (full token, base32 secret)."""
    _, setup = edge.json(vhost, "POST", "/auth/mfa/setup", {"current_password": password}, token, expect=200)
    _, enabled = edge.json(vhost, "POST", "/auth/mfa/enable", {"code": totp_now(setup["secret"], account)},
                           token, expect=200)
    return enabled["access_token"], setup["secret"]


def login_with_mfa(edge: "Edge", vhost: str, email: str, password: str, secret: str | None) -> tuple[str, str | None]:
    """Log in, handling an MFA challenge or a forced enrolment. Returns (token, secret)."""
    status, data = edge.json(vhost, "POST", "/auth/login", {"email": email, "password": password})
    if status == 401 and data and data.get("detail") == "MFA code required":
        if not secret:
            raise RuntimeError(f"{email} has MFA enabled; provide its TOTP secret")
        _, data = edge.json(vhost, "POST", "/auth/login",
                            {"email": email, "password": password, "otp": totp_now(secret, email)}, expect=200)
        return data["access_token"], secret
    if status != 200:
        raise RuntimeError(f"login {email} -> {status}: {data}")
    token = data["access_token"]
    _, me = edge.json(vhost, "GET", "/auth/me", token=token, expect=200)
    if me.get("mfa_enrollment_required"):
        token, secret = enrol_mfa(edge, vhost, token, password, email)
    return token, secret


def sign(secret: str, method: str, path: str, ts: str, body: bytes) -> str:
    canonical = "\n".join(("v1", method, path, ts, hashlib.sha256(body).hexdigest()))
    return "v1=" + hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--control-host", required=True)
    ap.add_argument("--ingest-host", required=True)
    ap.add_argument("--connect", required=True, help="address:port of the TLS listener")
    ap.add_argument("--http-connect", help="address:port of the plain HTTP listener")
    ap.add_argument("--cacert")
    ap.add_argument("--admin-email", required=True)
    ap.add_argument("--metrics-token", default=os.getenv("HS_VERIFY_METRICS_TOKEN"))
    ap.add_argument("--expect-replicas", type=int, default=1, help="backend replicas (checks shared state if > 1)")
    ap.add_argument("--smtp-configured", action="store_true", help="deployment has SMTP (self-service reset on)")
    ap.add_argument("--skip-rate-limit", action="store_true")
    ap.add_argument("--totp-secret-file", help="base32 TOTP secret of the admin (created on first enrolment)")
    args = ap.parse_args()
    password = os.environ.get("HS_VERIFY_ADMIN_PASSWORD")
    if not password:
        print("Set HS_VERIFY_ADMIN_PASSWORD", file=sys.stderr)
        return 2

    edge = Edge(args.connect, args.cacert)
    C, I = args.control_host, args.ingest_host

    # ------------------------------------------------------------- edge / TLS / hosts
    status, headers, _ = edge.request(C, "GET", "/api/v1/ready")
    check("control plane readiness", status == 200, f"HTTP {status}")
    check("HSTS on control plane", "strict-transport-security" in headers)
    for path in ("/api/v1/health", "/api/v1/ready", "/docs", "/openapi.json", "/auth/login", "/metrics", "/console/"):
        status, _, _ = edge.request(I, "GET", path)
        check(f"ingest host hides {path}", status == 404, f"HTTP {status}")
    status, _, _ = edge.request(C, "GET", "/t/anything")
    check("control host does not serve /t/", status == 404, f"HTTP {status}")
    status, _, _ = edge.request("unknown.invalid", "GET", "/api/v1/ready", sni=C)
    check("unknown Host header is dropped (444)", status == 0, f"HTTP {status}")
    status, _, _ = edge.request(C, "GET", "/docs")
    check("API docs disabled in production", status == 404, f"HTTP {status}")
    status, headers, body = edge.request(C, "GET", "/console/")
    check("console served with CSP", status == 200 and "script-src 'self'" in headers.get("content-security-policy", ""),
          f"HTTP {status}")
    if args.http_connect:
        h, p = args.http_connect.rsplit(":", 1)
        conn = http.client.HTTPConnection(h, int(p), timeout=10)
        conn.request("GET", "/api/v1/ready", headers={"Host": C})
        r = conn.getresponse()
        check("HTTP redirects to HTTPS", r.status == 301 and r.getheader("Location", "").startswith(f"https://{C}"),
              f"HTTP {r.status}")
    try:
        old = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        old.check_hostname = False
        old.verify_mode = ssl.CERT_NONE
        old.maximum_version = ssl.TLSVersion.TLSv1_1
        old.minimum_version = ssl.TLSVersion.TLSv1
        with old.wrap_socket(socket.create_connection((edge.addr, edge.port), timeout=5), server_hostname=C):
            check("TLS 1.1 refused", False, "handshake succeeded")
    except (ssl.SSLError, OSError):
        check("TLS 1.1 refused", True)

    # ------------------------------------------------------------- onboarding
    secret_file = args.totp_secret_file
    known = open(secret_file).read().strip() if secret_file and os.path.exists(secret_file) else None
    sys_token, sys_secret = login_with_mfa(edge, C, args.admin_email, password, known)
    if sys_secret and sys_secret != known:
        if not secret_file:
            raise RuntimeError("The admin was just enrolled in MFA; rerun with --totp-secret-file to keep the secret")
        fd = os.open(secret_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(sys_secret + "\n")
        print(f"NOTE: admin enrolled in MFA; TOTP secret written to {secret_file}")
    _, me = edge.json(C, "GET", "/auth/me", token=sys_token, expect=200)
    check("system admin session satisfies MFA policy", not me["mfa_enrollment_required"],
          f"mfa_enabled={me['mfa_enabled']} required={me['mfa_required']}")
    suffix = secrets.token_hex(3)
    slug = f"verify-{suffix}"
    edge.json(C, "POST", "/api/v1/tenants", {"name": f"Verify {suffix}", "slug": slug}, sys_token, expect=201)
    _, tenants = edge.json(C, "GET", f"/api/v1/tenants/{slug}", token=sys_token, expect=200)
    status, _ = edge.json(C, "POST", "/api/v1/tenants", {"name": "Unsafe", "slug": f"Verify {suffix}/.."}, sys_token)
    check("unsafe tenant slug refused", status == 422, f"HTTP {status}")
    admin_pw, viewer_pw = secrets.token_urlsafe(18), secrets.token_urlsafe(18)
    admin_email, viewer_email = f"admin-{suffix}@verify.test", f"viewer-{suffix}@verify.test"
    edge.json(C, "POST", "/api/v1/users", {"email": admin_email, "password": admin_pw, "role": "TENANT_ADMIN",
                                            "tenant_id": tenants["id"]}, sys_token, expect=201)
    edge.json(C, "POST", "/api/v1/users", {"email": viewer_email, "password": viewer_pw, "role": "TENANT_USER",
                                            "tenant_id": tenants["id"]}, sys_token, expect=201)
    _, login = edge.json(C, "POST", "/auth/login", {"email": admin_email.upper(), "password": admin_pw}, expect=200)
    tok = login["access_token"]
    check("tenant admin login (case-insensitive email)", bool(tok))
    _, me = edge.json(C, "GET", "/auth/me", token=tok, expect=200)
    if me["mfa_required"]:
        status, _ = edge.json(C, "GET", "/api/v1/projects", token=tok)
        check("MFA enforced: un-enrolled admin session limited to enrolment (403)", status == 403, f"HTTP {status}")
        tok, admin_secret = enrol_mfa(edge, C, tok, admin_pw, admin_email)
        check("MFA enrolment (setup + enable) issues a full session",
              edge.json(C, "GET", "/api/v1/projects", token=tok)[0] == 200)
        status, data = edge.json(C, "POST", "/auth/login", {"email": admin_email, "password": admin_pw})
        check("login without MFA code refused", status == 401 and (data or {}).get("detail") == "MFA code required",
              f"HTTP {status}")
        status, data = edge.json(C, "POST", "/auth/login", {"email": admin_email, "password": admin_pw,
                                                            "otp": totp_now(admin_secret, admin_email)})
        check("login with TOTP code succeeds", status == 200, f"HTTP {status}")
        tok = data["access_token"]
    domain = f"{suffix}.customer.example"
    edge.json(C, "POST", "/api/v1/projects", {"tenant_slug": slug, "name": "Verify", "domain": domain}, tok, expect=201)

    generated = {}
    for kind in ("URL", "LINK", "PIXEL", "FORM_FIELD", "API_KEY"):
        _, data = edge.json(C, "POST", f"/api/v1/projects/{domain}/honey-tokens/generate", {"token_type": kind},
                            tok, expect=201)
        generated[kind] = data

    # ------------------------------------------------------------- public artifacts through the ingest host
    def follow(url: str, spoof: bool = False):
        m = re.match(r"https://([^/]+)(/.*)", url)
        check(f"artifact targets ingest host ({url.split('/')[3] if url.count('/') > 3 else url})",
              bool(m) and m.group(1) == I, url[:60])
        hdrs = {"User-Agent": "HoneyShield-Verify/1"}
        if spoof:
            hdrs["X-Forwarded-For"] = "6.6.6.6"
        return edge.request(I, "GET", m.group(2), headers=hdrs)

    status, _, _ = follow(generated["URL"]["metadata"]["url"], spoof=True)
    check("URL trigger accepted", status == 204, f"HTTP {status}")
    href = re.search(r'href="([^"]+)"', generated["LINK"]["metadata"]["html_tag"]).group(1)
    status, _, _ = follow(href)
    check("LINK trigger accepted", status == 204, f"HTTP {status}")
    src = re.search(r'src="([^"]+)"', generated["PIXEL"]["metadata"]["embed_html"]).group(1)
    status, headers, body = follow(src)
    check("PIXEL returns a GIF", status == 200 and body[:6] in (b"GIF89a", b"GIF87a"), f"HTTP {status}")

    # ------------------------------------------------------------- customer hook (API_KEY, FORM_FIELD)
    _, cred = edge.json(C, "POST", f"/api/v1/projects/{domain}/integrations", {"label": "verify"}, tok, expect=201)

    def signed(method, path, payload=None):
        body = json.dumps(payload).encode() if payload is not None else b""
        ts = str(int(time.time()))
        return edge.request(I, method, path, body if payload is not None else None, {
            "X-HS-Integration": cred["integration_id"], "X-HS-Timestamp": ts,
            "X-HS-Signature": sign(cred["secret"], method, path, ts, body), "Content-Type": "application/json"})

    status, _, raw = signed("GET", "/integrations/v1/manifest")
    manifest = json.loads(raw) if status == 200 else {}
    key_hash = hashlib.sha256(generated["API_KEY"]["token_value"].encode()).hexdigest()
    check("manifest lists the decoy key hash (not the key)",
          any(d.get("sha256") == key_hash for d in manifest.get("decoys", []))
          and generated["API_KEY"]["token_value"].encode() not in raw)
    now = datetime.now(timezone.utc).isoformat()
    for kind, ip in (("API_KEY", "203.0.113.10"), ("FORM_FIELD", "203.0.113.11")):
        report = {"decoy_id": generated[kind]["decoy_id"], "idempotency_key": f"verify-{kind.lower()}-{suffix}xxxx",
                  "observed_at": now, "source_ip": ip, "http_method": "POST", "request_path": "/login"}
        status, _, _ = signed("POST", "/integrations/v1/events", report)
        check(f"{kind} hook report accepted", status == 202, f"HTTP {status}")
        status, _, _ = signed("POST", "/integrations/v1/events", report)
        check(f"{kind} duplicate report accepted idempotently", status == 202, f"HTTP {status}")
    status, _, _ = edge.request(I, "POST", "/integrations/v1/events", b"{}", {
        "X-HS-Integration": cred["integration_id"], "X-HS-Timestamp": str(int(time.time())),
        "X-HS-Signature": "v1=" + "0" * 64})
    check("forged hook signature rejected", status == 401, f"HTTP {status}")

    # ------------------------------------------------------------- evidence as seen by investigators
    time.sleep(1)
    _, events = edge.json(C, "GET", "/api/v1/detection-events?limit=50", token=tok, expect=200)
    by_token = {}
    for e in events:
        by_token.setdefault(e["honey_token_id"], []).append(e)
    for kind, sev, source in (("URL", "HIGH", "PUBLIC_INGEST"), ("LINK", "MEDIUM", "PUBLIC_INGEST"),
                              ("PIXEL", "HIGH", "PUBLIC_INGEST"), ("API_KEY", "CRITICAL", "CUSTOMER_HOOK"),
                              ("FORM_FIELD", "MEDIUM", "CUSTOMER_HOOK")):
        evs = by_token.get(generated[kind]["id"], [])
        check(f"{kind}: exactly one {source} event, severity {sev}",
              len(evs) == 1 and evs[0]["source"] == source and evs[0]["severity"] == sev,
              json.dumps([(e["source"], e["severity"]) for e in evs]))
    url_events = by_token.get(generated["URL"]["id"], [])
    check("spoofed X-Forwarded-For ignored", bool(url_events) and url_events[0]["ip_address"] != "6.6.6.6",
          url_events[0]["ip_address"] if url_events else "no event")
    check("each event names its decoy", bool(events) and all(e.get("decoy_id") and e.get("decoy_type") for e in events))
    _, crit = edge.json(C, "GET", "/api/v1/detection-events?severity=CRITICAL&limit=50", token=tok, expect=200)
    check("severity filter returns only that severity",
          bool(crit) and all(e["severity"] == "CRITICAL" for e in crit)
          and generated["API_KEY"]["id"] in {e["honey_token_id"] for e in crit}, f"{len(crit)} rows")
    one = events[0] if events else {"id": 0}
    status, single = edge.json(C, "GET", f"/api/v1/detection-events/{one['id']}", token=tok)
    check("one event by id matches the list view", status == 200 and single == one, f"HTTP {status}")
    # Cross-tenant: an event of another tenant. Older than this run's events, so look past them with
    # the cursor; reported (not silently skipped) when the database holds no other tenant's events.
    foreign, cursor = None, None
    for _ in range(20):
        page_q = f"/api/v1/detection-events?limit=200{f'&cursor={cursor}' if cursor else ''}"
        _, everyone = edge.json(C, "GET", page_q, token=sys_token, expect=200)
        foreign = next((e for e in everyone if e.get("project_domain") != domain), None)
        if foreign is not None or len(everyone) < 200:
            break
        cursor = everyone[-1]["id"]
    if foreign is None:
        print("[SKIP] another tenant's event id is not found - no other tenant has events yet")
    else:
        status, _ = edge.json(C, "GET", f"/api/v1/detection-events/{foreign['id']}", token=tok)
        check("another tenant's event id is not found", status == 404, f"HTTP {status}")
    _, days = edge.json(C, "GET", "/api/v1/detection-events/activity?days=7", token=tok, expect=200)
    today = days[-1] if days else {}
    check("activity series: 7 days, today counts this run's events",
          len(days) == 7 and today.get("total", 0) >= 5 and today["total"] == sum(today["by_severity"].values()),
          json.dumps(today))

    _, login = edge.json(C, "POST", "/auth/login", {"email": viewer_email, "password": viewer_pw}, expect=200)
    _, viewer_events = edge.json(C, "GET", "/api/v1/detection-events?limit=50", token=login["access_token"], expect=200)
    check("viewer never sees token values",
          generated["URL"]["token_value"] not in json.dumps(viewer_events) and len(viewer_events) == len(events))
    status, _ = edge.json(C, "POST", f"/api/v1/projects/{domain}/honey-tokens/generate", {"token_type": "URL"},
                          login["access_token"])
    check("viewer cannot create decoys", status == 403, f"HTTP {status}")

    _, verify = edge.json(C, "GET", "/api/v1/evidence/verify", token=tok, expect=200)
    check("evidence chain verifies", verify["ok"] and verify["links_checked"] == 5,
          f"links={verify['links_checked']} failures={verify['failures']}")

    _, audit_verify = edge.json(C, "GET", "/api/v1/audit-logs/verify", token=sys_token, expect=200)
    check("audit log hash chain verifies", audit_verify["ok"],
          f"links={audit_verify['links_checked']} unsealed={audit_verify['unsealed_records']} "
          f"failures={audit_verify['failures']}")

    # Password reset: admin-issued single-use link; completing it revokes the viewer's sessions.
    viewer_id = next(u["id"] for u in edge.json(C, "GET", "/api/v1/users?limit=100", token=tok, expect=200)[1]
                     if u["email"] == viewer_email)
    status, issued = edge.json(C, "POST", f"/api/v1/users/{viewer_id}/password-reset",
                               {"reason": "deployment verification of password reset"}, tok)
    check("admin issues a password reset link", status == 201 and "#reset=" in (issued or {}).get("reset_url", ""),
          f"HTTP {status}")
    reset_token = (issued or {}).get("reset_url", "#reset=").split("#reset=", 1)[1]
    new_viewer_pw = secrets.token_urlsafe(18)
    status, _ = edge.json(C, "POST", "/auth/password-reset/confirm", {"token": reset_token, "new_password": new_viewer_pw})
    reused, _ = edge.json(C, "POST", "/auth/password-reset/confirm", {"token": reset_token, "new_password": viewer_pw + "x"})
    old_session, _ = edge.json(C, "GET", "/auth/me", token=login["access_token"])
    new_login, _ = edge.json(C, "POST", "/auth/login", {"email": viewer_email, "password": new_viewer_pw})
    check("password reset link works once and revokes sessions",
          (status, reused, old_session, new_login) == (204, 401, 401, 200),
          f"confirm={status} reuse={reused} old_session={old_session} new_login={new_login}")
    if not args.smtp_configured:
        status, _ = edge.json(C, "POST", "/auth/password-reset/request", {"email": viewer_email})
        check("self-service reset is unavailable without SMTP (503)", status == 503, f"HTTP {status}")

    # Personal API key: created from a session, works for reads, refused for writes and /auth.
    status, key = edge.json(C, "POST", "/api/v1/api-keys", {"name": "verify", "scope": "read", "expires_in_days": 1},
                            tok)
    raw_key = (key or {}).get("api_key", "")
    k_read, k_rows = edge.json(C, "GET", "/api/v1/detection-events?limit=5", token=raw_key)
    k_write, _ = edge.json(C, "POST", f"/api/v1/projects/{domain}/honey-tokens/generate", {"token_type": "URL"},
                           raw_key)
    k_auth, _ = edge.json(C, "GET", "/auth/me", token=raw_key)
    check("read-only API key: reads yes, writes and /auth no",
          (status, k_read, k_write, k_auth) == (201, 200, 403, 401) and bool(k_rows),
          f"create={status} read={k_read} write={k_write} auth={k_auth}")
    if key:
        edge.json(C, "DELETE", f"/api/v1/api-keys/{key['key_id']}", token=tok)
        revoked, _ = edge.json(C, "GET", "/api/v1/detection-events?limit=1", token=raw_key)
        check("revoked API key is refused", revoked == 401, f"HTTP {revoked}")

    # CSV export: tenant-scoped, token values masked.
    status, hdrs, csv_body = edge.request(C, "GET", "/api/v1/detection-events/export",
                                          headers={"Authorization": f"Bearer {tok}"})
    check("CSV export masks token values",
          status == 200 and hdrs.get("content-type", "").startswith("text/csv")
          and generated["URL"]["token_value"].encode() not in csv_body and b"{token}" in csv_body,
          f"HTTP {status} rows={hdrs.get('x-export-rows')}")

    # Session renewal keeps the sign-in and the MFA level.
    status, renewed = edge.json(C, "POST", "/auth/refresh", token=sys_token)
    me_status, me_after = edge.json(C, "GET", "/auth/me", token=(renewed or {}).get("access_token", ""))
    check("session renewal issues a working token", status == 200 and me_status == 200,
          f"refresh={status} me={me_status}")
    _, sso = edge.json(C, "GET", "/auth/oidc/config")
    check("SSO configuration endpoint answers", isinstance(sso, dict) and "enabled" in sso, json.dumps(sso))

    if args.metrics_token:
        status, _, body = edge.request(C, "GET", "/metrics", headers={"Authorization": f"Bearer {args.metrics_token}"})
        check("metrics scrape", status == 200 and b"honeyshield_database_up 1" in body, f"HTTP {status}")
        check("metrics contain no token values", generated["URL"]["token_value"].encode() not in body)
        if args.expect_replicas > 1:
            # nginx spreads scrapes over the replicas; every replica must use the shared state, and
            # at least one must have received events published by another replica.
            scrapes = [edge.request(C, "GET", "/metrics",
                                    headers={"Authorization": f"Bearer {args.metrics_token}"})[2] for _ in range(12)]
            relayed = [int(float(line.split()[-1])) for b in scrapes for line in b.decode().splitlines()
                       if line.startswith("honeyshield_stream_relayed_in_total")]
            check("every replica uses the shared Redis state",
                  all(b"honeyshield_shared_state_up 1" in b for b in scrapes), f"{len(scrapes)} scrapes")
            check("live events are relayed between replicas", any(n > 0 for n in relayed), f"relayed_in={relayed}")

    # ------------------------------------------------------------- edge rate limit (last: it throttles this IP)
    if not args.skip_rate_limit:
        codes = [edge.request(I, "GET", f"/t/rl-{i}")[0] for i in range(120)]
        check("edge rate limit returns 429 on ingest floods", 429 in codes, f"429s={codes.count(429)}")

    failed = [r for r in RESULTS if not r[1]]
    print(f"\n{len(RESULTS) - len(failed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
