# Security model

## Identities and authorization

| Role | Scope | Can |
|---|---|---|
| SYSTEM_ADMIN | all tenants (no tenant) | tenants, users of any tenant, everything below; at least one must remain active (enforced with row locks) |
| TENANT_ADMIN | own tenant | projects, decoys (generate/rotate/revoke), integrations, alert destinations, manual events (with reason), audit log, evidence verification, tenant users |
| TENANT_USER | own tenant | read projects, decoys (values **masked**), events (paths masked), threat analytics, live feed |
| Integration credential | one project | read that project's manifest, report its decoys |

Tenant isolation is enforced in SQL (tenant predicates in repositories/services), not in the UI.
Cross-tenant object access returns 404 (no existence oracle) and writes `TENANT_ACCESS_DENIED`
in an independent transaction (never committing the caller's pending work).

## Authentication

* Passwords: bcrypt; 12+ chars for changes, ≤72 UTF-8 bytes; login compares against a dummy hash
  for unknown emails (no timing/enumeration oracle); emails are case-insensitive and unique on
  `lower(email)`.
* Tokens: HS256 JWT (algorithm pinned, `sub`/`exp`/`ver` required, `amr` = `pwd`|`mfa`, `crit` rejected, ≤4 KiB),
  30 min default; bound to `users.token_version`, which logout, password change, role/tenant
  change, deactivation and password reset by an admin all increment.
* Renewal: `POST /auth/refresh` issues a new token with the same `amr` and the original
  `auth_time` (sign-in time). It refuses once `SESSION_MAX_HOURS` (12) have passed since sign-in,
  and refuses revoked, expired, MFA-pending and API-key callers. The console renews 5 minutes
  before expiry only if the operator was active in the last 25 minutes, so idle consoles still
  time out after 30 minutes.
* Every request re-checks the user and tenant are active. Live streams: re-checked every 30 s,
  closed at JWT expiry, on role/tenant change, deactivation or revocation.
* Rate limits: login 30/min/IP (+10/min at the edge), password change 5/min/user.
* Per-account failure budget: after `LOGIN_ACCOUNT_FAILURES_ALLOWED` (10) wrong passwords for an
  address within `LOGIN_ACCOUNT_FAILURE_WINDOW_SECONDS` (15 min), from any IPs, sign-in for that
  address is refused with 429 (and audited) until the window slides. Unknown addresses are
  counted the same way, so the 429 reveals nothing about which accounts exist. The check runs
  before any password hashing. Trade-off: an attacker can keep a known address locked out for a
  while; administrators can see `AUTH_ACCOUNT_THROTTLED` in the audit log. Limits are
  shared by every API replica through Redis (per-replica fallback if Redis is down).
* **Operator MFA (TOTP, RFC 6238)** — HONEY-029:
  * Roles in `MFA_REQUIRED_ROLES` (default in production: `SYSTEM_ADMIN,TENANT_ADMIN`) must use
    MFA. Until they enrol, a password login yields an *MFA-pending* session that can reach only
    `/auth/me`, `/auth/logout`, `/auth/mfa/setup` and `/auth/mfa/enable`; everything else
    (including streams) is 403 `MFA enrolment required`.
  * Once enrolled, login needs `otp` (a TOTP code or a one-time recovery code). Password-only
    tokens of an enrolled account are refused (401), so enabling MFA ends older sessions.
  * Secrets are never stored: `HMAC-SHA256(MFA_SECRET_KEY, "honeyshield-totp-v1|id|nonce")[:20]`;
    re-enrolment changes the nonce. Recovery codes (10, ~50 bits each) are stored as keyed
    HMAC hashes and removed when used.
  * Replay: a code's 30 s step must be newer than the last accepted step (row-locked).
    ±1 step of clock drift is accepted. 5 second-factor attempts per minute per account on top
    of the per-IP login limit.
  * "MFA code required" is returned only after a correct password, so it reveals nothing new.
  * Lost device: another administrator resets it (`POST /api/v1/users/{id}/mfa/reset` with an
    audited reason); this revokes the user's sessions. Nobody can reset their own MFA.
  * Every enrolment, failure, recovery-code use, disable and reset is audited.
  * Residual risk: until an admin enrols, whoever holds their password can enrol an authenticator
    of their own. Enrol at the first sign-in after an account is created; an unexpected
    `MFA_ENABLED` audit entry is an incident (reset the user's MFA and password).
* **Password reset** (stateless, single-use links, 30 min):
  * The token is `user id.expiry.HMAC(key, id|expiry|current password hash|token_version)`.
    Nothing is stored. Using the link changes the hash, which kills it; logging out everywhere
    or an MFA reset kills it too. The key is derived from `JWT_SECRET_KEY` with its own label.
  * *Administrator-issued:* `POST /api/v1/users/{id}/password-reset` with an audited reason.
    Scope follows user management: tenant admins act in their tenant only, and nobody resets
    their own account this way. It returns the link once.
  * *Self-service* (when SMTP is configured): `POST /auth/password-reset/request` answers 202 the
    same way for known and unknown addresses. The API only queues the mail, and the alert worker
    sends it: the API has no internet egress. The queue row holds just the user id, and the
    worker builds the single-use link at send time, so the database never holds a usable link.
    Mail not sent within 15 minutes expires; delivery retries with backoff, up to 5 attempts. Limits: 5 requests/min per IP, 3 per address per 15 min. Unknown
    addresses are audited with the domain only.
  * Completing (`/auth/password-reset/confirm`) applies the password policy (12+ chars, ≤72
    bytes), revokes every session and audits `PASSWORD_RESET_COMPLETED`. Invalid links are
    audited (`PASSWORD_RESET_FAILED`) and limited to 10/min per IP.
  * A reset never removes MFA: an enrolled user still needs the authenticator or a recovery code.
  * The console carries the token in the URL fragment (`/console/#reset=…`), which browsers
    never send to servers or in `Referer`. The page removes it from history after use.
* **Personal API keys** (`hsk_<id>.<secret>`, 256-bit secret):
  * Only `HMAC-SHA256(key derived from JWT_SECRET_KEY, id|secret)` is stored.
  * A key acts as its owner, with role, tenant and active status read live, so disabling the
    user disables the key. Keys expire (1–365 days, default 90); there are at most 25 active
    per user.
  * Read keys allow GET/HEAD only.
  * Keys can never manage users or keys, and never reach `/auth/*` or streams. Creating a key
    needs a full session, including MFA, so a key cannot mint keys.
  * Invalid keys are counted per source IP: after 20 a minute, requests from that IP are refused
    before any database lookup. Valid keys have a per-key budget. At the edge, every key request
    from one IP shares one bucket, so inventing key ids gains nothing.
  * `last_used_at` is recorded at most once a minute; creation and revocation are audited.
    Owners, tenant admins (in their tenant) and system admins can revoke.
* **Single sign-on (OIDC)**: authorization code + PKCE, signed flow cookie, JWKS-verified ID
  tokens, one-time hand-off code, pre-provisioned users only; MFA level from the IdP's `amr` or an
  explicit trust setting. Details: `docs/sso.md`.

## Decoy secrecy

Token values are secrets. They are never chosen by tenants (no cross-tenant uniqueness oracle),
masked for TENANT_USER, removed from live-stream payloads and alert payloads (`{token}`), never in
metrics, and customer integrations exchange only `decoy_id` and SHA-256 hashes.

## Public surfaces

| Surface | Exposure | Controls |
|---|---|---|
| Ingest host | `/t/`, `/px/`, `/collect/`, `/integrations/v1/` only | nginx route allowlist + app host routing; 16 KiB bodies; edge limit 20 r/s/IP (burst 40); identical responses for valid and invalid tokens; valid hits stored even when limiters are saturated |
| Control host | API, auth, streams, console, `/metrics` (token) | TLS, HSTS, CSP, CORS allowlist, 1 MiB bodies, header limits, per-user/IP limits, docs off in production |
| Unknown Host | – | 444 at the edge, 404 in the app |

## Data protection

* Evidence append-only at the DB-privilege, ownership and trigger layers; hash chain +
  signed checkpoints for detection (evidence-integrity.md).
* Audit metadata is sanitised; secrets (passwords, tokens, integration secrets, presented keys)
  are never logged or stored. Integration and webhook secrets are derived, not stored.
* Request IDs from clients are accepted only as short opaque tokens.

## Infrastructure

Non-root containers (UID 10001), read-only root filesystems, `cap_drop: ALL`,
`no-new-privileges`, memory/CPU limits, log rotation; PostgreSQL and the API on an internal
network with no internet route; only the worker has egress; nginx is the only public listener.
