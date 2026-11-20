> **Superseded (2026-11-15).** The hook described here is now implemented; the authoritative contract is [customer-integrations.md](customer-integrations.md). This file is kept as the original design record.

# API_KEY detection: customer-side integration hook (design)

**Status: DESIGN ONLY. Automatic detection for `API_KEY` tokens is UNSUPPORTED.**
Generated API_KEY tokens carry `metadata.detection.status = "UNSUPPORTED"` until the
hook below is implemented and its tests pass. Nothing in this document is built yet.

## 1. Why a hook is required

A decoy API key is presented to the *customer's* systems (or, if leaked, to a
third-party API). HoneyShield never sees that request, so no HoneyShield-hosted URL
can detect it (see HONEY-004). Only code that already inspects incoming credentials can
notice a decoy being used, so detection has to be reported from the customer side.

## 2. Goals and non-goals

Goals
- Customers plant decoy keys in config files, repositories and internal docs.
- Customer authentication middleware recognises a presented decoy and reports it.
- **The presented key and any real `Authorization` header are never sent to HoneyShield.**
- Reports are authenticated, idempotent, and never slow down or alter the customer's auth path.
- Events are recorded with source `CUSTOMER_HOOK`, distinct from `PUBLIC_INGEST` and `MANUAL`.

Non-goals
- Detecting a decoy used against a third party (Stripe, OpenAI, ...). That is not observable.
- Detecting a decoy that is read but never used.
- Any change to URL, LINK, PIXEL or FORM_FIELD behaviour.

## 3. Components

1. **Decoy key** (generated today by `ApiKeyGenerator`).
2. **Decoy manifest**: an authenticated, read-only export of `{decoy_id, sha256(key)}` pairs
   for a project. Customer middleware keeps it in memory and refreshes it periodically.
3. **Integration credential**: a dedicated, per-project, report-only credential (section 5).
4. **Report endpoint** on the ingest host: `POST /integrations/v1/api-key-events`.
5. **Reference middleware snippets** (Python, Node) implementing section 7.

### 3.1 Decoy identity must not be the key
Today `honey_tokens.token_value` *is* the key, is the lookup key, and is returned by the
API. The hook needs an opaque public `decoy_id` (random, non-secret) so reports never
reference the key itself. This needs a new column or metadata field and is a prerequisite.

### 3.2 Matching without disclosure
The middleware hashes the presented credential (SHA-256; keys carry about 190 bits of
entropy so a plain hash is not brute-forceable) and looks it up in the manifest using a
constant-time comparison or hash-set lookup. On a hit it reports `decoy_id`; the key
itself is discarded. Decoys must not have a recognisable prefix beyond the provider style
requested, to avoid weakening the deception.

## 4. Report contract

`POST /integrations/v1/api-key-events` (JSON, `Content-Type: application/json`, TLS only)

| Field | Required | Rules |
|---|---|---|
| `decoy_id` | yes | Must belong to the integration's project; unknown or foreign ids return the same generic response |
| `idempotency_key` | yes | Client-generated, 16-64 chars, `[A-Za-z0-9_-]` |
| `observed_at` | yes | RFC 3339 UTC; rejected if more than 24 h old or in the future by more than 5 min |
| `source_ip` | yes | Valid IPv4/IPv6, as seen by the customer; stored normalised |
| `http_method` | no | Allowlisted verb |
| `request_path` | no | Max 2048 chars; the **path only**, query string stripped |
| `user_agent` | no | Truncated to 1024 chars |
| `headers` | no | Only the existing forensic allowlist (`core/header_security.py`) |

Strictness
- `extra="forbid"`: unknown fields are rejected, not ignored.
- Any field or header named like a credential (`authorization`, `api_key`, `token`, `cookie`, ...) is rejected with 422 and the offending **value is never logged or stored**.
- If a field value equals a known token value or manifest hash, the report is rejected and an audit entry written (guards against clients that leak the key by accident).
- Response is always `202` with `{"status":"accepted"}` for valid-looking reports, including duplicates and unknown `decoy_id`, to avoid creating an oracle.

## 5. Authentication of reports

Recommended: **HMAC-signed requests** with a dedicated integration credential.

- Credential = `{integration_id (public), secret (shown once)}`, scoped to one project, report-only (it cannot read events, manifests of other projects, or any other API), revocable, rotatable with an overlap window. Created by a TENANT_ADMIN and audited.
- Headers: `X-HS-Integration`, `X-HS-Timestamp`, `X-HS-Signature = HMAC-SHA256(secret, METHOD "\n" PATH "\n" TIMESTAMP "\n" SHA256(body))`.
- Server verifies: signature in constant time, timestamp within +/-5 min, integration active, project/tenant active.
- Storage trade-off: HMAC needs the secret recoverable server-side, so it is stored encrypted with an application key (new secret to manage). The simpler alternative, a bearer secret stored only as a hash, avoids that but gives no body integrity or replay window. Decide before implementation.
- The manifest endpoint uses the same credential family but a separate read scope.

## 6. Recording

- New non-null column `detection_events.source` enum: `PUBLIC_INGEST | MANUAL | CUSTOMER_HOOK`. This is the same column HONEY-006 needs, so it must land **first** and be shared.
- New nullable columns: `integration_id` and `idempotency_key`, with a unique constraint on `(integration_id, idempotency_key)`. A duplicate returns the original result and inserts nothing.
- Severity comes from a per-type default, not the client.
- **Provenance is weaker for `CUSTOMER_HOOK`:** `source_ip`, `user_agent` and `observed_at` are asserted by the customer, not observed by HoneyShield. The UI and API must label them so and analytics must be able to filter by source.
- Reports use their own bounded rate limiter, separate from the public ingest limiter, and must never be dropped silently for a valid integration (aggregate instead, per HONEY-001).

## 7. Customer-side requirements (integration contract)

1. Check credentials as today; run the decoy check without changing the auth decision. A decoy match must still be **rejected** exactly like any invalid key, with the same response and timing as far as practical.
2. Reporting is **non-blocking**: enqueue to a bounded in-memory queue and return immediately. Send from a background worker.
3. Per-report timeout (suggested 2 s), at most 3 attempts with exponential backoff and jitter, then drop. Queue full means drop the oldest report; never block or raise into the request path.
4. Generate `idempotency_key` deterministically per event (for example hash of `decoy_id + source_ip + minute`) so retries and repeated hits collapse.
5. Never include the presented credential, the `Authorization` header, cookies, request bodies or query strings.
6. Keep the integration secret in the customer's secret store; rotate on staff changes.
7. Refresh the manifest at least every few minutes and on startup. Failure to refresh must not break authentication.

## 8. Limitations (to document for customers)

- Detects only use of the decoy against systems that run the middleware.
- Misses decoys that are copied but never used, or used against third parties.
- Best-effort delivery: if the customer's worker is down or the queue overflows, an event is lost. There is no replay.
- Source IP and timestamps are customer-asserted; behind proxies they depend on the customer's own trusted-proxy configuration.
- A compromised customer middleware can suppress or forge reports.
- Decoys planted where legitimate scanners or CI read them may produce false positives if those tools attempt authentication.
- Revoked decoys should stay in the manifest so reuse is still reported.

## 9. Required tests (not yet written)

1. **Valid report**: signed report for an own-project decoy is accepted; one event stored with `source = CUSTOMER_HOOK`, correct tenant/project, normalised IP.
2. **Invalid credentials**: bad signature, expired or future timestamp, replayed signature outside window, revoked integration, integration from another project or tenant, inactive tenant. All rejected, no event stored.
3. **Duplicate reports**: same `idempotency_key` returns accepted but stores exactly one event, including under concurrent submission.
4. **Metadata sanitization**: credential-like fields or headers rejected; unknown fields rejected; key or manifest-hash values rejected; query strings stripped; oversized values truncated or rejected; the key never appears in the database, audit log or application log.
5. **No oracle**: unknown and foreign `decoy_id` give the same response as a valid one.
6. **Reference middleware**: queue is bounded, retries are bounded, reporting failure never changes or delays the auth result.
7. **Source separation**: `PUBLIC_INGEST` and `MANUAL` events are unaffected and filterable apart from `CUSTOMER_HOOK`.

## 10. Prerequisites and ordering

1. `detection_events.source` column and provenance work (HONEY-006).
2. Opaque `decoy_id` separate from the key.
3. Valid-hit-preserving rate limiting (HONEY-001).
4. Least-privilege runtime database role (HONEY-002), so integration credentials and evidence are not exposed to a superuser connection.
5. Then this feature.

Until then API_KEY stays a supported token type whose automatic detection is **UNSUPPORTED**.
