# Customer integrations (CUSTOMER_HOOK) — contract v1

**Status: IMPLEMENTED and tested** (`backend/tests/integrations/test_customer_hook.py`,
`tests/postgres/test_api_on_postgres.py`, live deployment verification). Supersedes the design in
`api_key_detection_design.md`.

Used by decoys whose use only the customer's own code can observe:

| Decoy | What the customer code checks | Severity |
|---|---|---|
| `API_KEY` | SHA-256 of a presented credential matches a manifest entry | CRITICAL |
| `FORM_FIELD` | the honeypot field (`field_name`) was submitted non-empty | MEDIUM |
| `AD_ACCOUNT` | a domain controller logged an event naming the decoy account ([§6](#directory-decoys)) | CRITICAL / HIGH |

Use of a decoy key against third-party services, and decoys copied but never used, are **not
detectable**.

## 1. Credentials

A TENANT_ADMIN creates a credential per project (console: *Integrations*, or
`POST /api/v1/projects/{domain}/integrations`). The response contains `integration_id`
(public) and `secret` (shown once; HoneyShield stores only a salt and re-derives it from
`INTEGRATION_SIGNING_KEY`). Credentials can only fetch that project's manifest and report its
decoys. Revoke with `POST .../integrations/{id}/revoke`; rotate by creating a new one, deploying
it, then revoking the old one.

## 2. Request signing

```
X-HS-Integration: <integration_id>
X-HS-Timestamp:   <unix seconds>             (must be within ±300 s of server time)
X-HS-Signature:   v1=<hex HMAC-SHA256(secret, canonical)>
canonical = "v1\n" + METHOD + "\n" + PATH + "\n" + TIMESTAMP + "\n" + hex(SHA256(body))
```
PATH excludes the query string. Any authentication failure returns `401
{"detail":"Integration authentication failed"}` regardless of cause. More than 30 failures per
minute from one IP returns 429.

## 3. Endpoints (ingest host only)

`GET /integrations/v1/manifest` →
```json
{"version":1,"generated_at":"…","decoys":[
  {"decoy_id":"dcy_…","token_type":"API_KEY","is_active":true,"sha256":"<hex>"},
  {"decoy_id":"dcy_…","token_type":"FORM_FIELD","is_active":true,"field_name":"website"}]}
```
Revoked decoys stay listed: reuse of a retired decoy is still worth reporting.

`POST /integrations/v1/events` (≤16 KiB, unknown fields rejected):

| Field | Required | Rules |
|---|---|---|
| `decoy_id` | yes | `dcy_` + 24 hex |
| `idempotency_key` | yes | 16-64 of `[A-Za-z0-9_-]`; same key = stored once |
| `observed_at` | yes | RFC 3339 with timezone; within the last 24 h, ≤5 min in the future |
| `source_ip` | yes | IPv4/IPv6 as determined by *your* trusted-proxy logic |
| `http_method` | no | GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS |
| `request_path` | no | path only; query and fragment are dropped |
| `user_agent` | no | truncated to 1024 chars |
| `headers` | no | ≤20; any name containing authorization/cookie/token/secret/password/api-key/session/credential/signature → 422 |

Responses: `202 {"status":"accepted"}` for every authenticated, well-formed report — including
duplicates, unknown decoys and decoys of other projects (no oracle). `422` for malformed reports
or a report that contains the decoy key itself (rejected, audited, value never stored or logged).
`429` when the per-integration rate (default 1200/min) is exceeded. Reports beyond 60/min for the
same (decoy, source IP) are acknowledged but stored once per minute with a
`DETECTION_HITS_SUPPRESSED` audit record.

## 4. Customer-side requirements

1. Make your authentication decision exactly as before; a decoy key must be rejected like any
   invalid key. The hook never changes or delays it.
2. Report asynchronously from a bounded queue (reference: 10,000 entries, drop-oldest only when
   full), 2 s timeout; keep a report that cannot be delivered and retry it with exponential backoff
   and jitter (reference: up to 60 s between rounds) until it is accepted; do not retry 4xx except 429.
3. Derive `idempotency_key` deterministically (reference: SHA-256 of decoy|ip|minute).
4. Never send the presented credential, `Authorization`, cookies, bodies or query strings.
5. Keep the secret in your secret store; refresh the manifest every few minutes.

The reference implementation (`integrations/python/honeyshield_hook.py`, stdlib only, Python
3.9+) does all of the above:
```python
hook = HoneyShieldHook("https://ingest.example.com", os.environ["HONEYSHIELD_INTEGRATION_ID"],
                       os.environ["HONEYSHIELD_INTEGRATION_SECRET"],
                       spool_path="/var/lib/myapp/honeyshield-hook.jsonl")   # optional: survive restarts
hook.start()
...
hook.stop()   # on shutdown: undelivered reports are saved to spool_path and sent after the next start
hook.check_api_key(presented_key, source_ip=client_ip, http_method=method, request_path=path)
hook.check_form(form_data, source_ip=client_ip, request_path=path)
```

## 5. Provenance and limitations

Events are stored with `source = CUSTOMER_HOOK`, the reporting `integration_credential_id` and
the idempotency key; IP, path and time are **asserted by the customer**, not observed by
HoneyShield. A compromised customer application can suppress or forge reports for its own
project only. An outage of HoneyShield delays reports but does not lose them: the reference client
keeps and retries them, with the same idempotency key so nothing is stored twice. Reports are lost
only if the queue overflows (10,000 by default) or the customer's process crashes before reporting;
with `spool_path`, a graceful restart keeps them.

<a id="directory-decoys"></a>
## 6. Directory decoys (Active Directory)

[Active Directory decoys](active-directory-decoys.md) use the same credentials and signing, with
their own two endpoints. The shipped collector is `HoneyShield-DCCollector.ps1` (the decoy's
`dc-collector` file).

`GET /integrations/v1/directory-manifest` lists one entry per account name: the active decoy, or
the newest revoked one if none is active. Calling it updates the credential's *last used* time, so
the console shows that a controller checked in.
```json
{"version":1,"generated_at":"…","decoys":[
  {"decoy_id":"dcy_…","account_name":"svc_sqlbackup","spn":"MSSQLSvc/sqlbak01:1433","audit_reads":false,"is_active":true}]}
```

`POST /integrations/v1/directory-events` carries one Windows Security event. It is at most 16 KiB,
and unknown fields are rejected.

| Field | Required | Rules |
|---|---|---|
| `decoy_id`, `idempotency_key`, `observed_at` | yes | as for `/events` |
| `windows_event_id` | yes | 4624, 4625, 4662, 4768, 4769, 4771 or 4776 |
| `succeeded` | yes | `true` for Audit Success, `false` for Audit Failure |
| `domain_controller` | yes | host name of the controller that logged it |
| `target_name` | yes | the account the event names (`ServiceName` for 4769); it must be the decoy's account, compared case-insensitively and without any `DOMAIN\` or `@realm` part; otherwise `422` |
| `source_ip` | no | `IpAddress`; `::ffff:` IPv4 addresses are unwrapped; when it is absent, `0.0.0.0` is stored |
| `workstation` | no | `WorkstationName` or `Workstation` |
| `actor` | no | the requesting account (4769 `TargetUserName`) or the reader (4662 `SubjectDomainName\SubjectUserName`) |
| `status` | no | `Status` (`SubStatus` for 4625), e.g. `0x18` |
| `logon_type` | no | 0-13 |
| `ticket_encryption` | no | `TicketEncryptionType`, e.g. `0x17` |
| `record_id` | no | `EventRecordID` |

Text fields reject control characters. HoneyShield derives the event's request (`AD ad/<kind>`),
severity and ATT&CK technique from `windows_event_id` and `succeeded`, never from the reporter.
Responses and rate limits are as for `/events`. An AD decoy cannot be reported through `/events`,
and an HTTP decoy cannot be reported through `/directory-events`. Both are accepted and not stored.
