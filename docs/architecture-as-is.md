# HoneyShield architecture (as implemented)

Status date: 2026-11-15. Describes the code in this repository, not a plan. Anything not
implemented is listed in `architecture-target.md`.

## 1. Components

| Component | Code | Runs as | Network |
|---|---|---|---|
| Edge proxy | `proxy/templates/default.conf.template` (nginx 1.28) | container `nginx` | `public_net` + `internal_net` (fixed IP) |
| API (control plane + ingest routes) | `backend/app` (FastAPI, 1 uvicorn worker) | container `backend`, DB role `honeyshield_app` | `internal_net` only (no internet) |
| Alert worker | `backend/app/workers/outbox.py` | container `worker`, DB role `honeyshield_app` | `internal_net` + `egress_net` |
| Evidence checkpointer | `backend/app/workers/evidence.py` | container `checkpointer`, DB role `honeyshield_app` | `internal_net` |
| Migration job | Alembic + `app/db/privileges.py` | one-shot `migrate`, DB role `honeyshield_owner` | `internal_net` |
| Database | PostgreSQL 16 | container `postgres` | `internal_net` only |
| Operator console | `frontend/console` (static, vanilla JS) | served by nginx under `/console/` | same origin as API |
| Customer hook (reference) | `integrations/python/honeyshield_hook.py` | inside the customer's application | customer -> ingest host |

Shared state between API replicas (rate-limit windows, live-stream relay) lives in Valkey, the BSD-licensed,
Redis-protocol-compatible store (container `redis`, `internal_net` only, no persistence). If it is down,
limits fall back to per replica and detection is unaffected.

## 2. Domain model

```
Tenant 1─* Project 1─* HoneyToken 1─* DetectionEvent 1─1 EvidenceChainLink
   │          │             │                 └─* OutboxEvent *─1 AlertDestination
   │          └─* IntegrationCredential ──────────┘ (CUSTOMER_HOOK events reference it)
   └─* User (SYSTEM_ADMIN: no tenant)      AuditLog (append-only, tenant-scoped)
```

* `HoneyToken.token_value` is the secret value embedded in artifacts; `decoy_id` is an opaque
  public identifier used by integrations so the value never has to be transmitted.
* `DetectionEvent.source` ∈ {PUBLIC_INGEST, CUSTOMER_HOOK, MANUAL, LEGACY_UNVERIFIED}.
* Evidence tables (`detection_events`, `audit_logs`, `evidence_chain`) are append-only:
  PostgreSQL triggers reject UPDATE/DELETE/TRUNCATE and the runtime role has only SELECT/INSERT.

## 3. Request paths

### 3.1 Public detection (URL, LINK, PIXEL)
```
attacker ─https─► nginx (ingest vhost: /t/ /px/ /collect/ only, limit_req)
        ─► HostRoutingMiddleware (ingest host => ingest routes only)
        ─► ingestion router: resolve token by indexed lookup FIRST
             valid  -> per-(IP,token) evidence counter (fails open) -> persist
             invalid -> nothing stored
           response decided ONLY by the caller's request rate (no validity oracle)
        ─► one DB transaction: DetectionEvent + EvidenceChainLink + OutboxEvent(s)
        ─► commit ─► in-process live broadcast (best effort, value-redacted)
```
Client IP: the backend trusts `X-Forwarded-For` only from the nginx container's fixed IP and
reads it right-to-left (`app/core/ip_trust.py`). Nginx overwrites the header with `$remote_addr`.

### 3.2 Customer-hook detection (API_KEY, FORM_FIELD)
```
customer app (reference hook) ─ manifest: GET /integrations/v1/manifest (signed)
  presented key -> sha256 -> manifest match -> enqueue (non-blocking)
  background sender ─ POST /integrations/v1/events (HMAC-signed, idempotency key)
     ─► nginx ingest vhost ─► signature + timestamp + credential/tenant state checks
     ─► decoy must belong to the credential's project (else identical 202)
     ─► unique (integration, idempotency_key) => duplicates/replays store nothing
     ─► same transaction as 3.1 (event + chain link + outbox), source CUSTOMER_HOOK
```

### 3.3 Alerting
```
worker loop: UPDATE ... WHERE id IN (SELECT ... FOR UPDATE SKIP LOCKED) -> lease
  resolve webhook host -> every address public? -> connect to that IP (SNI = host)
  signed POST -> 2xx DELIVERED | 4xx (not 408/425/429) DEAD | else retry w/ backoff
  max attempts -> DEAD + ALERT_DELIVERY_FAILED audit
```

### 3.4 Operators
`/auth/login` -> short-lived HS256 JWT bound to `users.token_version`. Every request re-reads
the user (active, tenant active, token version). Streams re-check every 30 s, end at the JWT
`exp`, and end on role/tenant change. Logout and password change bump `token_version`.

## 4. Trust boundaries

1. Internet -> nginx: TLS 1.2/1.3 only; unknown Host -> 444; per-vhost rate limits.
2. Ingest vhost -> backend: only four route prefixes exist; enforced by nginx AND the app.
3. Backend -> PostgreSQL: runtime role cannot run DDL, own tables, or modify evidence; the API
   refuses to start if it can (`app/db/runtime_guard.py`).
4. Customer -> HoneyShield: integration credentials are report/manifest-only and project-scoped.
5. Worker -> internet: only public unicast addresses; DNS re-checked per delivery.
6. Database admin -> evidence: not prevented; detected by the hash chain + external checkpoints.

## 5. Process-local state (single worker)

Rate limiters (`app/core/rate_limit.py`) and the live-stream broadcaster are in-process. The
deployment therefore runs exactly one API process (`--workers 1`, `replicas: 1`). Durable
alerting does not depend on this (outbox is in PostgreSQL). See `architecture-target.md`.
