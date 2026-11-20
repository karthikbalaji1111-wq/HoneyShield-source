# HoneyShield — Rate Limiting Architecture & Security Boundaries
**Document Version:** 1.0  
**Target Environment:** Container Runtime & Ingress  
**Classification:** Architecture Specification & Threat Model

---

## 1. Admission Control & Rate Limiting Architecture

HoneyShield implements an in-memory, thread-safe admission control subsystem centered around `FixedWindowLimiter` (`backend/app/core/rate_limit.py`).

### Key Dimensions & Quotas:
| Category | Metric / Key | Default Quota | Behavior upon Exceeded Limit |
| :--- | :--- | :--- | :--- |
| **Authenticated API** | `user_id:<ID>` | 300 req / min | 429 Too Many Requests (`Retry-After: <secs>`) |
| **Public / Anonymous API** | `public_ip:<IP>` | 120 req / min | 429 Too Many Requests (`Retry-After: <secs>`) |
| **Global API Threshold** | Total requests in window | 5000 req / min | 429 Too Many Requests |
| **Login Protection** | `login_ip:<IP>` | 30 req / min | 429 Too Many Requests |
| **Ingestion response rate** | `ingest_ip:<IP>`, all requests valid or not | 120 req / min | 429 Too Many Requests, identical for valid and invalid tokens |
| **Ingestion evidence cap** | `valid:<IP>:<token id>`, valid tokens only | 60 stored events / min | Repeats are not stored individually; the first one over the cap writes one `DETECTION_HITS_SUPPRESSED` audit record. The response is **not** changed |
| **Integration auth failures** | `intfail:<IP>` | 30 failures / min | 429 for that IP; valid integrations elsewhere unaffected |
| **Integration reports** | `int:<integration id>` (after authentication) | 1200 / min (`INTEGRATION_REPORTS_PER_MINUTE`) | 429 with Retry-After (visible to the customer, never a silent drop) |
| **Hook evidence cap** | `hook:<integration>:<decoy>:<IP>` | 60 stored events / min | 202; summarised by one `DETECTION_HITS_SUPPRESSED` audit record |
| **Password change** | `pwchange:<user id>` | 5 / min | 429 |
| **Live streams** | broadcaster | 500 total, 25 per tenant | SSE 429 / WebSocket close 1013 |

### Edge limits (nginx, per client IP; `proxy/templates/default.conf.template`)
| Zone | Applies to | Rate | Burst |
|---|---|---|---|
| `hs_ingest` | `/t/ /px/ /collect/` on the ingest host | `HS_EDGE_INGEST_RPS` (20 r/s) | 40 |
| `hs_hook` | `/integrations/v1/` | `HS_EDGE_HOOK_RPS` (50 r/s) | 200 |
| `hs_api` | control-plane API and streams | `HS_EDGE_API_RPS` (30 r/s) | 60 |
| `hs_login` | `/auth/login` | 10 r/min | 5 |
Connections per IP: 50 (ingest) / 100 (control). Verified on 2026-11-15: a 120-request burst on
the ingest host produced 60 × 429 at the edge.

### Public ingestion evidence guarantee (HONEY-001)
- The token is resolved **before** any limiter decision. A hit on a valid token is stored even
  when the response limiter, its global budget, or its key table is exhausted. Attacker noise
  can no longer blind detection.
- The evidence counter is a separate limiter instance. When its key table is full it **fails
  open**: the hit is stored.
- The HTTP response depends only on the caller's request rate, never on token validity, so
  the ingestion endpoints cannot be used to test whether a value is a honey token.
- Cost: one indexed lookup per ingestion request, including invalid ones. Bound this at the
  edge with Nginx `limit_req` on the ingest host.
- Values longer than 512 characters (the stored maximum) are rejected without a lookup.
- Severity of a public hit comes from the token type (URL/PIXEL: HIGH, LINK/FORM_FIELD:
  MEDIUM, API_KEY: CRITICAL), not from the route.

### Client IP resolution (HONEY-005)
Forwarding headers are honoured only when the direct peer is in `TRUSTED_PROXIES`.
`X-Forwarded-For` is then walked **right to left**, skipping trusted proxies, and the first
untrusted address is the client. The left-hand entries can be written by the client and are
never used. Ingestion, login and the API rate limiter share one implementation
(`app/core/ip_trust.py::resolve_client_ip`).

---

## 2. Memory Bounds & Fail-Closed Saturation Policy

### Bounded Memory Guarantees
To prevent adversarial memory exhaustion (e.g. an attacker distributing requests across millions of spoofed IP addresses or random bearer tokens):
1. **Maximum Key Capacity (`max_keys = 4096`):**
   The internal dictionary maintains at most 4096 tracking keys per limiter instance.
2. **Fail-Closed Admission:**
   If the dictionary reaches `max_keys` within an active 60-second window, any *new, untracked* key is immediately rejected (`429 Too Many Requests`) with a valid `Retry-After` header.
3. **Preservation of Existing Clients (No Key Eviction):**
   Existing clients already in the dictionary are NOT evicted. They continue to be serviced up to their individual quota limits.
4. **Deterministic Time-Window Reclamation:**
   At the rollover of the window (`time.monotonic() // window_seconds`), the dictionary is atomically cleared (`self._counts.clear()`), restoring capacity for all keys.

### Memory Overhead Bound:
- 4096 keys $\times$ ~100 bytes/entry $\approx$ ~400 KB of RAM maximum. Memory consumption cannot grow unbounded under denial-of-service attacks.

---

## 3. Cryptographic Token Pre-Verification Invariant

A common architectural vulnerability in rate limiting is granting elevated authenticated quotas based solely on the presence of an `Authorization: Bearer <token>` header without cryptographic verification.

In HoneyShield (`backend/app/middleware/rate_limit.py`):
1. The middleware parses `Authorization: Bearer <token>`.
2. It performs cryptographic signature verification and expiration checking using `jwt.decode(..., algorithms=["HS256"])` with `settings.jwt_secret_key`.
3. **If signature verification fails:** The client is NOT granted the authenticated bucket (300/min). It is demoted to the `public_ip:<IP>` bucket (120/min).
4. **Key Table Defense:** An attacker sending random/forged tokens from a single IP will all map to a single `public_ip:<IP>` bucket, completely neutralizing attempts to saturate the 4096-key capacity with fake tokens.

---

## 4. Single-Worker vs Distributed Architectural Boundary

> [!IMPORTANT]
> **Process-Local State Limitation:**
> In the standard single-process HoneyShield container (`--workers 1`), `FixedWindowLimiter` provides complete thread-safe admission control.
>
> However, if the deployment scales to multiple Uvicorn workers (`--workers > 1`) or multiple container replicas without sticky session routing, each worker process maintains independent counter buckets in its local heap.
>
> **Future Work:** Distributed multi-container deployments should configure an external Redis backend for cluster-wide rate limit synchronization (architecture-target.md #1). The alert worker is already safe to scale (SKIP LOCKED leases).

---

## 5. Forensic Immutability Security Boundary

HoneyShield implements defense-in-depth for forensic records (`detection_events` and `audit_logs`):

1. **Layer 1: PostgreSQL Trigger Invariants:**
   PostgreSQL `BEFORE UPDATE`, `BEFORE DELETE`, and `BEFORE TRUNCATE` triggers (`prevent_forensic_modification()`) unconditionally raise exceptions for any mutation.
2. **Layer 2: SQL Table Grants (Principle of Least Privilege):**
   The runtime database role (`honeyshield_app`) only possesses `SELECT` and `INSERT` grants on forensic tables (`detection_events`, `audit_logs`, `evidence_chain`). `UPDATE`, `DELETE`, and `TRUNCATE` are denied at the SQL permission layer. Applied by `python -m app.db.privileges grant` (see database-roles.md); verified on real PostgreSQL.
3. **Layer 3: Non-Owner Table Restriction:**
   Because `honeyshield_app` does not own the forensic tables, it is prohibited by PostgreSQL from running `ALTER TABLE detection_events DISABLE TRIGGER ALL`.
