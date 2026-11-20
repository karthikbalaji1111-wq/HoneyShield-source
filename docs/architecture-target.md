# HoneyShield target architecture and the remaining gap

What the as-is system (`architecture-as-is.md`) still lacks for larger or multi-node
deployments, in priority order. Nothing here is implemented unless stated.

| # | Gap | Why it matters | Planned approach |
|---|---|---|---|
| 1 | Process-local rate limiting and live fan-out (HONEY-026) | Prevents >1 API process; one host is a single point of failure | Redis (or PostgreSQL) shared counters; LISTEN/NOTIFY or Redis pub/sub for stream fan-out. Until then: one API process, enforced in compose and documented |
| 2 | No partitioning of `detection_events` (HONEY-011) | Retention would need row DELETEs, which the immutability design forbids | Monthly range partitions on `triggered_at`; retention = detach + archive + drop partition with an audited, two-person procedure. Requires re-keying (`PRIMARY KEY (id, triggered_at)`) and moving FKs from evidence_chain/outbox_events; designed, not built |
| 3 | No password reset or SSO; TOTP is the only second factor (HONEY-029, MFA done) | Operator accounts are the highest-value target | WebAuthn/passkeys for phishing resistance; OIDC SSO for organisations with an IdP; password reset needs an email channel |
| 4 | Alert channels: webhook (signed JSON) and Slack/Teams-compatible text only | Email/SIEM-native adapters missing | Add adapters behind the existing outbox; no change to the detection path |
| 5 | Evidence checkpoints written to a local volume | A host compromise can delete them | Ship to object storage with retention lock (S3 Object Lock compliance mode or equivalent); adapter interface is `WriteOnceDirectory` |
| 6 | Audit logs are append-only but not hash-chained | Tampering by a DB superuser is not detectable for audit rows | Extend the chain to `audit_logs` (same design as detection events) |
| 7 | Analytics aggregate raw events (0.45-0.7 s at 1M events per scope) | Will degrade past ~10M events per tenant | Hourly rollup tables per (tenant, ip) maintained by the worker |
| 8 | Webhook delivery verified only against a local receiver | External delivery not exercised in this environment | Verify against a staging receiver before go-live (release checklist) |

## Target topology (multi-node)

```
           ┌──────── load balancer (TLS) ────────┐
   app.example.com                         ingest.example.com
           │                                     │
     API pods (N) ◄── shared limiter / pubsub (Redis) ──► API pods (N)
           │                                     │
           └──────────► PostgreSQL (primary + replica, PITR) ◄──── workers (N, SKIP LOCKED)
                                 │
                       checkpoints + exports ──► object storage (retention lock)
```
Workers already support N replicas (lease + SKIP LOCKED). API pods do not until gap 1 is closed.
