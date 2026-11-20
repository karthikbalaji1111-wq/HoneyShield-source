# Production readiness

## Classification: **Deployment candidate**

(Scale: engineering alpha → internal beta → **deployment candidate** → production candidate →
production ready.) The system works end to end on its real stack, on Docker Compose and on
Kubernetes, and every critical release gate that can be exercised without the owner's accounts
passes (2026-11-17). It becomes a production candidate once it has run in a real environment:
CI on GitHub, staging with real DNS and certificates, and real alert/WORM/IdP endpoints (below).

## Critical gates

| Gate | Status | Evidence |
|---|---|---|
| Valid decoy interactions are detected (all 5 types) | PASS | E2E: URL/LINK/PIXEL via ingest host, API_KEY/FORM_FIELD via hook, exactly one event each with correct source and severity |
| Artifacts point at a functioning ingest host | PASS | E2E artifact host checks; host-separation tests |
| Floods cannot suppress valid hits | PASS | tests under limiter/key-table saturation; edge returns 429 while valid hits stay recorded |
| Tenant isolation | PASS | per-resource cross-tenant tests (tokens, events, projects, integrations, destinations, audit, evidence, streams) |
| Manual events cannot masquerade | PASS | `source` + CHECK constraints on PostgreSQL; reason + audit |
| Runtime DB credentials cannot rewrite/delete evidence | PASS | real PostgreSQL as `honeyshield_app`; live probes on the deployed DB |
| Durable alerting | PASS | outbox + worker; deployed worker delivered signed test and real alerts to an HTTPS receiver (private network, private CA); email and syslog against real local servers |
| AuthN/AuthZ tests | PASS | 731/731 tests (PostgreSQL, S3 Object Lock and Redis tests run, none skipped), repeated runs |
| Operator MFA | PASS | forced TOTP enrolment for admins in production; compose E2E through nginx 45/45 (twice); browser walkthrough of the console |
| Ingest and control planes separated | PASS | nginx + app enforcement; 10 E2E checks |
| Production secrets configuration | PASS | app refuses weak/missing config; compose refuses missing secrets |
| Backup and restore verified | PASS | restore drill (three times, last on the MFA build) with grants, triggers, chain and role checks |
| No unresolved critical vulnerability | PASS | pip-audit clean; image scan 0 critical/high |
| Tamper-evident audit log | PASS | hash chain sealed by the checkpointer; verified in E2E and the restore drill |
| Evidence checkpoints off-host and write-once | PASS (local MinIO) | S3 Object Lock COMPLIANCE over TLS; outage and catch-up exercised |
| Horizontal scale (≥2 API replicas) | PASS | Redis-shared limits + stream relay; E2E with 2 replicas; Redis outage degrades safely |
| Retention | PASS | signed archive, then owner-only purge with chain anchors (PostgreSQL tests) |
| SSO / API keys / account protection | PASS | OIDC (local IdP), API keys, per-account throttle, session renewal; E2E |
| Kubernetes deployment | PASS (k3s) | Helm chart, restricted Pod Security, NetworkPolicies, 56/56, zero-downtime rollouts |

## Remaining before "production candidate"

Everything that can be built and verified without the owner's accounts and environments is done
(remediation-audit-report.md §13). What remains needs the owner:
1. Push the branch and let CI run on GitHub.
2. A staging environment with real DNS and CA certificates. Run `scripts/verify_deployment.py`
   there (56 checks; 56/56 on Compose and on Kubernetes locally) and the restore drill.
3. Real receivers: a webhook, SMTP relay or SIEM; an S3 Object Lock bucket; the IdP if SSO is
   used. All were verified only against local equivalents.

## Remaining before "production ready"

Managed PostgreSQL with replication and PITR (platform task), a managed Kubernetes cluster run,
an external penetration test, and a period of production operation.

## Earlier measurement (PostgreSQL 17, laptop, 1,000,000 events, 50 tenants, before the 10M work)

| Operation | sysadmin (1M) | hot tenant (500k) | small tenant (20k) |
|---|---|---|---|
| list 100 newest events | 0.7 ms | 1.0 ms | 2.6 ms |
| next page (keyset cursor) | 1.6 ms | 2.9 ms | 3.9 ms |
| statistics | 29 ms | 50 ms | 2.3 ms |
| top attackers (100) | 452 ms | 699 ms | 13.8 ms |
| threat summary | 461 ms | 692 ms | 13.3 ms |

Medians of 5 runs through the application's service layer.

## Measured at 10 million events (2026-11-18)

Setup: PostgreSQL 17 on a laptop; 10,000,000 events across 50 tenants, one hot tenant holding 5M;
about half of the events in the last 30 days, a heavy stress case. Timings are medians through
the application's service layer.

| Operation | System admin (10M) | Hot tenant (5M) | Small tenant (~100k) |
|---|---|---|---|
| list 100 newest | 2.0 ms | 1.5 ms | 1.5 ms |
| next page / page 51 (cursor) | 2.5 / 2.4 ms | 1.8 / 1.8 ms | 1.8 / 1.8 ms |
| statistics | 2.6 ms | 1.0 ms | 0.4 ms |
| top attackers (100) | 0.58 s | 0.56 s | 0.30 s |
| threat summary | 1.45 s | 1.41 s | 0.50 s |
| CSV export walk, 50,000 rows | 0.71 s | 0.44 s | 0.48 s |
| 14-day activity chart (daily totals) | 21 ms | 3.5 ms | – |

Before the changes below, statistics took 7.1 s, 42.9 s and 0.34 s; top attackers and the summary
**exceeded 120 s** (the production limit is 15 s, so a large customer's dashboard failed); and the
small tenant's export walk took 40.5 s. Three changes fixed it:
* **Exact per-tenant totals** in `tenant_event_counts`, maintained by statement-level triggers on
  every insert and delete (migration 20261118_01; backfill of 10M rows: 8 s).
* **`detection_events.tenant_id`**, set by a database trigger from the decoy and immutable, with
  a `(tenant_id, triggered_at, id)` index (migration 20261118_02). The migration runs **online**:
  fixed primary-key batches of 20,000 rows, the index built `CONCURRENTLY`, the foreign key
  added `NOT VALID` then validated. Measured on 10M events with a decoy-hit insert every ~10 ms
  throughout: 10 min, 42,384 inserts, **0 failed**, p99 6.6 ms, max 626 ms. Run `VACUUM ANALYZE
  detection_events` afterwards. (The first version disabled the immutability trigger per batch;
  under the same load 2 inserts failed on a 5 s timeout, p99 1.8 s. That is why it was reworked.)
* **Daily totals per tenant, UTC day and severity** in `tenant_daily_event_counts`, kept exact by
  the same kind of statement-level triggers (migration 20261118_03). The console's 14-day chart
  reads 56 rows instead of counting events: 4.0 s → 21 ms for a system administrator, 0.8 s →
  3.5 ms for the 5M-event tenant. The migration is online: 5.2 s on 10M events with an insert
  every ~10 ms, 0 of 785 inserts failed (p99 15 ms); totals matched all 10,045,231 events with no
  mismatched bucket. The restore drill checks both counter tables against the events.
* **Bounded analytics:** ranking and the summary consider at most `ANALYTICS_SAMPLE_EVENTS`
  (200,000) of the most recent events in the window, aggregated in three hash stages without
  `COUNT(DISTINCT)`. Responses say when the cap applied (`sampled`, `X-Analytics-Sampled`).
  A timeout is answered with 503 and a clear message, not 500.

## Measured ingest capacity (2026-11-17)

Setup: laptop with Docker Desktop; Compose stack with 2 API replicas, each limited to 1 CPU, and
PostgreSQL 16. 300 decoys in one tenant. The load came from inside the internal network, because
the edge caps each client IP at 20 hits/s by design. Every request is a full evidence write: event,
chain link under the tenant lock, and alert queueing.

| Concurrency | Throughput | p50 | p95 | p99 |
|---|---|---|---|---|
| 8 | 446 hits/s | 16 ms | 33 ms | 62 ms |
| 32 | 405 hits/s | 50 ms | 248 ms | 391 ms |
| 64 | 396 hits/s | 114 ms | 441 ms | 709 ms |

* **CPU-bound.** Both API replicas run at about 91% of their CPU limit while PostgreSQL sits
  near 50%, so adding replicas or CPU raises capacity.
* **Before profiling,** a hit took 12 SQL statements and throughput was 276–353 hits/s. It now
  takes 7, guarded by `tests/ingestion/test_ingest_query_budget.py`.
* **Evidence after about 100,000 requests:** the load tenant held 68,884 events and 68,884 chain
  links, and full chain verification passed.
