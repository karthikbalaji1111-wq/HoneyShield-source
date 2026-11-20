# Evidence integrity

## What is protected and how

| Layer | Mechanism | Stops | Detects |
|---|---|---|---|
| Provenance | `detection_events.source` (+ creator / integration / idempotency key), CHECK constraints | manual or hook events masquerading as observed ones | – |
| Append-only | runtime grants + immutability triggers (`database-roles.md`) | the application (and anyone holding its credentials) rewriting history | – |
| Hash chain | `evidence_chain`: per-tenant `seq`, `prev_hash`, `record_hash = SHA-256(prev_hash ‖ "\n" ‖ canonical(event))` | – | modified fields, removed/reordered links, gaps, events inserted around the app, head mismatch |
| Checkpoints | `(tenant, seq, head_hash, created_at)` signed with HMAC-SHA256 (`INTEGRATION_SIGNING_KEY`), written write-once every 15 min | – | a chain fully recomputed by a database administrator after the checkpoint |

A hash chain does not make evidence immutable; it makes changes **detectable**. Only checkpoints
stored outside the database (object storage with retention lock) detect a complete rewrite.

## Canonical form

`json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False)` of: version,
tenant_id, seq, event_id, honey_token_id, source, severity, ip_address, request_path,
http_method, user_agent, headers (string map), triggered_at (UTC, microseconds, `Z`),
created_by_user_id, integration_credential_id, idempotency_key. The DB-generated `created_at`
is deliberately excluded.

## Ordering and concurrency

Appending locks the tenant's row in `evidence_chain_heads` (`SELECT … FOR UPDATE`) inside the
event transaction, so links are strictly ordered and gap-free per tenant (verified with 40
concurrent hits on PostgreSQL). Cost: event inserts for one tenant are serialised.

## Operations

```bash
docker compose exec backend python -m app.workers.evidence verify               # all tenants
docker compose run --rm checkpointer python -m app.workers.evidence verify --checkpoints /evidence
docker compose exec backend python -m app.workers.evidence export --tenant 3 --after 0 --out /tmp/t3.jsonl
```
API: `GET /api/v1/evidence/verify` (TENANT_ADMIN own tenant; SYSTEM_ADMIN `?tenant_slug=`).
Exports contain `prev_hash`, `record_hash` and the canonical document, so an archive can be
re-verified offline without HoneyShield.

**WORM shipping (required for production use).** Set `EVIDENCE_S3_*` (checkpointer only). After
writing each checkpoint locally, the checkpointer uploads every local checkpoint file not yet
in the bucket, so a failed upload is retried on the next run and the container exits non-zero
until it succeeds. Each object is written with:
* `x-amz-object-lock-mode: COMPLIANCE` and `x-amz-object-lock-retain-until-date` (now +
  `EVIDENCE_S3_RETENTION_DAYS`, default 400);
* `Content-MD5`;
* `If-None-Match: *`, so a name is never replaced.

In COMPLIANCE mode no one, including the account root user, can delete the version or shorten
its retention. Signing is AWS SigV4 from the standard library (checked against AWS's published
test vectors); any S3 store that implements Object Lock works.

```bash
# bucket must be created with Object Lock enabled (this also enables versioning)
aws s3api create-bucket --bucket acme-honeyshield-evidence --object-lock-enabled-for-bucket \
    --create-bucket-configuration LocationConstraint=eu-west-1
docker compose exec checkpointer python -m app.workers.evidence verify --checkpoints s3
```

Least-privilege policy for the checkpointer's key (no delete, no retention bypass):
```json
{"Version": "2012-10-17", "Statement": [
 {"Effect": "Allow", "Action": ["s3:PutObject", "s3:PutObjectRetention", "s3:GetObject",
  "s3:GetObjectRetention"], "Resource": ["arn:aws:s3:::acme-honeyshield-evidence/checkpoints/*",
  "arn:aws:s3:::acme-honeyshield-evidence/archives/*"]},
 {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "arn:aws:s3:::acme-honeyshield-evidence",
  "Condition": {"StringLike": {"s3:prefix": ["checkpoints/*", "archives/*"]}}}]}
```
Verified against a real Object Lock store (MinIO) in the test suite and in CI:
* objects are locked in COMPLIANCE mode with the expected retain-until date;
* re-uploading an existing name returns 412;
* deleting a locked version is refused;
* `checkpoint` followed by `verify --checkpoints s3` round-trips both chains.

Without a bucket, `WriteOnceDirectory` (O_EXCL, mode 0444) in the local volume is the only copy,
and it is only as safe as the host.

## Audit log chain

The administrative audit log (`audit_logs`) has its own hash chain (`audit_chain`, migration
`20261117_01`), protected like the evidence chain: immutability triggers and INSERT/SELECT-only
grants for the runtime role.

* **Sealing is asynchronous.** Audit records are written exactly as before. The checkpointer
  runs `audit_chain.seal` before every checkpoint and appends every committed, unsealed record
  in id order under a single head-row lock. A synchronous lock was rejected: audit records are
  also written from a second session while the caller's transaction is open
  (`record_independently`), and that wait is invisible to PostgreSQL's deadlock detector.
* **Canonical form:** sorted-key JSON of every column (id, type, severity, message, actor,
  target, tenant, project, metadata, `created_at` in UTC microseconds) plus the chain sequence.
  `record_hash = SHA-256(prev_hash || "\n" || canonical)`.
* **Checkpoints:** each signed checkpoint file now also carries
  `{"chain": "audit", "seq", "head_hash"}`. The signature covers the chain name, so a tenant
  checkpoint cannot be replayed as the audit one.
* **Verification** (`python -m app.workers.evidence verify [--checkpoints DIR]`, or
  `GET /api/v1/audit-logs/verify` for SYSTEM_ADMIN) detects:
  * a sealed record modified or deleted;
  * links removed, reordered or altered;
  * a head mismatch;
  * records still unsealed 10 minutes after a later seal;
  * with checkpoints, a chain rewritten after the checkpoint.

  Recent records not yet sealed are reported as `unsealed_records` without failing.
* `python -m app.workers.evidence seal-audit` seals on demand.

## Retention (archive, then purge)

Evidence is kept forever by default. Set `EVENT_RETENTION_DAYS` / `AUDIT_RETENTION_DAYS` (0 or ≥ 30)
and schedule the maintenance job (daily is typical):

```bash
docker compose --profile maintenance run --rm retention --dry-run   # what would go
docker compose --profile maintenance run --rm retention
```

For each tenant chain, and then the audit chain, in batches of 5,000 links per transaction:
1. **Verify first.** A chain that does not verify is never purged (that would destroy the
   evidence of tampering). The job reports `REFUSED` and exits 1.
2. **Choose a prefix.** Links appended before the cutoff are selected; append time rises
   with the sequence, so this is a contiguous prefix.
3. **Archive.** A signed JSON-lines archive is written write-once, to S3 `archives/` in the
   Object Lock bucket or to the `evidence_archive` volume. Its first line names the range,
   the previous hash and the last hash; each record line carries `prev_hash`, `record_hash`
   and the canonical record; the last line is an HMAC over the rest.
   `retention.verify_archive()` re-checks an archive offline.
4. **Purge.** `SET LOCAL honeyshield.retention_purge = 'on'`, then delete the links, events
   (with their outbox rows) or audit records.
5. **Anchor.** `evidence_chain_anchors` / `audit_chain_anchor` move to the last purged link.
   Verification then starts from that hash, and checkpoints in the purged range are skipped
   (they were checked when archived).
6. **Audit.** A `RETENTION_PURGE` record is written with the counts and the archive name.

**Trigger exemption:** `prevent_forensic_modification()` still refuses every UPDATE and
TRUNCATE. It allows DELETE only when the transaction set the flag AND the deleting role owns
the table. The runtime role has no DELETE grant, so it cannot purge even with the flag (tested on
PostgreSQL). The owner cannot delete without the flag or update with it. The job runs with the
owner credentials and is the only service that has them besides `migrate`.

The checkpointer's IAM policy needs `archives/*` added next to `checkpoints/*` when the
retention job writes to the same bucket.

## Limits

* Events recorded before migration `20261113_04` are unchained (reported as `unchained_events`).
* Audit records are chained minutes after they are written, not at write time. Until sealed,
  only the immutability trigger and grants protect them. A database superuser could forge a record
  before it is sealed; once sealed, it cannot be altered undetected.
* Checkpoint signatures use the same master key as integrations; whoever holds it can forge
  checkpoints, so keep exported checkpoints in storage the HoneyShield host cannot rewrite.
