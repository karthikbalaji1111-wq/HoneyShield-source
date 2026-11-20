# Backup and restore (HONEY-028, HONEY-069)

## Automatic encrypted backups

The `backup` service (Compose) or `backup` CronJob (Helm) makes a backup every
`BACKUP_INTERVAL_HOURS` (24):

1. `pg_dump` in custom format, as the runtime role (it can read every table and change nothing).
2. `pg_restore --list` on the result: a dump that is not a readable archive is never kept.
3. Encryption to your age public key(s) in `BACKUP_AGE_RECIPIENTS`, in the standard
   [age](https://age-encryption.org) format. The plain dump is deleted at once. The server holds
   only the public key, so it can write backups but not read them.
4. Upload to any S3-compatible bucket (`BACKUP_S3_*`) and a size check of what was stored.
5. Retention: `BACKUP_KEEP_LOCAL` (3) copies on the server; off-site copies older than
   `BACKUP_KEEP_DAYS` (30) are deleted, but the newest seven are always kept.
6. Status for the watchdog, which warns you when the last good backup is more than 26 hours old.

### The key

The installer creates the key on the first install (or the first upgrade to 1.3.0) and saves it as
`backup-key.txt` next to `.env`. **Copy that file somewhere safe off the server now**: a password
manager, or another machine. Without it no backup can be decrypted, and if it exists only on the
server, losing the server loses the backups' only key.

To make a key yourself:

```bash
docker run --rm --network none ghcr.io/karthikbalaji1111-wq/honeyshield-backend:1.3.0 \
  python -m app.workers.backup keygen > backup-key.txt
```

`age-keygen` from the age project produces the same kind of key. Put the `# public key:` value in
`BACKUP_AGE_RECIPIENTS` (several, comma-separated, for example a second key held by a colleague).

### Off-site storage

| Provider | `BACKUP_S3_ENDPOINT` | Notes |
|---|---|---|
| Oracle Cloud Object Storage | `https://<namespace>.compat.objectstorage.<region>.oraclecloud.com` | 20 GB in the Always Free tier; create a Customer Secret Key for the access key pair; `BACKUP_S3_REGION` is the region, e.g. `eu-frankfurt-1` |
| Backblaze B2 | `https://s3.<region>.backblazeb2.com` | 10 GB free; an application key limited to the bucket |
| Cloudflare R2 | `https://<account id>.r2.cloudflarestorage.com` | `BACKUP_S3_REGION=auto` |
| AWS S3 | `https://s3.<region>.amazonaws.com` | an IAM user with Put/Get/List/Delete on the prefix only |

Give the credentials access to this one bucket and nothing else. If the bucket supports versioning or
object lock, turn it on: then even someone who takes over the server cannot destroy older backups
(deletion of expired copies is then refused, which the service reports and tolerates).

### Proof that backups restore

Mount the key read-only and set `BACKUP_IDENTITY_FILE` to have the service download the newest
off-site copy every `BACKUP_VERIFY_EVERY_DAYS` (7), decrypt it and check it is a readable dump. This
puts the key on the server, which trades some protection of the off-site copies for continuous proof.
Without it, run the drill below yourself every month.

### Restoring

```bash
# list what exists
docker compose --env-file .env exec backup python -m app.workers.backup list
# download and decrypt the newest off-site copy into ./restore.dump
docker compose --env-file .env run --rm -T --no-deps --user "$(id -u):$(id -g)" -v "$PWD:/out" backup \
  python -m app.workers.backup fetch latest --identity /out/backup-key.txt --out /out/restore.dump
# or by hand, from any machine with age installed
age -d -i backup-key.txt honeyshield-20261120T020000Z.dump.age > restore.dump
# restore it into a new database and verify everything
COMPOSE="docker compose --env-file .env" scripts/restore_drill.sh --dump restore.dump
```

Verified on 2026-11-20: a backup made by the service in Compose, decrypted with the reference `age`
binary and restored with `restore_drill.sh --dump` gave identical row counts and a verifying evidence
chain (`tests/postgres/test_backup_pg.py` repeats the off-site path in CI).

## Policy

| Item | Requirement |
|---|---|
| Logical backups | daily by the backup service, plus before every upgrade (`scripts/restore_drill.sh` does both backup and proof) |
| Integrity | `pg_restore --list` before keeping; SHA-256 and size checked after upload and before a verified restore |
| Encryption & off-site | age (X25519, ChaCha20-Poly1305) to keys held off the server; S3-compatible bucket; local copies mode 600 in a 700 directory |
| Retention | 35 daily, 12 monthly (adjust to your evidence-retention obligations) |
| PITR | recommended for production: WAL archiving (pgBackRest/WAL-G) or a managed PostgreSQL with PITR; not configured by this repository |
| Evidence checkpoints | the `evidence_checkpoints` volume is shipped separately to retention-locked storage (evidence-integrity.md) |
| Drill | monthly and after every schema change: a backup that has not been restored is not a backup |

## Restore procedure (proven)

`scripts/restore_drill.sh` automates and verifies it:

1. Dump the live database (read-only for the source) and checksum it.
2. Create a **new** database owned by `honeyshield_owner` (never restore over the live one).
3. `pg_restore --no-owner --role=honeyshield_owner --no-privileges --exit-on-error`, so every
   object is owned by the owner, not the superuser.
4. Re-apply the runtime grant policy (`python -m app.db.privileges grant`); `--no-privileges`
   drops grants, and without this step the API has no access.
5. Verify: Alembic revision is head, row counts per table, immutability triggers present,
   evidence chain verifies (as the runtime role), runtime role passes the least-privilege check.

```bash
COMPOSE="docker compose --env-file /etc/honeyshield/prod.env" BACKUP_DIR=/var/backups/honeyshield \
  scripts/restore_drill.sh            # keeps the drill DB for inspection; --cleanup drops it
```

Drill result on 2026-11-15 (verification stack): source and restored counts identical
(audit_logs 20, detection_events 6, evidence_chain 6, honey_tokens 6, outbox_events 1,
tenants 1, users 3), head `20261113_06`, 6 triggers, chain OK, runtime role OK.

## Disaster recovery cut-over

After a successful drill against the chosen dump: stop `backend`, `worker`, `checkpointer`;
point `POSTGRES_DB` at the restored database (or rename databases as the superuser); `docker
compose up -d`; run `scripts/verify_deployment.py`; compare the evidence head with the last
exported checkpoint (`verify --checkpoints`). Events after the dump are lost unless PITR is used.
`scripts/restore_postgres.sh` (legacy, in-place `--clean`) remains for compatibility; prefer the drill.
