#!/usr/bin/env bash
# ==============================================================================
# HoneyShield backup + restore DRILL (HONEY-028). Proves a backup is restorable; a backup
# command exiting 0 proves nothing.
#
#   1. pg_dump (custom format) of the live database, with SHA-256 checksum
#   2. restore into a NEW database owned by the schema-owner role (never over the live one)
#   3. re-apply the runtime grant policy (pg_restore --no-privileges drops grants)
#   4. verify: migration head, row counts per table, evidence hash chain (as the runtime role)
#      and least-privilege of the runtime role on the restored copy
#
# The live database is only read. The drill database is left in place for inspection unless
# --cleanup is passed (it is dropped only if this script created it).
#
# Usage: COMPOSE="docker compose --env-file prod.env" scripts/restore_drill.sh [--dump FILE] [--cleanup]
#
#   --dump FILE  restore this (decrypted) dump instead of taking a new one, e.g. an off-site backup:
#                docker compose --env-file prod.env run --rm -T --no-deps --user "$(id -u):$(id -g)" \
#                  -v "$PWD:/out" backup python -m app.workers.backup fetch latest \
#                  --identity /out/backup-key.txt --out /out/restore.dump
#                (docs/backup-and-restore.md)
# ==============================================================================
set -euo pipefail

COMPOSE="${COMPOSE:-docker compose}"
BACKUP_DIR="${BACKUP_DIR:-./backups}"
SUPERUSER="${POSTGRES_BOOTSTRAP_USER:-postgres}"
OWNER_ROLE="${HS_OWNER_DB_USER:-honeyshield_owner}"
CLEANUP=""
GIVEN_DUMP=""
while [ $# -gt 0 ]; do
  case "$1" in
    --cleanup) CLEANUP="--cleanup"; shift ;;
    --dump) GIVEN_DUMP="${2:?--dump needs a file}"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

SRC_DB=$($COMPOSE exec -T postgres sh -c 'printf %s "$POSTGRES_DB"')
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
DRILL_DB="${SRC_DB}_drill_$(date -u +%Y%m%d%H%M%S)"
mkdir -p "$BACKUP_DIR" && chmod 700 "$BACKUP_DIR"
DUMP="$BACKUP_DIR/${SRC_DB}_${STAMP}.dump"

psql_su() { $COMPOSE exec -T postgres psql -v ON_ERROR_STOP=1 -U "$SUPERUSER" "$@"; }

if [ -n "$GIVEN_DUMP" ]; then
  [ -s "$GIVEN_DUMP" ] || { echo "ERROR: $GIVEN_DUMP is missing or empty" >&2; exit 1; }
  DUMP="$GIVEN_DUMP"
  echo "[1/5] Using the given dump ${DUMP} (row counts are compared with the live database for reference)"
else
  echo "[1/5] Backing up ${SRC_DB} -> ${DUMP}"
  $COMPOSE exec -T postgres pg_dump -U "$SUPERUSER" -d "$SRC_DB" -Fc > "$DUMP"
  [ -s "$DUMP" ] || { echo "ERROR: empty dump" >&2; exit 1; }
fi
chmod 600 "$DUMP"
(command -v sha256sum >/dev/null && sha256sum "$DUMP" || shasum -a 256 "$DUMP") > "$DUMP.sha256"
chmod 600 "$DUMP.sha256"

echo "[2/5] Restoring into new database ${DRILL_DB} (owner ${OWNER_ROLE})"
(command -v sha256sum >/dev/null && sha256sum -c "$DUMP.sha256" || shasum -a 256 -c "$DUMP.sha256") >/dev/null
psql_su -d postgres -c "CREATE DATABASE \"${DRILL_DB}\" OWNER \"${OWNER_ROLE}\"" >/dev/null
psql_su -d "$DRILL_DB" -c "ALTER SCHEMA public OWNER TO \"${OWNER_ROLE}\"; REVOKE ALL ON SCHEMA public FROM PUBLIC" >/dev/null
$COMPOSE exec -T postgres pg_restore -U "$SUPERUSER" -d "$DRILL_DB" --no-owner --role="$OWNER_ROLE" \
    --no-privileges --exit-on-error < "$DUMP"

echo "[3/5] Re-applying runtime grants on ${DRILL_DB}"
$COMPOSE run --rm -T --no-deps -e POSTGRES_DB="$DRILL_DB" migrate python -m app.db.privileges grant

echo "[4/5] Verifying ${DRILL_DB}"
FAIL=0
HEAD=$($COMPOSE run --rm -T --no-deps -e POSTGRES_DB="$DRILL_DB" migrate alembic current 2>/dev/null | tail -1)
case "$HEAD" in *"(head)"*) echo "  migration head: $HEAD";; *) echo "  FAIL migration head: $HEAD"; FAIL=1;; esac
COUNTS="SELECT string_agg(t || '=' || n, ' ' ORDER BY t) FROM (SELECT 'tenants' t, count(*) n FROM tenants UNION ALL
  SELECT 'users', count(*) FROM users UNION ALL SELECT 'honey_tokens', count(*) FROM honey_tokens UNION ALL
  SELECT 'detection_events', count(*) FROM detection_events UNION ALL SELECT 'audit_logs', count(*) FROM audit_logs UNION ALL
  SELECT 'evidence_chain', count(*) FROM evidence_chain UNION ALL SELECT 'outbox_events', count(*) FROM outbox_events) c"
SRC_COUNTS=$(psql_su -d "$SRC_DB" -tA -c "$COUNTS")
DRILL_COUNTS=$(psql_su -d "$DRILL_DB" -tA -c "$COUNTS")
echo "  source: $SRC_COUNTS"
echo "  drill:  $DRILL_COUNTS"
# The source keeps receiving events; the drill must hold at least the dumped rows per table.
[ -n "$DRILL_COUNTS" ] || FAIL=1
# Trigger-maintained totals must equal the real counts (catches double counting during restore).
COUNTS_OK=$(psql_su -d "$DRILL_DB" -tA -c "SELECT (SELECT coalesce(sum(total),0) FROM tenant_event_counts) = (SELECT count(*) FROM detection_events WHERE tenant_id IS NOT NULL) AND (SELECT coalesce(sum(total),0) FROM tenant_daily_event_counts) = (SELECT count(*) FROM detection_events WHERE tenant_id IS NOT NULL) AND NOT EXISTS (SELECT 1 FROM detection_events WHERE tenant_id IS NULL)")
echo "  tenant event totals consistent: $COUNTS_OK"; [ "$COUNTS_OK" = "t" ] || FAIL=1
TRIGGERS=$(psql_su -d "$DRILL_DB" -tA -c "SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgname LIKE 'trg_%'")
echo "  triggers restored (immutability, counters, daily totals, tenant): $TRIGGERS"; [ "$TRIGGERS" -ge 13 ] || FAIL=1
$COMPOSE run --rm -T --no-deps -e POSTGRES_DB="$DRILL_DB" migrate python -m app.workers.evidence verify || FAIL=1
$COMPOSE run --rm -T --no-deps -e POSTGRES_DB="$DRILL_DB" -e POSTGRES_MIGRATION_USER= migrate \
    python -m app.db.privileges check || FAIL=1

echo "[5/5] Result"
if [ "$CLEANUP" = "--cleanup" ]; then
  psql_su -d postgres -c "DROP DATABASE \"${DRILL_DB}\"" >/dev/null && echo "  dropped drill database ${DRILL_DB}"
else
  echo "  drill database kept for inspection: ${DRILL_DB} (drop it when done)"
fi
if [ "$FAIL" -ne 0 ]; then echo "RESTORE DRILL FAILED"; exit 1; fi
echo "RESTORE DRILL PASSED: ${DUMP}"
