#!/usr/bin/env bash
# Reproduces the outage experiment: decoy hits sent while every API replica is stopped, and while
# the database is stopped, must all be recorded exactly once after recovery, and the evidence chain
# must still verify.
#
#   scripts/reproduce_outage.sh [INSTALL_DIR] [HITS_PER_PHASE]
#
# INSTALL_DIR is a Compose installation (default ~/honeyshield, as made by the installer). Run it on
# a TEST installation: it creates a tenant "outage-test-<time>" with one decoy, and detection events
# are evidence, so they stay. Phases: baseline, backend stopped, database stopped (HITS_PER_PHASE
# each, default 50). Exit status 0 only when every check passes.
#
# By design HoneyShield stores at most INGESTION_RATE_LIMIT_PER_MINUTE_TOKEN hits (default 60) per
# minute from one address on one decoy; further hits in that minute become a single
# DETECTION_HITS_SUPPRESSED audit entry, so a flood cannot fill the database. All hits here come from
# one address, so each phase starts on a fresh minute and stays below that cap.
set -euo pipefail
DIR="${1:-$HOME/honeyshield}"
N="${2:-50}"
cd "$DIR"
[ -f .env ] || { echo "error: no .env in $DIR" >&2; exit 1; }
C=(docker compose --env-file .env)
host="$(sed -n 's/^HS_INGEST_HOST=//p' .env)"
port="$(sed -n 's/^NGINX_TLS_PORT=//p' .env)"; port="${port:-443}"
link_path="$(sed -n 's/^HS_DECOY_LINK_PATH=//p' .env)"; link_path="${link_path:-t}"
cap="$(sed -n 's/^INGESTION_RATE_LIMIT_PER_MINUTE_TOKEN=//p' .env)"; cap="${cap:-60}"
[ "$N" -le "$cap" ] || { echo "error: HITS_PER_PHASE must be at most the per-minute cap ($cap)" >&2; exit 1; }

say() { printf '%s\n' "$*"; }
wait_healthy() {  # wait_healthy SERVICE
  for _ in $(seq 1 90); do
    [ "$("${C[@]}" ps --format '{{.Health}}' "$1" 2>/dev/null | sort -u)" = healthy ] && return 0
    sleep 2
  done
  echo "error: $1 did not become healthy" >&2; return 1
}
next_minute() {  # wait until a fresh minute has started, with room to send N hits inside it
  local s
  s="$(date +%S)"; s="${s#0}"
  sleep $((61 - s))
}
hits() {  # hits PHASE: send N decoy requests, paced at 5 per second; count what the visitor saw
  local phase="$1" i code ok=0
  next_minute
  for i in $(seq 1 "$N"); do
    code="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 20 --resolve "${host}:${port}:127.0.0.1" \
      -A "honeyshield-outage-test/${phase}" "https://${host}:${port}/${link_path}/${TOKEN}?n=${phase}-${i}")"
    [ "$code" = 204 ] && ok=$((ok + 1))
    sleep 0.2
  done
  say "  ${phase}: ${ok}/${N} requests answered 204 (the visitor cannot tell an outage happened)"
  [ "$ok" = "$N" ]
}
count() {
  # shellcheck disable=SC2016  # $POSTGRES_* expand inside the database container
  "${C[@]}" exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc "$0"' \
    "select count(*) || ' ' || count(distinct idempotency_key) from detection_events e join honey_tokens t on t.id = e.honey_token_id where t.token_value = '${TOKEN}'"
}

say "==> Creating a test tenant, project and URL decoy"
TOKEN="$("${C[@]}" exec -T backend python - <<'EOF'
import secrets, time
from app.db.session import SessionLocal
from app.models.tenant import Tenant
from app.models.project import Project
from app.models.honey_token import HoneyToken, HoneyTokenType
s = SessionLocal()
stamp = time.strftime("%Y%m%d%H%M%S")
tenant = Tenant(name=f"Outage test {stamp}", slug=f"outage-test-{stamp}", is_active=True)
s.add(tenant); s.flush()
project = Project(tenant_id=tenant.id, name="Outage test", domain=f"outage-{stamp}.example.test", is_active=True)
s.add(project); s.flush()
token = HoneyToken(project_id=project.id, token_type=HoneyTokenType.URL, token_value=secrets.token_urlsafe(24),
                   label="outage experiment", is_active=True)
s.add(token); s.commit()
print(token.token_value)
EOF
)"
TOKEN="$(printf '%s' "$TOKEN" | tail -n 1 | tr -d '\r')"
say "  decoy: https://${host}/${link_path}/<${#TOKEN}-character token>"

say "==> Phase 1: everything running"
hits baseline

say "==> Phase 2: every API replica stopped"
"${C[@]}" stop backend >/dev/null 2>&1
hits backend-down
"${C[@]}" start backend >/dev/null 2>&1
wait_healthy backend

say "==> Phase 3: database stopped"
"${C[@]}" stop postgres >/dev/null 2>&1
hits database-down
"${C[@]}" start postgres >/dev/null 2>&1
wait_healthy postgres
wait_healthy backend

expected=$((3 * N))
say "==> Waiting for the edge to replay what it captured (up to 3 minutes)"
for _ in $(seq 1 90); do
  read -r total distinct <<<"$(count)"
  [ "${total:-0}" -ge "$expected" ] && break
  sleep 2
done
sleep 10  # a late duplicate would show up now
read -r total distinct <<<"$(count)"

say "==> Evidence chain"
chain_ok=1
"${C[@]}" run --rm -T --no-deps migrate python -m app.workers.evidence verify || chain_ok=0

say ""
say "Sent ${expected} decoy hits (${N} per phase). Recorded ${total} events, ${distinct} distinct."
fail=0
[ "$total" = "$expected" ] || { say "FAIL: expected exactly ${expected} events"; fail=1; }
[ "$distinct" = "$total" ] || { say "FAIL: some hits were stored more than once"; fail=1; }
[ "$chain_ok" = 1 ] || { say "FAIL: the evidence chain did not verify"; fail=1; }
[ "$fail" = 0 ] && say "PASS: every hit recorded exactly once, through both outages, and the chain verifies."
exit "$fail"
