#!/usr/bin/env bash
# Writes a complete env file for a LOCAL evaluation stack, so `docker compose` starts without
# hand-made secrets:
#   * fresh random secrets (JWT, integration signing, MFA encryption, database and Redis passwords,
#     metrics token), mode 600;
#   * hosts under .localhost (app.localhost, ingest.localhost), which resolve to 127.0.0.1 with no
#     DNS or /etc/hosts change;
#   * a self-signed certificate for both names (proxy/certs/local-dev.*), created only if absent.
# Every other value comes from .env.example. Not for production: see docs/deployment-guide.md.
# Works with the bash 3.2 that macOS ships.
#
# Usage: scripts/quickstart_env.sh [OUTPUT]      (default: .env.local; never overwritten)
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${1:-.env.local}"
case "$out" in /*) ;; *) out="$PWD/$out" ;; esac
if [ -e "$out" ]; then
  echo "$out already exists; refusing to overwrite it (delete it yourself to start over)." >&2
  exit 1
fi
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }

certs="$root/proxy/certs"
mkdir -p "$certs"
if [ ! -e "$certs/local-dev.crt" ]; then
  openssl req -x509 -nodes -newkey rsa:2048 -days 90 \
    -keyout "$certs/local-dev.key" -out "$certs/local-dev.crt" \
    -subj "/CN=app.localhost" -addext "subjectAltName=DNS:app.localhost,DNS:ingest.localhost" 2>/dev/null
  chmod 600 "$certs/local-dev.key"
  chmod 644 "$certs/local-dev.crt"
  echo "Created a self-signed certificate for app.localhost and ingest.localhost (proxy/certs/local-dev.*)."
fi

# Values this script sets; everything else is copied from .env.example unchanged.
KEYS="APP_ENV HS_CONTROL_HOST HS_INGEST_HOST JWT_SECRET_KEY INTEGRATION_SIGNING_KEY MFA_SECRET_KEY
REDIS_PASSWORD METRICS_TOKEN POSTGRES_BOOTSTRAP_PASSWORD HS_OWNER_DB_PASSWORD HS_APP_DB_PASSWORD
HS_CONTROL_CERT HS_CONTROL_KEY HS_INGEST_CERT HS_INGEST_KEY"
value_for() {
  case "$1" in
    APP_ENV) echo production ;;
    HS_CONTROL_HOST) echo app.localhost ;;
    HS_INGEST_HOST) echo ingest.localhost ;;
    HS_CONTROL_CERT|HS_INGEST_CERT) echo local-dev.crt ;;
    HS_CONTROL_KEY|HS_INGEST_KEY) echo local-dev.key ;;
    *) openssl rand -hex 32 ;;                      # every secret is generated independently
  esac
}
is_managed() { for k in $KEYS; do [ "$k" = "$1" ] && return 0; done; return 1; }

umask 077
tmp="$(mktemp "${out}.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
written=" "
while IFS= read -r line || [ -n "$line" ]; do
  key="${line%%=*}"
  case "$line" in
    \#*|"") printf '%s\n' "$line" ;;
    *=*) if is_managed "$key"; then printf '%s=%s\n' "$key" "$(value_for "$key")"; written="$written$key "
         else printf '%s\n' "$line"; fi ;;
    *) printf '%s\n' "$line" ;;
  esac
done < "$root/.env.example" > "$tmp"
for key in $KEYS; do
  case "$written" in *" $key "*) ;; *) printf '%s=%s\n' "$key" "$(value_for "$key")" >> "$tmp" ;; esac
done
mv "$tmp" "$out"
trap - EXIT

echo "Wrote $out (mode 600). No secret was printed."
echo "Next: docker compose --env-file $out up -d --build"
