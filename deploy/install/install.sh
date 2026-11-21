#!/usr/bin/env bash
# HoneyShield installer: sets up and starts HoneyShield with Docker, from the published images.
# Only the deployment files are downloaded (Compose file, database init script, config template),
# never the source code.
#
#   Try it on this machine:
#     bash -c "$(curl -fsSL https://raw.githubusercontent.com/karthikbalaji1111-wq/HoneyShield-source/main/deploy/install/install.sh)"
#
#   On a server with two DNS names pointing at it:
#     bash -c "$(curl -fsSL .../install.sh)" -- --control-host app.example.com --ingest-host ingest.example.com --email you@example.com
#
#   Upgrade an existing installation to another version (keeps data and settings):
#     ~/honeyshield/install.sh --upgrade --version 1.3.1
#
# Options:
#   --dir DIR             where to install (default: ~/honeyshield)
#   --version X.Y.Z       image version (default: the version this script was released with)
#   --control-host NAME   operator console host (server mode); default: app.localhost (local mode)
#   --ingest-host NAME    decoy host (server mode); default: ingest.localhost
#   --email ADDRESS       first administrator (asked for if missing)
#   --http-port N         port for plain HTTP (default: 8080 locally, 80 on a server)
#   --https-port N        port for HTTPS (default: 8443 locally, 443 on a server)
#   --registry PREFIX     image registry prefix (default: ghcr.io/karthikbalaji1111-wq/)
#   --source DIR          copy the deployment files from a local checkout instead of downloading
#   --build               build the images on this machine from the published source of --version
#                         instead of downloading ready-made ones (with --source: from that checkout)
#   --upgrade             switch an existing installation to --version and restart it
#   --no-start            prepare everything but do not start
#   --notify-url URL      where the watchdog sends problem notices (ntfy, Slack, Discord, any webhook)
#   --heartbeat-url URL   dead-man's-switch ping after every healthy check (Healthchecks.io and similar)
#   --admin-cidrs LIST    only these addresses may open the console (e.g. 203.0.113.7/32,10.0.0.0/8)
#   --decoy-paths L,P,C   your own decoy URL prefixes for links, pixels and forms (e.g. static/v2,assets/img,telemetry/v1)
#
# A backup key is generated on the first install (backup-key.txt): backups are encrypted to it.
# Copy that file somewhere safe OFF this server; without it no backup can be restored.
#
# Downloads only the deployment files of the chosen version from the public repository HoneyShield-source.
# Private packages: run `docker login ghcr.io` first; set GITHUB_TOKEN if HS_INSTALL_BASE_URL is private.
# Works with the bash 3.2 that macOS ships. Never prints a secret.
set -euo pipefail

HS_VERSION_DEFAULT="1.3.1"
DIR="${HOME}/honeyshield"
VERSION="$HS_VERSION_DEFAULT"
CONTROL_HOST=""
INGEST_HOST=""
EMAIL=""
REGISTRY="ghcr.io/karthikbalaji1111-wq/"
SOURCE=""
BUILD=0
SOURCE_ARCHIVE_URL="${HS_SOURCE_ARCHIVE_URL:-https://github.com/karthikbalaji1111-wq/HoneyShield-source/archive/refs/tags}"
HTTP_PORT=""
HTTPS_PORT=""
UPGRADE=0
START=1
NOTIFY_URL=""
HEARTBEAT_URL=""
ADMIN_CIDRS=""
DECOY_PATHS=""
BASE_URL="${HS_INSTALL_BASE_URL:-https://raw.githubusercontent.com/karthikbalaji1111-wq/HoneyShield-source}"
FILES="docker-compose.yml docker/init-db.sh .env.example scripts/quickstart_env.sh scripts/restore_drill.sh deploy/install/install.sh"

say()  { printf '%s\n' "$*"; }
# A usable terminal (not just a /dev/tty node: under CI or cloud-init opening it fails).
have_tty() { (exec < /dev/tty) 2>/dev/null; }
step() { printf '\n==> %s\n' "$*"; }
die()  { printf 'Error: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dir) DIR="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --control-host) CONTROL_HOST="$2"; shift 2 ;;
    --ingest-host) INGEST_HOST="$2"; shift 2 ;;
    --email) EMAIL="$2"; shift 2 ;;
    --registry) REGISTRY="$2"; shift 2 ;;
    --http-port) HTTP_PORT="$2"; shift 2 ;;
    --https-port) HTTPS_PORT="$2"; shift 2 ;;
    --source) SOURCE="$2"; shift 2 ;;
    --build) BUILD=1; shift ;;
    --upgrade) UPGRADE=1; shift ;;
    --no-start) START=0; shift ;;
    --notify-url) NOTIFY_URL="$2"; shift 2 ;;
    --heartbeat-url) HEARTBEAT_URL="$2"; shift 2 ;;
    --admin-cidrs) ADMIN_CIDRS="$2"; shift 2 ;;
    --decoy-paths) DECOY_PATHS="$2"; shift 2 ;;
    -h|--help) sed -n '2,30p' "$0" 2>/dev/null || true; exit 0 ;;
    --) shift ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done

case "$VERSION" in
  [0-9]*.[0-9]*.[0-9]*) ;;
  *) die "--version must look like 1.3.0" ;;
esac
if [ -n "$CONTROL_HOST" ] || [ -n "$INGEST_HOST" ]; then
  if [ -z "$CONTROL_HOST" ] || [ -z "$INGEST_HOST" ]; then die "server mode needs both --control-host and --ingest-host"; fi
  [ "$CONTROL_HOST" != "$INGEST_HOST" ] || die "the console and decoy hosts must be different names"
  MODE=server
else
  MODE=local
fi
for u in "$NOTIFY_URL" "$HEARTBEAT_URL"; do
  case "$u" in ""|https://*) ;; *) die "--notify-url and --heartbeat-url must start with https://" ;; esac
done
if [ -n "$DECOY_PATHS" ]; then
  printf '%s' "$DECOY_PATHS" | grep -Eq '^[a-z0-9/-]+,[a-z0-9/-]+,[a-z0-9/-]+$' \
    || die "--decoy-paths needs three comma-separated paths of a-z, 0-9, '-' and '/'"
fi
[ -z "$ADMIN_CIDRS" ] || printf '%s' "$ADMIN_CIDRS" | grep -Eq '^[0-9A-Fa-f:./, ]+$' \
  || die "--admin-cidrs takes IP addresses or CIDR ranges separated by commas"

step "Checking prerequisites"
for cmd in docker openssl curl; do
  command -v "$cmd" >/dev/null 2>&1 || die "$cmd is required (install Docker Desktop or Docker Engine, openssl and curl)"
done
docker compose version >/dev/null 2>&1 || die "the Docker Compose plugin (docker compose) is required"
docker info >/dev/null 2>&1 || die "Docker is installed but not running: start Docker and run this again"
say "Docker $(docker version --format '{{.Server.Version}}' 2>/dev/null) with Compose $(docker compose version --short 2>/dev/null)"

step "Fetching HoneyShield ${VERSION} deployment files into ${DIR}"
mkdir -p "$DIR"
cd "$DIR"
for f in $FILES; do
  mkdir -p "$(dirname "$f")"
  if [ -n "$SOURCE" ]; then
    cp "$SOURCE/$f" "$f"
  else
    auth=()
    [ -n "${GITHUB_TOKEN:-}" ] && auth=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
    curl -fsSL --retry 3 ${auth[@]+"${auth[@]}"} "${BASE_URL}/v${VERSION}/${f}" -o "${f}.download" \
      || die "could not download ${f} for version ${VERSION} (is the version right, and is the download URL public?)"
    mv "${f}.download" "$f"
  fi
done
# Downloaded files arrive without the executable bit. The database runs init-db.sh on first start;
# without +x it fails and the database roles are never created.
chmod +x scripts/quickstart_env.sh scripts/restore_drill.sh deploy/install/install.sh docker/init-db.sh
mkdir -p proxy/acme  # Let's Encrypt webroot (docs/deployment-guide.md, section 2)
ln -sf deploy/install/install.sh install.sh

set_env() {  # set_env KEY VALUE: replace the line, or append it
  local key="$1" value="$2" tmp
  tmp="$(mktemp .env.XXXXXX)"
  if grep -q "^${key}=" .env; then
    awk -v k="$key" -v v="$value" 'BEGIN{FS=OFS="="} $1==k {print k "=" v; next} {print}' .env > "$tmp"
  else
    cat .env > "$tmp"; printf '%s=%s\n' "$key" "$value" >> "$tmp"
  fi
  chmod 600 "$tmp"; mv "$tmp" .env
}

if [ -f .env ]; then
  [ "$UPGRADE" = 1 ] || say "Keeping the existing configuration in ${DIR}/.env"
else
  [ "$UPGRADE" = 0 ] || die "no installation found in ${DIR} to upgrade"
  step "Writing a new configuration with freshly generated secrets"
  ./scripts/quickstart_env.sh .env >/dev/null
  if [ "$MODE" = server ]; then
    set_env HS_CONTROL_HOST "$CONTROL_HOST"
    set_env HS_INGEST_HOST "$INGEST_HOST"
    set_env NGINX_BIND_ADDRESS 0.0.0.0
    set_env NGINX_HTTP_PORT 80
    set_env NGINX_TLS_PORT 443
    if [ ! -e proxy/certs/server-selfsigned.crt ]; then
      openssl req -x509 -nodes -newkey rsa:2048 -days 30 -keyout proxy/certs/server-selfsigned.key \
        -out proxy/certs/server-selfsigned.crt -subj "/CN=${CONTROL_HOST}" \
        -addext "subjectAltName=DNS:${CONTROL_HOST},DNS:${INGEST_HOST}" 2>/dev/null
      chmod 600 proxy/certs/server-selfsigned.key; chmod 644 proxy/certs/server-selfsigned.crt
    fi
    for k in HS_CONTROL_CERT HS_INGEST_CERT; do set_env "$k" server-selfsigned.crt; done
    for k in HS_CONTROL_KEY HS_INGEST_KEY; do set_env "$k" server-selfsigned.key; done
  fi
  # The certificate starts self-signed: the watchdog's self-test must not fail on that, but its
  # certificate check still warns until a real one is installed (then set this to true).
  set_env WATCHDOG_PROBE_VERIFY_TLS false
fi
# Containers take addresses from the upper half of the internal subnet so the edge's fixed address
# (.10) is never handed out first (docker-compose.yml). A custom /24 subnet gets the matching range.
subnet="$(sed -n 's/^HS_INTERNAL_SUBNET=//p' .env | tail -n 1)"  # the last one wins, as in Compose
if [ -n "$subnet" ] && ! grep -q '^HS_INTERNAL_IP_RANGE=.' .env; then
  case "$subnet" in
    *.*.*.0/24) set_env HS_INTERNAL_IP_RANGE "${subnet%.0/24}.128/25" ;;
    *) die "HS_INTERNAL_SUBNET=${subnet} is not a /24: set HS_INTERNAL_IP_RANGE in .env to its upper half (see .env.example)" ;;
  esac
fi
# Installations from before the watchdog existed: same default as a new one.
grep -q '^WATCHDOG_PROBE_VERIFY_TLS=' .env || set_env WATCHDOG_PROBE_VERIFY_TLS false
[ -z "$NOTIFY_URL" ] || set_env WATCHDOG_NOTIFY_WEBHOOK_URL "$NOTIFY_URL"
[ -z "$HEARTBEAT_URL" ] || set_env WATCHDOG_HEARTBEAT_URL "$HEARTBEAT_URL"
[ -z "$ADMIN_CIDRS" ] || set_env HS_CONTROL_ALLOW_CIDRS "$(printf '%s' "$ADMIN_CIDRS" | tr -d ' ')"
if [ -n "$DECOY_PATHS" ]; then
  set_env HS_DECOY_LINK_PATH "$(printf '%s' "$DECOY_PATHS" | cut -d, -f1)"
  set_env HS_DECOY_PIXEL_PATH "$(printf '%s' "$DECOY_PATHS" | cut -d, -f2)"
  set_env HS_DECOY_COLLECT_PATH "$(printf '%s' "$DECOY_PATHS" | cut -d, -f3)"
fi
[ -z "$HTTP_PORT" ] || set_env NGINX_HTTP_PORT "$HTTP_PORT"
[ -z "$HTTPS_PORT" ] || set_env NGINX_TLS_PORT "$HTTPS_PORT"
# Images built here carry no registry prefix, so they can never be mistaken for downloaded ones.
[ "$BUILD" = 1 ] && REGISTRY=""
set_env HS_IMAGE_REGISTRY "$REGISTRY"
set_env HS_IMAGE_TAG "$VERSION"
chmod 600 .env

[ "$START" = 1 ] || { say "Prepared. Start with: cd ${DIR} && docker compose --env-file .env up -d --no-build --wait"; exit 0; }

if [ "$BUILD" = 1 ]; then
  if [ -n "$SOURCE" ]; then
    src="$SOURCE"
  else
    step "Downloading the HoneyShield ${VERSION} source"
    rm -rf src && mkdir src
    curl -fsSL --retry 3 "${SOURCE_ARCHIVE_URL}/v${VERSION}.tar.gz" | tar -xz -C src --strip-components 1 \
      || die "could not download the source of version ${VERSION}"
    src="${DIR}/src"
  fi
  step "Building the images from source (several minutes the first time)"
  for image in db backend edge; do
    say "  honeyshield-${image}"
    docker build --quiet -f "${src}/docker/Dockerfile.${image}" -t "honeyshield-${image}:${VERSION}" "$src" >/dev/null \
      || die "building honeyshield-${image} failed: run the same docker build without --quiet to see why"
  done
else
  step "Downloading images (${REGISTRY}honeyshield-*:${VERSION})"
  if ! docker compose --env-file .env pull --quiet 2>pull.log; then
    if grep -qiE "unauthorized|denied|authentication" pull.log; then
      die "the image registry refused access. If the packages are private, run 'docker login ghcr.io' first, or install with --build."
    fi
    cat pull.log >&2; die "could not download the images"
  fi
  rm -f pull.log
fi

if ! grep -q '^BACKUP_AGE_RECIPIENTS=age1' .env; then
  step "Creating the backup encryption key"
  umask 077
  # A throwaway container with no network: the key never leaves this machine.
  docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true \
    "${REGISTRY}honeyshield-backend:${VERSION}" python -m app.workers.backup keygen \
    > backup-key.txt.new 2>/dev/null || { rm -f backup-key.txt.new; die "could not generate the backup key"; }
  recipient="$(sed -n 's/^# public key: //p' backup-key.txt.new)"
  case "$recipient" in age1*) ;; *) rm -f backup-key.txt.new; die "could not generate the backup key" ;; esac
  if [ -e backup-key.txt ]; then mv backup-key.txt "backup-key.txt.old.$(date +%s)"; fi
  mv backup-key.txt.new backup-key.txt
  chmod 600 backup-key.txt
  umask 022
  set_env BACKUP_AGE_RECIPIENTS "$recipient"
  KEY_CREATED=1
  say "Backups will be encrypted to the key in ${DIR}/backup-key.txt. Copy it OFF this server (see the end)."
fi

step "Starting HoneyShield"
docker compose --env-file .env up -d --no-build --wait --wait-timeout 300 \
  || die "some services did not become healthy: see 'docker compose --env-file .env ps' and 'docker compose --env-file .env logs'"

control_host="$(sed -n 's/^HS_CONTROL_HOST=//p' .env)"
tls_port="$(sed -n 's/^NGINX_TLS_PORT=//p' .env)"
url="https://${control_host}$([ "${tls_port:-443}" = 443 ] || printf ':%s' "$tls_port")/console/"

users="$(docker compose --env-file .env exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc "select count(*) from users"' 2>/dev/null || echo 0)"
if [ "${users:-0}" = 0 ]; then
  step "Creating the first administrator"
  if [ -z "$EMAIL" ] && have_tty; then
    printf 'Administrator email: ' > /dev/tty; read -r EMAIL < /dev/tty
  fi
  if [ -n "$EMAIL" ] && have_tty; then
    docker compose --env-file .env exec backend python -m app.bootstrap --email "$EMAIL" < /dev/tty
  else
    say "Create it when you are at a terminal:"
    say "  cd ${DIR} && docker compose --env-file .env exec backend python -m app.bootstrap --email you@example.com"
  fi
fi

step "HoneyShield ${VERSION} is running"
say "Console:   ${url}"
if [ "$MODE" = local ]; then
  say "           (self-signed certificate: accept the browser warning)"
  say "Decoys:    generated URLs start with https://ingest.localhost/ ; on this machine add :${tls_port}"
else
  say "Certificate: a temporary self-signed one is in use. Replace it with a real one (Let's Encrypt):"
  say "           see docs/deployment-guide.md in the HoneyShield documentation, section 2."
fi
if [ "${KEY_CREATED:-0}" = 1 ]; then
  say ""
  say "IMPORTANT  Backups are encrypted to the key in ${DIR}/backup-key.txt."
  say "           Copy that file to a password manager or another machine NOW. If this server is lost"
  say "           and the key is only here, the backups cannot be decrypted. Then set BACKUP_S3_* in"
  say "           .env so copies leave this server (docs/backup-and-restore.md)."
fi
grep -q '^WATCHDOG_NOTIFY_WEBHOOK_URL=https' .env || grep -q '^WATCHDOG_NOTIFY_EMAIL=.' .env \
  || say "Watchdog:  nothing will tell you when HoneyShield breaks until you set --notify-url (docs/watchdog.md)."
say "Manage:    cd ${DIR} && docker compose --env-file .env ps | logs | down"
say "Upgrade:   ${DIR}/install.sh --upgrade --version X.Y.Z"
