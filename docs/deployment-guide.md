# Deployment guide (single host, Docker Compose)

Verified end to end on 2026-11-15 with Docker 29.9 / Compose v2 (40/40 checks in
`scripts/verify_deployment.py`, restore drill passed). Production use additionally needs real DNS,
real certificates and the release checklist.

Just evaluating on one machine? `scripts/quickstart_env.sh` writes a complete local env file
(fresh secrets, `*.localhost` hosts, a self-signed certificate); see *Try it on your own machine* in
the README. It is not a production configuration.

## 1. Requirements

* Linux host with Docker Engine ≥ 24 and the Compose plugin; 2 vCPU / 4 GB RAM minimum.
* Two DNS names pointing at the host, e.g. `app.example.com` (operators) and
  `ingest.example.com` (decoys). The ingest name must not be a customer domain.
* TLS certificate(s) covering both names (one SAN certificate is fine) in `proxy/certs/`.
* Inbound 80/443 open; outbound 443 open for the worker (webhooks) only.

## 2. Configure

```bash
install -m 600 /dev/null /etc/honeyshield/prod.env
cp .env.example /etc/honeyshield/prod.env     # then edit; see environment-configuration.md
openssl rand -hex 32                         # once per secret: JWT, INTEGRATION_SIGNING_KEY, MFA_SECRET_KEY,
                                             # bootstrap / owner / app DB passwords, METRICS_TOKEN
```
Set `NGINX_BIND_ADDRESS=0.0.0.0`, `NGINX_HTTP_PORT=80`, `NGINX_TLS_PORT=443`.

Certificates (Let's Encrypt, webroot challenge served by nginx on port 80):
```bash
certbot certonly --webroot -w "$PWD/proxy/acme" -d app.example.com -d ingest.example.com
# copy fullchain.pem/privkey.pem into proxy/certs and set HS_*_CERT / HS_*_KEY. nginx serves
# proxy/acme (HS_ACME_WEBROOT) on port 80, so renewals need no downtime; docs/deploy-oracle-free.md
# has a deploy hook that copies renewed certificates and reloads nginx.
```
A self-signed certificate (`scripts/generate_test_certs.sh`) is for local testing only.

## 3. Build, start, migrate

To run released images instead of building on the host, set `HS_IMAGE_REGISTRY=ghcr.io/karthikbalaji1111-wq/`
and `HS_IMAGE_TAG=<version>` in the env file (log in first with `docker login ghcr.io` if the packages
are private), then use `docker compose $E pull` and `docker compose $E up -d --no-build` below.

```bash
E="--env-file /etc/honeyshield/prod.env"
docker compose $E config -q                  # fails if any required value is missing
docker compose $E build
docker compose $E up -d                      # postgres -> migrate (owner) -> backend/worker/checkpointer -> nginx
docker compose $E ps                         # migrate: Exited (0); others: running/healthy
```
On first start the postgres container runs `docker/init-db.sh` once: it creates
`honeyshield_owner` and `honeyshield_app` (no defaults) and hands the database to the owner.
`migrate` runs `alembic upgrade head` and `python -m app.db.privileges grant` as the owner. The
backend refuses to start if its own DB role could alter or delete evidence.

## 4. First administrator

```bash
docker compose $E exec backend python -m app.bootstrap --email you@example.com
```
Interactive password prompt; works only while the users table is empty. Admin roles must use MFA
in production: the first sign-in (console or API) is limited to enrolling a second factor. A passkey
is recommended (it cannot be phished, docs/passkeys.md); an authenticator app (TOTP) with ten
recovery codes also works. Create a second SYSTEM_ADMIN as a break-glass account.

## 4a. Watchdog, backups and hardening (do these before relying on it)

1. Notices: set `WATCHDOG_NOTIFY_WEBHOOK_URL` (ntfy, Slack, Discord) or `WATCHDOG_NOTIFY_EMAIL`,
   then `docker compose $E exec watchdog python -m app.workers.watchdog --test-notice`.
2. Dead-man's switch: a Healthchecks.io check (period 5 min, grace 10 min) and its URL in
   `WATCHDOG_HEARTBEAT_URL` (docs/watchdog.md).
3. Backups: copy `backup-key.txt` off the server; set `BACKUP_S3_*` to a bucket elsewhere
   (docs/backup-and-restore.md); run the restore drill once with a downloaded backup.
4. Decoy paths and a company-like ingest host name (docs/decoy-paths.md).
5. Optional: `HS_CONTROL_ALLOW_CIDRS` with your office or VPN range (docs/passkeys.md).

`docker compose $E up -d` applies changed settings.

## 5. Verify

```bash
HS_VERIFY_ADMIN_PASSWORD=… python3 scripts/verify_deployment.py \
  --control-host app.example.com --ingest-host ingest.example.com \
  --connect <public-ip>:443 --http-connect <public-ip>:80 --admin-email you@example.com \
  --metrics-token "$METRICS_TOKEN" --totp-secret-file /root/hs-verify-admin.totp
```
With MFA enforced the script logs in with a TOTP code generated from `--totp-secret-file`. If the
admin has not enrolled yet, the script enrols it and writes the secret to that file (mode 600);
better: enrol the admin in the console first and put the same secret in the file.
It creates a uniquely named tenant (`verify-xxxxxx`) and exercises every decoy type, the hook,
host separation, TLS, masking, evidence verification and edge limits. Deactivate that tenant
afterwards: console → Tenants → Deactivate (type the slug), or `DELETE /api/v1/tenants/{slug}`; evidence is kept.

Onboarding a customer: console → **Tenants** → Add tenant, then **Users** → Add user with the tenant admin role.
The console issues a one-time set-up link instead of a password; the person chooses their own
password through it and enrols two-factor authentication at first sign-in.

## 6. Upgrades and rollback

From releases before 2026-11-17: the database now runs from `docker/Dockerfile.db` (PostgreSQL 16.16,
started as the postgres user, no added capabilities) and shared state from Valkey instead of Redis.
`docker compose $E build && docker compose $E up -d` switches both in place: the data volume is
reused as it is (same major version and C library), and the shared state is ephemeral by design.

```bash
git pull && docker compose $E build
scripts/restore_drill.sh                     # take + prove a backup first
docker compose $E up -d                      # migrate runs again, then the new API starts
```
Rollback of code: redeploy the previous image tag (`HS_IMAGE_TAG`). Rollback of a migration
is **never automatic**; downgrades drop provenance/integration columns and must be decided by an
operator after a backup (see database_migration_runbook.md).

## 7. Scaling limits

Outages do not lose decoy hits: the edge keeps them while the backend or database is down and the
`ingest-replay` service records them afterwards (see the operations runbook). What a single Compose
host cannot survive is the loss of the host itself; for that, run the Helm chart on several nodes
with a managed PostgreSQL.

The API runs `HS_BACKEND_REPLICAS` replicas (default 2) behind nginx. Rate limits and the live
stream are shared through Redis; if Redis is down they fall back to per replica, and detection
is unaffected. Each replica runs one uvicorn worker; scale with more replicas, not `--workers`.
Alert workers scale too (`docker compose up -d --scale worker=3`). For Kubernetes, see
`docs/kubernetes.md` (Helm chart, zero-downtime rolling upgrades).

## 8. Local development

`docker compose -f docker-compose.yml -f docker-compose.dev.yml --env-file dev.env up` with
`APP_ENV=development`, test hostnames in `/etc/hosts`, and a self-signed certificate.
