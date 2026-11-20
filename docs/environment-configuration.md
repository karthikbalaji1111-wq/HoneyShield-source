# Environment configuration

Authoritative source: `backend/app/core/config.py` (application) and `docker-compose.yml`
(deployment). `.env.example` lists every deployment variable with comments.

## Profiles

| Profile | `APP_ENV` | Enforced by the application |
|---|---|---|
| development | `development` | nothing extra; API docs on; DB least-privilege check off |
| test | `test` | same as development (CI and pytest) |
| staging / production | `staging`, `production` | everything in the next table |

Production/staging refuse to start unless:

| Setting | Rule |
|---|---|
| `JWT_SECRET_KEY` | ≥32 bytes, no placeholder patterns |
| `POSTGRES_PASSWORD` | not a known default (when DATABASE_URL is not given) |
| `PUBLIC_INGEST_BASE_URL` | set, https, origin only |
| `INTEGRATION_SIGNING_KEY` | set, ≥32 bytes, different from JWT_SECRET_KEY |
| `CONTROL_PLANE_HOSTNAMES` | set; must not contain the ingest host |
| `ALERT_ALLOW_HTTP_WEBHOOKS` | false |
| `SMTP_SECURITY` | `starttls` or `tls` when `SMTP_HOST` is set |
| DB role | not superuser/owner/DDL-capable (checked against the live DB at start-up and readiness) |

API docs (`/docs`, `/redoc`, `/openapi.json`) are off unless `EXPOSE_API_DOCS=true`.

## Application settings (env names are case-insensitive)

| Variable | Default | Meaning |
|---|---|---|
| `POSTGRES_HOST/PORT/DB/USER/PASSWORD` | localhost/5432/honeyshield_dev/… | runtime connection (compose sets the runtime role) |
| `DATABASE_URL` | – | full SQLAlchemy URL instead of the POSTGRES_* parts |
| `POSTGRES_MIGRATION_USER/PASSWORD`, `MIGRATION_DATABASE_URL` | – | owner identity for Alembic and grants |
| `POSTGRES_APP_USER` | – | role the grant step targets |
| `ENFORCE_DB_LEAST_PRIVILEGE` | on in prod | refuse to run as a privileged role |
| `PUBLIC_INGEST_BASE_URL` | – | origin embedded in artifacts (compose: `https://$HS_INGEST_HOST`) |
| `CONTROL_PLANE_HOSTNAMES` | – | comma list; enables host separation with the ingest host |
| `TRUSTED_PROXIES` | 127.0.0.1, ::1 | proxies allowed to set X-Forwarded-For (compose: nginx fixed IP) |
| `INTEGRATION_SIGNING_KEY` | – | master key for hook/webhook secrets and checkpoint signatures |
| `MFA_SECRET_KEY` | – (required in prod) | derivation key for TOTP secrets and recovery-code hashes; must differ from JWT/integration keys |
| `MFA_REQUIRED_ROLES` | prod: `SYSTEM_ADMIN,TENANT_ADMIN`; else none | comma list of roles that must use MFA; `none` = no requirement (risk acceptance) |
| `MFA_ISSUER` | HoneyShield | issuer label shown in authenticator apps |
| `INTEGRATION_TIMESTAMP_TOLERANCE_SECONDS` | 300 | hook signature clock window |
| `INTEGRATION_REPORTS_PER_MINUTE` | 1200 | per integration |
| `ALERT_DELIVERY_TIMEOUT_SECONDS` / `ALERT_MAX_ATTEMPTS` | 5 / 8 | webhook delivery |
| `ALERT_WORKER_BATCH_SIZE` / `ALERT_WORKER_POLL_SECONDS` | 20 / 2 | worker loop |
| `METRICS_TOKEN` | – | enables `/metrics` with this bearer token |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_SECURITY` | – / 587 / starttls | relay for EMAIL alerts (`tls` = implicit TLS, usually 465) |
| `SMTP_USERNAME` / `SMTP_PASSWORD` | – | relay login; set both or neither |
| `SMTP_FROM` | – (required with SMTP_HOST) | sender address of alert mail |
| `EVIDENCE_S3_ENDPOINT` / `_BUCKET` / `_REGION` | – / – / us-east-1 | S3 Object Lock bucket for WORM checkpoint copies (checkpointer only; https in production) |
| `EVIDENCE_S3_ACCESS_KEY_ID` / `_SECRET_ACCESS_KEY` | – | key with put/get/list only (policy in evidence-integrity.md) |
| `EVIDENCE_S3_PREFIX` / `_RETENTION_DAYS` / `_LOCK_MODE` | checkpoints/ / 400 / COMPLIANCE | object prefix, retention per object, `COMPLIANCE` or `GOVERNANCE` |
| `EVENT_RETENTION_DAYS` / `AUDIT_RETENTION_DAYS` | 0 / 0 | keep forever (0) or ≥ 30 days; applied by the `retention` maintenance job |
| `RETENTION_ARCHIVE_DIR` | /evidence-archive | write-once archive directory when no S3 bucket is set |
| `REDIS_URL` (compose: from `REDIS_PASSWORD`) | – | shared rate limits + live stream across backend replicas |
| `HS_BACKEND_REPLICAS` (compose) | 2 | API replicas behind nginx |
| `ALERT_ALLOWED_PRIVATE_CIDRS` | – | self-hosted only: comma list of private networks a SIEM/webhook may use; loopback, link-local and metadata stay refused |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | 30 | JWT lifetime (streams end at expiry) |
| `SESSION_MAX_HOURS` | 12 | absolute session length; `/auth/refresh` renews only until then |
| `LOGIN_ATTEMPTS_PER_MINUTE` | 30 | per IP |
| `LOGIN_ACCOUNT_FAILURES_ALLOWED` / `LOGIN_ACCOUNT_FAILURE_WINDOW_SECONDS` | 10 / 900 | failed passwords per address (any IP) before sign-in is refused; 0 disables |
| `INGESTION_RATE_LIMIT_PER_MINUTE_IP` / `_TOKEN` | 120 / 60 | response rate / stored-evidence cap |
| `RATE_LIMIT_*`, `MAX_REQUEST_BODY_BYTES`, `HEADER_*`, `CORS_*`, `SECURITY_HEADERS_*` | see config.py | |
| `DB_POOL_*`, `DB_STATEMENT_TIMEOUT_MS`, `DB_ANALYTICS_TIMEOUT_MS` | 10/10/…/5000/15000 | |
| `ANALYTICS_SAMPLE_EVENTS` | 200000 | analytics consider at most this many of the most recent events in their window (responses say when sampled) |

## Secrets handling

* Generate each secret independently (`openssl rand -hex 32`); keep the env file outside the
  repository with mode 600; `.env` is git- and docker-ignored.
* Rotating `MFA_SECRET_KEY` invalidates every authenticator enrolment and every recovery code.
  Before rotating, have an administrator who keeps a valid session reset MFA for everyone else;
  afterwards reset that administrator via a second admin or the owner-role SQL in the runbook.
* Rotating `JWT_SECRET_KEY` signs everyone out. Rotating `INTEGRATION_SIGNING_KEY` invalidates
  all integration credentials, webhook signing secrets and checkpoint signatures (re-issue them).
* Database passwords: `ALTER ROLE … PASSWORD` as the bootstrap superuser, update the env file,
  `docker compose up -d`.
