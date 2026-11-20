# HoneyShield

**Install on your server with one command:**

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/karthikbalaji1111-wq/HoneyShield-source/main/deploy/install/install.sh)" -- \
  --control-host app.example.com --ingest-host cdn.example.com --email you@example.com
```

Replace the two host names with two DNS names that point at your server, and the email with the
first administrator's address. To try it on your own computer first, leave the options out:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/karthikbalaji1111-wq/HoneyShield-source/main/deploy/install/install.sh)"
```

Free for everyone ([licence](#licence)). The full source code is in this repository.


## What HoneyShield does

HoneyShield catches intruders with bait. You plant decoys in places no legitimate person or system
has a reason to touch: a hidden URL in a config comment, a fake API key in an old repository, a
tracking pixel in a document nobody should open, an invisible field in a login form. When something
touches one of them, that is not noise to be tuned out. It is a strong sign that someone is looking
where they should not be, and HoneyShield records exactly what happened, keeps the record in a form
that can stand up as evidence, and tells your team.

It runs entirely on your own server. Your detection data never leaves it.


## What the install command does

1. Checks that Docker and the Compose plugin are installed and running.
2. Downloads the deployment files from this repository into `~/honeyshield` (not the whole source).
3. Generates every password and secret, unique to your installation.
4. Downloads the ready-made HoneyShield images (for x86 and ARM servers) and starts everything.
5. Waits until it is healthy and asks for the first administrator's password.
6. Creates `backup-key.txt`. **Copy it off the server straight away**: backups are encrypted to
   it and cannot be restored without it.

Then open `https://<control host>/console/` and sign in. On your own computer that is
https://app.localhost:8443/console/ (accept the certificate warning; the certificate is self-signed).

**What you need:** a Linux server with Docker and the Compose plugin (or Docker Desktop on a Mac or
Windows to try it), about 2 GB of memory, ports 80 and 443 open, and two DNS names pointing at the
server: one for the console, one for the decoys. Pick a decoy name that looks like ordinary
infrastructure, such as `cdn.` or `assets.`, never `honeypot.` or `trap.`.

The installer starts with a temporary certificate. For a real one from Let's Encrypt, follow step 7 of
the [server guide](docs/deploy-oracle-free.md#7-real-https-certificates-lets-encrypt); steps 4 to 11
of that guide apply to any Ubuntu server, not only Oracle's.

**Upgrade** later, keeping all data and settings:

```bash
~/honeyshield/install.sh --upgrade --version X.Y.Z
```

On Kubernetes, use the Helm chart in `deploy/helm/honeyshield`: see [docs/kubernetes.md](docs/kubernetes.md).


## How it works

You create a project for each application you want to protect and generate decoys for it. There
are five kinds:

- A hidden URL: a path that only shows up where an intruder would look, such as a commented-out
  line in a config file or a `Disallow` line in robots.txt.
- A hidden link: the same idea placed inside a page, where people browsing normally never see it.
- A tracking pixel: a tiny image for decoy documents and decoy emails. Opening one fires it.
- A fake API key: a credential that looks real and is planted in decoy config files or repositories.
- A form honeypot: a field people never see, so only a bot fills it in.

URLs, links and pixels point at HoneyShield's public ingest address, so HoneyShield sees the request
itself. Fake keys and form fields are noticed inside your own application: a small hook (a reference
client is in `integrations/python`) reports the hit to HoneyShield with a signed, timestamped message.

Every hit becomes a detection event with its time, source address, request, user agent and
headers, the decoy it touched, and where the information came from (observed by HoneyShield,
reported by your integration, or entered by hand). Events cannot be edited or deleted by the
application, and each one is linked into a per-tenant hash chain, so a later change to any event is
detectable. The chain's head is checkpointed to write-once (S3 Object Lock) storage outside the
database.

Hits are not lost when part of the system is down. If the database or every API replica is
unavailable, the edge still answers the visitor normally and keeps the hit; once the backend is back
it is recorded with the time the edge saw it, exactly once. This was tested by stopping the API, then
the database, while sending hits: every one was recorded, none twice.

When an event arrives, HoneyShield alerts the destinations you have set up: a signed JSON webhook,
Slack or Microsoft Teams, email, or a SIEM over syslog with TLS. Alerts go through a queue with
retries, so a receiver that is down for a while still gets every alert once it comes back.


## What you get

Operator console. A web console for everyday work: an overview with a fourteen-day detections chart,
the event list with filters and a detail panel, projects and decoys (including when each decoy last
fired), integration credentials, alert destinations and their delivery history, the audit log,
evidence verification, users and tenants. It works on a phone, has light and dark themes, loads no
third-party code, and passes an automated accessibility audit with no violations.

People and access. Multiple tenants, each fully separated from the others. Three roles: system
admin, tenant admin and read-only tenant user. Admins must use two-factor authentication, either an
authenticator app or a passkey, which a fake sign-in page cannot steal. The console can be limited
to your own addresses while decoys stay reachable from everywhere. Single sign-on through any OpenID
Connect provider, and personal API keys with read or write scope for automation. New users get a
one-time set-up link and choose their own password; nobody else ever knows it.

Evidence you can defend. Hash chains over detection events and over the audit log, checkpoints in
write-once storage, a database role for the application that is not allowed to change or delete
evidence, and a restore drill that checks every chain again after a backup is restored.

Knowing it works. A watchdog sends a test hit through the public entry point every five minutes and
checks it was recorded, along with the alert worker, failed alerts, backups, certificates and disk
space. Problems go to a channel of your choice (ntfy, Slack, Discord, email), and a heartbeat lets
an outside service tell you if the whole server stops. Nightly backups are encrypted with a key you
keep off the server and copied to any S3-compatible bucket.

Decoys that blend in. Decoy URLs use path prefixes and a host name of your choosing, so nothing in a
decoy points to HoneyShield.

Operations. Runs with Docker Compose on a single host or on Kubernetes with the included Helm
chart. Upgrades roll out without dropped requests, because database migrations are written so the
running version keeps working while the next one migrates. Prometheus metrics and tested alert
rules are included, along with a script that checks a whole deployment end to end.


## Build and run it from the source

You need Docker (Docker Desktop on a Mac or Windows) and `openssl`. It takes about ten minutes.

```bash
git clone https://github.com/karthikbalaji1111-wq/HoneyShield-source.git
cd HoneyShield-source
scripts/quickstart_env.sh
docker compose --env-file .env.local up -d --build --wait
docker compose --env-file .env.local exec backend python -m app.bootstrap --email you@example.com
```

The script writes `.env.local` with freshly generated secrets, a self-signed certificate, and two
host names, `app.localhost` and `ingest.localhost`, which already point at your own machine. It
never overwrites a file that exists. The last command asks you to choose the first administrator's
password.

Then open https://app.localhost:8443/console/, accept the certificate warning (the certificate is
self-signed) and sign in. You will be asked to set up two-factor authentication. A good first tour:

1. Tenants: add one.
2. Projects and decoys: add a project and generate a hidden URL.
3. Open that URL in another tab. Generated URLs start with `https://ingest.localhost/`; on your
   machine add the port, so `https://ingest.localhost:8443/...`.
4. Events: the hit shows up within a few seconds. Open it to see everything that was recorded.

To check the whole local stack end to end, the verification script exercises every decoy type,
the integration hook, host separation, TLS, masking, evidence and rate limits:

```bash
HS_VERIFY_ADMIN_PASSWORD='the admin password' python3 scripts/verify_deployment.py \
  --control-host app.localhost --ingest-host ingest.localhost \
  --connect 127.0.0.1:8443 --http-connect 127.0.0.1:8080 --cacert proxy/certs/local-dev.crt \
  --admin-email you@example.com --metrics-token "$(grep '^METRICS_TOKEN=' .env.local | cut -d= -f2-)" \
  --totp-secret-file ~/.honeyshield-admin.totp --expect-replicas 2
```

Stop everything with `docker compose --env-file .env.local down`. Adding `-v` also deletes the local
data.


## Running it for real

- On one server: the install command above, then [docs/deployment-guide.md](docs/deployment-guide.md).
- Step by step on a free cloud server: [docs/deploy-oracle-free.md](docs/deploy-oracle-free.md).
- On Kubernetes with Helm: [docs/kubernetes.md](docs/kubernetes.md).
- Before going live, work through [docs/release-checklist.md](docs/release-checklist.md).

Every release publishes the backend, edge and database images for both x86 and ARM servers. Every
image is scanned for known vulnerabilities before it is published and carries a list of its
components (an SBOM) and a record of how it was built.

A production deployment needs a few things only you can provide: two DNS names (one for operators,
one for the decoys), certificates for them, a PostgreSQL database, an S3 bucket with Object Lock for
evidence checkpoints, and wherever you want alerts to go. [docs/production-readiness.md](docs/production-readiness.md)
lists what has been verified and what is still yours to do.


## How it is built

The edge is nginx. It serves two host names and keeps them apart: the operator host carries the
console and the API, while the ingest host accepts decoy hits and integration reports and nothing
else. Behind it:

- the API, a FastAPI application (Python 3.12, SQLAlchemy 2, Pydantic 2), running as two or more
  replicas;
- an alert worker that delivers queued alerts;
- an evidence checkpointer that seals the audit log and ships chain checkpoints to S3;
- a watchdog and a backup service;
- a retention job, when retention is enabled;
- PostgreSQL 16, managed with Alembic migrations;
- Valkey, a Redis-compatible store, for rate limits and live updates shared between API replicas.
  It holds nothing that matters if it is lost.

The code follows a plain layered layout. Routes in `app/api` handle HTTP and permissions, services
in `app/services` hold the rules, repositories in `app/repositories` do the database work, and
models in `app/models` describe the tables. [docs/architecture-as-is.md](docs/architecture-as-is.md)
goes into detail, and [docs/security-model.md](docs/security-model.md) explains the trust
boundaries.


## Repository layout

- `backend/app`: the application. `api` (routes, sign-in, ingestion), `services`, `repositories`,
  `models`, `schemas`, `core` (settings, security, logging), `db`, `middleware` and `workers`.
- `backend/alembic`: database migrations.
- `backend/tests`: the test suite.
- `frontend/console`: the operator console. Plain HTML, CSS and JavaScript, served by the edge.
- `proxy`: the nginx configuration for the edge.
- `docker`: Dockerfiles for the backend, edge and database images.
- `deploy/install`: the one-command installer. `deploy/helm/honeyshield`: the Helm chart.
  `deploy/monitoring`: Prometheus alert rules and their tests.
- `integrations/python`: the reference client for the integration hook.
- `scripts`: quick start, deployment verification, backup and restore.
- `docs`: everything else, listed below.


## Developing

```bash
cd backend
python3.12 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt pytest pytest-asyncio httpx
JWT_SECRET_KEY="$(openssl rand -hex 32)" APP_ENV=test pytest -q
```

That runs the suite on SQLite. The tests that need real PostgreSQL, S3 Object Lock or Valkey run
when you point them at disposable instances with `HS_TEST_PG_ADMIN_URL`, `HS_TEST_S3_ENDPOINT`
(plus `HS_TEST_S3_ACCESS_KEY` and `HS_TEST_S3_SECRET_KEY`) and `HS_TEST_REDIS_URL`; see
[docs/testing-strategy.md](docs/testing-strategy.md).

Database changes are Alembic migrations, written expand-first so the version already running keeps
working during an upgrade. The rules are in
[docs/database_migration_runbook.md](docs/database_migration_runbook.md).

Every push runs the full suite with real PostgreSQL, S3 and Valkey (a skipped integration test
fails the build), audits the Python dependencies for known vulnerabilities, checks the migrations
upgrade, downgrade and upgrade again with no drift from the models, builds every image and scans it,
validates the Compose files, the Helm chart, the nginx configuration and the Prometheus rules, and
runs contract tests on the console.


## Documentation

- [Deployment guide](docs/deployment-guide.md) and [Kubernetes](docs/kubernetes.md)
- [Environment configuration](docs/environment-configuration.md)
- [Planting decoys](docs/honeytoken-deployment-guide.md) and [customer integrations](docs/customer-integrations.md)
- [Alerting and the outbox](docs/alerting-and-outbox.md)
- [Evidence integrity](docs/evidence-integrity.md) and [backup and restore](docs/backup-and-restore.md)
- [Watchdog](docs/watchdog.md): self-test, notices and the dead-man's switch
- [Decoys that do not look like HoneyShield](docs/decoy-paths.md)
- [Passkeys and the operator allowlist](docs/passkeys.md) and [single sign-on](docs/sso.md)
- [Monitoring and service levels](docs/monitoring-and-slos.md) and the [operations runbook](docs/operations-runbook.md)
- [Incident response](docs/incident-response.md)
- [Security model](docs/security-model.md), [threat model](docs/threat-model.md) and the
  [security findings register](docs/security-findings-register.md)
- [API reference](docs/api-reference.md)
- [Console design notes](docs/console-design.md)
- [Production readiness](docs/production-readiness.md) and the [audit report](docs/remediation-audit-report.md)
- [Is it ready for companies?](docs/industry-readiness.md), a plain re-audit with what is still missing

If this README and a document in `docs` ever disagree, the document is right.


## What is next

- Enrichment for attacker addresses, such as location, network owner and reputation.
- Help from AI with reading attacker behaviour across many events.
- Scheduled reports.
- Ready-made templates for managed cloud platforms.


## Security

Please report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md). Do not open a
public issue for a security problem.


## Licence

HoneyShield is free for everyone to install and use, for any purpose, including inside a company.
You may read, build and change the source for your own use, but not sell it, redistribute it or
offer it as a hosted service. The full terms are in [LICENSE](LICENSE); it is not an open-source
licence. Copyright 2026 Karthik Balaji. The open-source components HoneyShield includes, and their
licences, are listed in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
