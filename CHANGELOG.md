# Changelog

Versions follow [Semantic Versioning](https://semver.org). The Helm chart's `appVersion` and the
release tag (`vX.Y.Z`) always match; the release workflow refuses a tag that does not.

## Unreleased

### Changed
* Licence: free for everyone, for any purpose; selling, redistributing or hosting HoneyShield for
  others is not allowed. Not an open-source licence.
* The full source is public in `HoneyShield-source`, one commit per release under GitHub's no-reply
  address (no history, no personal addresses). The installer downloads its files from there, so
  installing needs no GitHub login. The release workflow publishes each version there
  (`scripts/publish_source_repo.sh`; `deploy/public/EXCLUDE` lists what stays private).
* Security reports go through GitHub's private vulnerability reporting.
* The installer also fetches `scripts/restore_drill.sh`, which the backup guide uses.

## 1.3.0 — 2026-11-20

### Upgrade notes
* Run the installer with `--upgrade --version 1.3.0`. It creates a backup key (`backup-key.txt` next
  to `.env`): **copy it off the server**. Without it no backup can be decrypted.
* Two new Compose services, `watchdog` and `backup`, start with the upgrade. Set a notice channel
  (`WATCHDOG_NOTIFY_WEBHOOK_URL` or `WATCHDOG_NOTIFY_EMAIL`), a heartbeat (`WATCHDOG_HEARTBEAT_URL`)
  and an off-site bucket (`BACKUP_S3_*`): docs/watchdog.md, docs/backup-and-restore.md.
* The internal network gains an address range (`HS_INTERNAL_IP_RANGE`, upper half of the subnet), so
  Compose recreates it during the upgrade: containers restart once. The installer sets the range for
  a custom /24 subnet; any other custom subnet needs it set by hand.
* Migrations `20261119_02` and `20261119_03` add three small tables and one column with a constant
  default: no rewrite, nothing blocked.
* The backend image now contains the PostgreSQL 16 client (for backups).
* Helm: a `watchdog` Deployment (on by default), an optional `backup` CronJob, and the values
  `decoyPaths`, `controlAllowCidrs`, `watchdog`, `backup`. Upgrade with `--reset-then-reuse-values`
  (or `--reuse-values` plus the new defaults) so the new values exist.

### Added
* Watchdog: a self-test decoy hit through the public entry point every 5 minutes, plus checks of the
  alert worker, failed and stuck alerts, the outage buffer, evidence checkpoints, backups, certificate
  expiry and trust, and disk space. Notices with reminders and recovery messages, a heartbeat for an
  outside dead-man's switch, a System health panel in the console and `/api/v1/system/status`
  (HONEY-068).
* Encrypted, off-site, verified backups: nightly `pg_dump`, encrypted with age to a key kept off the
  server, uploaded to any S3-compatible bucket, with retention, an optional weekly restore check and
  `restore_drill.sh --dump` for a downloaded backup (HONEY-069).
* Passkeys (WebAuthn) as a phishing-resistant second factor, usable instead of the authenticator app
  for roles that require MFA; an address allowlist for the console and API (HONEY-070).
* Decoy URL path prefixes of your choosing, with the old prefixes kept for existing decoys until you
  switch them off (HONEY-071).
* Installer options `--notify-url`, `--heartbeat-url`, `--admin-cidrs`, `--decoy-paths`.
* Let's Encrypt webroot mounted into nginx (`proxy/acme`), so certificates renew without downtime.
* Guide: running HoneyShield for free on Oracle Cloud's Always Free ARM server (docs/deploy-oracle-free.md).

### Fixed
* The edge's fixed internal address could be taken by another container that started first, leaving
  the stack without its edge (HONEY-072).

## 1.2.0 — 2026-11-19

### Upgrade notes
* New service `ingest-replay` (Compose) and a sidecar of the same name in each edge pod (Helm), plus
  a spool volume for the edge. Both start with the upgrade; nothing to configure (they use the
  existing `INTEGRATION_SIGNING_KEY`).
* Migration `20261119_01` adds a partial unique index, built concurrently: decoy hits keep flowing.
* The installer is now the recommended way to deploy a single server (`deploy/install/install.sh`).

### Added
* No decoy hit is lost while the database or every API replica is down: the edge answers and spools
  the hit, and it is recorded with its original time once the backend is back, exactly once.
* One-command installer from the published images, with upgrades in place.
* Alert `HoneyShieldHitsRecoveredAfterOutage`.
* Accessibility: 0 automated (axe-core) violations across the console.

### Fixed
* Decoy hits were lost during backend or database outages (HONEY-067).

## 1.1.0 — 2026-11-17

### Upgrade notes
* **Shared state moves from Redis 7.4 to Valkey 9.0** (BSD-licensed, Redis-compatible). Nothing to
  migrate: the store is ephemeral by design. Compose and Helm switch on upgrade.
* **Compose database image** is now `honeyshield-db` (PostgreSQL 16.16 with security updates, runs
  as `postgres` with no added capabilities). `docker compose build && docker compose up -d` reuses
  the existing data volume as it is (same major version and C library).
* **New tenant slugs** must be lower-case letters, digits and hyphens (2–63). Existing slugs keep
  working.
* **Admin-set passwords** (create or update a user through the API) need 12 characters, like
  self-chosen ones.
* Helm: images default to `ghcr.io/karthikbalaji1111-wq/honeyshield-*:1.1.0`; set `imagePullSecrets`
  if the packages are private (every workload now honours it).

### Added
* Console: user management (invite by one-time set-up link, role changes, deactivate/reactivate),
  tenant management for system admins, alert destinations with names and format help, deliveries
  linked to their events, audit log filter and readable actors, evidence and audit-chain
  verification with plain verdicts, decoys with their last trigger time and a link to their
  events, events filters (severity, address, time, decoy) and a detail panel, 14-day detections
  chart, light and dark themes.
* API: `GET /api/v1/detection-events/{id}`; `decoy_id`, `severity`, `ip_address`, `since`/`until`
  filters on the event list and CSV export; `GET /api/v1/detection-events/activity`;
  `last_triggered_at` on decoys; `created_at` on alert deliveries.
* `scripts/quickstart_env.sh`: complete local configuration in one command.
* Release workflow: multi-arch images with SBOM and signed provenance, gated on vulnerabilities.
* `LICENSE` (proprietary) and `THIRD-PARTY-NOTICES.md`, also shipped inside every image.

### Fixed
* Kubernetes upgrades with a migration briefly had no ready backend (502s): readiness now accepts a
  database that is ahead of the image (HONEY-059).
* The CI test step could not fail on failing or skipped tests (HONEY-060).
* Signing out left the previous account's data and one-time secrets in the page.
* Deployed third-party images carried fixable critical/high vulnerabilities, and CI scanned only
  our own images (HONEY-064). Runtime image shipped `pip` (HONEY-061).
* `.env.local` was not git-ignored.

### Security
* Findings HONEY-059 to HONEY-066 in `docs/security-findings-register.md`.

## 1.0.0
First verified deployment candidate: see `docs/remediation-audit-report.md`.
