# Changelog

Versions follow [Semantic Versioning](https://semver.org). The Helm chart's `appVersion` and the
release tag (`vX.Y.Z`) always match; the release workflow refuses a tag that does not.

## 1.5.0 — 2026-11-27

### Added
* **Active Directory decoys** (`AD_ACCOUNT`): a domain account nobody uses, with a password nobody
  knows. By default it also has an SPN, which makes it a Kerberoasting target. The decoy's setup
  script creates the account on a domain controller with a random password generated there.
  `HoneyShield-DCCollector.ps1` runs every minute as a scheduled task on each domain controller. It
  reads the Security log for events naming a decoy account and reports them through the signed
  customer-integration channel, using two new endpoints: `GET /integrations/v1/directory-manifest`
  and `POST /integrations/v1/directory-events`. The following are reported as CRITICAL:
  * Kerberos service tickets for the decoy (4769, T1558.003);
  * failed Kerberos, NTLM and interactive sign-ins (4771, 4768, 4776, 4625, T1110);
  * any successful sign-in (T1078.002).

  Reads of the account object (4662, T1087.002) are reported as HIGH when you turn on read
  auditing. The decoy needs `INTEGRATION_SIGNING_KEY`. See `docs/active-directory-decoys.md`.
* ATT&CK labels can depend on the event as well as the decoy type: an AD decoy's event is labelled
  with the technique its Windows event shows, in the API, in alerts and in CEF.
* **Splunk and Microsoft Sentinel alert destinations** (`SPLUNK_HEC`, `SENTINEL`). Alerts go
  straight into the SIEM, with no syslog receiver in between:
  * *Splunk* receives one JSON event per alert through the HTTP Event Collector (sourcetype
    `honeyshield:detection`, optional index). It works with Splunk Enterprise on port 8088 and
    Splunk Cloud on 443.
  * *Microsoft Sentinel* receives a row in a `HoneyShield_CL` table through the Azure Monitor Logs
    Ingestion API, using an Entra application and client credentials.
    `deploy/sentinel/honeyshield-sentinel.json` creates the table and the data collection rule.

  Tokens and client secrets are masked in API responses and the console. Delivery uses the
  webhook transport's SSRF checks and address pinning. See `docs/alerting-and-outbox.md`.

### Changed
* The console's event drawer calls the context section *Directory event* or *Cloud event* when the
  event is not an HTTP request.

### Upgrade notes
* `~/honeyshield/install.sh --upgrade --version 1.5.0` (or `<dir>/install.sh --upgrade --version
  1.5.0` for an installation made with `--dir`).
* No database migrations and no new settings. Active Directory decoys use the existing
  `INTEGRATION_SIGNING_KEY`. Splunk and Sentinel destinations need outbound HTTPS from the alert
  worker, as webhooks already do.
* Not yet verified outside the test suite:
  * the domain controller scripts, against a real Active Directory;
  * Splunk and Sentinel delivery, against real accounts;
  * the Sentinel ARM template, which has not been deployed.

  Each is tested end to end against simulated counterparts. Report anything that differs.

## 1.4.0 — 2026-11-26

### Added
* **DNS decoys** (`DNS`): a host name in a zone delegated to HoneyShield. Any lookup of it, or of any
  name ending in it, becomes a HIGH event with the resolver's address, the EDNS client subnet when
  sent, the query type and the time. Nothing is needed where it is planted. A new `dns` service
  (Compose profile `dns`, Helm `dnsDecoys`) answers for the zone. It holds no database credentials,
  spools every decoy lookup before delivering it signed to the backend, refuses other zones, gives
  the same answer for every name and rate-limits each source. See `docs/dns-tokens.md`.
* **Cloud canaries** (`AWS_KEY`): real AWS access keys that can do nothing. A new `cloud-canary`
  service (Compose profile `cloud-canary`, Helm `cloudCanary`) creates each key's IAM user, with a
  deny-all policy and a deny-all permissions boundary, and reads CloudTrail event history in every
  watched region. It records each use of a key as a CRITICAL event with the new provenance
  `CLOUD_AUDIT`, and deletes the IAM user when the decoy is revoked or rotated. See
  `docs/cloud-canaries.md`.
* `GET /api/v1/honey-tokens/types`: the decoy types this installation can watch. The console
  disables the others.
* Watchdog checks `DNS decoys` and `Cloud canaries`: the listener's heartbeat, the worker's status,
  AWS refusals and unreadable regions.
* **Document decoys** (`DOCUMENT`): a Word file that reports being opened. It loads a linked 1-pixel
  picture from the pixel route, so opening it in Word records a HIGH event with Word's user agent.
  There are no macros or fields, and the same decoy always gives the same file. It needs
  `PUBLIC_INGEST_BASE_URL`. See `docs/document-decoys.md`.
* **Bait files**: `GET /api/v1/honey-tokens/{decoy_id}/files/{kind}` returns a decoy already inside
  the file intruders look for:
  * AWS key: `~/.aws/credentials` and `.env`;
  * DNS: kubeconfig, SSH config and `.env`, each with its own label in front of the host name, so a
    hit says which file was used;
  * API key: `.env`;
  * Document: the Word file.

  Only administrators can download them, and every download is audited
  (`HONEY_TOKEN_FILE_DOWNLOADED`). Token listings name the files available for each decoy (`files`).
* **MITRE ATT&CK labels**: events (`attack` in the API and the console's event panel) and every
  alert name the techniques the decoy type points to, for example T1552.001 and T1078.004 for an
  AWS key. They appear in the webhook and PagerDuty payloads, Slack and email text, and CEF `cs6`.
* **PagerDuty alerts** (`PAGERDUTY`, `pagerduty://<integration key>` or `pagerduty+eu://…`): Events
  API v2 triggers with one dedup key per event. Delivery goes through the webhook transport's SSRF
  checks; 400 is permanent, while 429 and 5xx are retried.

### Changed
* **Console:** a white, neutral design. The page, app bar and sidebar are white, separated by
  hairlines, instead of a beige canvas with a graphite frame. Primary buttons are near-black, one
  blue is used for links and focus, honey appears only in the logo, and dark mode is neutral
  black. No page, element id or behaviour changed.
* **Dependencies:** FastAPI 0.165.0, Pydantic 2.14.4, SQLAlchemy 2.1.9 and other patch updates;
  refreshed PostgreSQL 16.16 and nginx 1.30.7 base images; CodeQL action 4.39.4.

### Fixed
* Opening the console signed out, or signing out, showed an "Authorization header" error toast.
  Resetting the events filter reloaded events with no session.

### Upgrade notes
* `~/honeyshield/install.sh --upgrade --version 1.4.0` (or `<dir>/install.sh --upgrade --version
  1.4.0` for an installation made with `--dir`).
* Migration `20261122_01` adds `CLOUD_AUDIT` to the allowed event sources and a partial unique index
  on CloudTrail event IDs. It runs online: the constraint is re-added `NOT VALID` and then
  validated, and the index is built `CONCURRENTLY`.
* Both new services are off unless listed in `COMPOSE_PROFILES` (or enabled in Helm). Existing
  installations behave exactly as before.
* Webhook payloads gain a field, `data.attack`. Receivers that reject unknown fields need updating.
  The envelope stays at `version` 1 because the change only adds a field.
* Document decoys, bait files, ATT&CK labels and PagerDuty need no migration or new configuration.

## 1.3.3 — 2026-11-21

### Upgrade notes
* `~/honeyshield/install.sh --upgrade --version 1.3.3`, or for an installation made with `--dir`:
  `<dir>/install.sh --upgrade --dir <dir> --version 1.3.3` (the `--dir` is only needed to upgrade
  *to* 1.3.3; from then on `<dir>/install.sh --upgrade` finds its own directory). No database or
  configuration changes.

### Fixed
* `<dir>/install.sh --upgrade` ignored `<dir>` and looked in `~/honeyshield`, so an installation
  made with `--dir` could not be upgraded with the command the installer prints. The installer now
  defaults to the installation it is run from (recognised by its `.env`, `docker-compose.yml` and
  `install.sh` link, which a source checkout does not have).
* A failed `--upgrade` (no installation in the directory) created the directory and downloaded the
  deployment files before giving up. It now stops before touching anything.

### Security
* Evidence checkpoints and exports are created `0400` (owner only) instead of 1.3.2's `0440`: no
  other process reads them, so the group needs no access.
* The tests and `scripts/verify_deployment.py` build their TLS contexts the same way as the
  application (TLS 1.2 minimum), which also closes the two CodeQL alerts that followed those paths.

## 1.3.2 — 2026-11-21

From the first public CodeQL scan of `HoneyShield-source` (16 alerts: 5 changed here, 11 reviewed
and dismissed as false positives, with the reason recorded on each alert).

### Upgrade notes
* `~/honeyshield/install.sh --upgrade --version 1.3.2`. No database or configuration changes.
* If something outside HoneyShield reads files in the evidence checkpoint volume as a different user
  (not the group of the checkpointer), give it that group or read them as root: new checkpoints are
  `0440`. Files written before the upgrade keep their old mode.
* A webhook, syslog, SMTP, S3 or OIDC server that only speaks TLS 1.0 or 1.1 is now refused. Such
  servers were already refused by the default OpenSSL configuration of the images.

### Security
* Every connection HoneyShield makes to another server (webhooks, syslog/SIEM over TLS, SMTP, S3 and
  WORM storage, OIDC sign-in, the watchdog's probe) now requires TLS 1.2 or newer explicitly, through
  one shared helper (`app.core.tls`). Python's default already refused older versions on current
  OpenSSL builds, but that depended on the system's OpenSSL configuration. A test fails if code
  creates its own TLS context again. `scripts/verify_deployment.py` sets the same floor.
* Evidence checkpoint files and evidence exports are created `0440` instead of `0444`: still
  read-only, but no longer readable by other users of the host. Exports contain attacker IP addresses
  and request details.

### Changed
* An invalid `TRUSTED_PROXIES` entry is logged by its position ("entry 2 is not an IP address or CIDR
  network") instead of echoing the configured value.

## 1.3.1 — 2026-11-20

### Upgrade notes
* `~/honeyshield/install.sh --upgrade --version 1.3.1`. No database changes. Images now come from
  the public repository `HoneyShield-source` with a signed build record; check one with
  `gh attestation verify oci://ghcr.io/karthikbalaji1111-wq/honeyshield-backend:1.3.1 --repo karthikbalaji1111-wq/HoneyShield-source`.

### Fixed
* Installing with the one-line command failed on a fresh machine: downloaded files are not
  executable, so the database never ran `docker/init-db.sh` and its roles were missing. The installer
  now marks the scripts executable, and CI installs from non-executable copies to keep it that way.
* Two `Strict-Transport-Security` headers on proxied responses (edge and backend); the edge is now
  the only source.
* Console forms submitted by the browser itself (for example if the script failed to load) used GET,
  which would put a password in the URL. Every form now uses POST.
* The watchdog's `--once` output showed warnings as FAIL; it now shows WARN.

### Added
* Images are built and signed in the public repository, so anyone can prove an image came from a
  given public commit (`docs/verify-it-yourself.md`).
* `install.sh --build`: builds every image on the machine from the published source instead of
  downloading them.
* Security analysis in public CI: CodeQL (Python, JavaScript, workflows), Bandit (medium and high
  findings fail the build), and an OWASP ZAP baseline scan of a freshly installed, self-tested
  stack. Accepted findings are documented next to the code and in `.zap/rules.tsv`.
* Fuzz tests (Hypothesis) for the WebAuthn/CBOR, backup encryption, S3 XML and decoy path parsers
  and for the public decoy endpoints over HTTP.
* `scripts/reproduce_outage.sh`: sends decoy hits while the backend and then the database are down
  and checks every one is recorded exactly once and the evidence chain verifies.
* `docs/verify-it-yourself.md`: how to check every claim independently.

### Changed
* XML from S3-compatible servers is parsed with `defusedxml` (no DTDs, no entity expansion).
* Stricter headers: `base-uri` and `form-action` in the default Content-Security-Policy; on the
  decoy host a Content-Security-Policy, Permissions-Policy and Cross-Origin-Resource-Policy on every
  response; on the console a Permissions-Policy that allows only passkeys, and cross-origin isolation.
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
