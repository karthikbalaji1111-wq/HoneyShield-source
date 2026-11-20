# HoneyShield remediation — audit of the work performed

Period: 2026-11-13 → 2026-11-17.
This report explains **what was changed, how, why, and what evidence supports each claim**.
Committed on branch `remediation/deployment-candidate` on the owner's instruction; not pushed (§10, §12).

---

## 1. Executive summary

| | Before | After |
|---|---|---|
| Classification | engineering alpha | **deployment candidate** (production-readiness.md) |
| Tests | 336 (SQLite only; DB-level claims unverified) | **731 passed / 0 failed / 0 skipped**, repeated runs, with real PostgreSQL, S3 Object Lock (MinIO) and Redis (§13) |
| Deployment | localhost-only, single vhost, never run end to end; API ran as the DB superuser | Docker Compose **and Kubernetes (Helm)**, both **56/56** end-to-end checks through TLS with 2 API replicas; zero-downtime rolling upgrades measured (§13) |
| Decoy types actually detectable | URL, LINK, PIXEL (to the wrong host); FORM_FIELD flawed; API_KEY undetectable | all five, via the ingest host or a signed customer hook |
| Evidence | ORM-level immutability; superuser runtime; manual events indistinguishable | provenance, DB-enforced append-only for the runtime role, hash chain, signed checkpoints, restore drill |
| Alerting | in-process broadcast only | transactional outbox + webhook worker with retries, dead letter and SSRF protection |
| Dependencies | 16 known advisories (starlette, anyio, PyJWT, python-dotenv); image had 2 HIGH CVEs | pip-audit clean; image scan 0 critical/high |
| Findings HONEY-001…052 | open | 018 closed in configuration (real DNS/TLS needs an environment); 016 partial until CI runs on GitHub; the rest closed with evidence — security-findings-register.md |

## 2. Rules followed

From the mandate, applied throughout:

* **No git writes**: no stage, commit, push, reset, checkout, restore, stash, clean or branch
  change. Pre-existing uncommitted work (71 modified + 38 untracked files at the start) was
  preserved; existing files were changed with targeted edits.
* **No destruction**: no deletion of user files, volumes or databases. Verification used a
  dedicated Compose project (`hsverify`), a disposable PostgreSQL cluster in the session scratch
  directory (port 55432, localhost only) and per-run test databases the harness itself creates
  and drops. One attempted `rm` of scratch certificates was blocked by a safety check; a new
  directory was used instead.
* **No external side effects**: no data sent to third parties; webhook delivery was tested only
  against a local receiver; only public, read-only lookups were made (GitHub tag → SHA, PyPI
  metadata, image pulls, Docker Scout CVE data).
* **Secrets**: verification secrets were generated with `openssl rand` into the scratch directory
  and never printed; the user's `.env` was read for key names only, never values, and never used.
* **No fabricated evidence**: every number in this report comes from a command run in this
  session; things not run are marked NOT RUN / BLOCKED.
* **Docker Desktop** was started (it was installed but stopped) under the owner's instruction to
  proceed without asking; nothing pre-existed in Docker.

## 3. Method

Each workstream followed the same loop:

1. **Read** the implementation, its callers, tests and docs (never trusting earlier reports).
2. **Threat-model** the change: what an attacker, a buggy client and an operator could do.
3. **Design** the smallest change that closes the issue at the right layer (database where the
   guarantee must hold against the application itself).
4. **Implement**, then **test at three levels**:
   * SQLite unit/API tests (fast, behaviour and authorization);
   * **real PostgreSQL** tests authenticated as each role (anything involving triggers, grants,
     constraints, locking or concurrency — SQLite cannot prove these);
   * **the real deployment** through nginx/TLS (`scripts/verify_deployment.py`).
5. **Run the full suite** after every change; inspect failures before touching tests. Tests were
   only changed when the old assertion encoded the vulnerability (e.g. per-token 429, chosen token
   values) — each such change asserts the new security property instead.

### Techniques worth noting

| Technique | Used for |
|---|---|
| Disposable PostgreSQL 17 cluster (`initdb`, TCP on 127.0.0.1, trust auth) | real-DB verification while Docker was unavailable |
| Per-session test database + owner/runtime roles created by the pytest harness, migrations applied via Alembic subprocess, grants via the shipped CLI | tests run against exactly the production schema and privilege model |
| Connections authenticated **as the role under test** + raw SQL | proving grants/ownership/triggers rather than ORM behaviour |
| `threading.Barrier` to widen race windows | idempotency race (8 workers past the pre-check), SKIP LOCKED claims (4 workers), chain ordering (8×5 concurrent hits) |
| Core-SQL tampering on SQLite (no triggers) | proving the hash chain *detects* modification, reordering, removal, insertion and a full rewrite |
| Following delivered artifacts | every decoy test generates via the API and follows the URL/src/href the customer would deploy |
| Shipping the customer client and testing through it | hook tests drive `integrations/python/honeyshield_hook.py` over a transport bound to the app |
| Migration rehearsal on seeded legacy data | 5 000 legacy events + mixed-case emails/domains; upgrade → downgrade → upgrade |
| Live probes in the deployed DB | psql as `honeyshield_app` over TCP with its password |
| Back-up then restore into a new DB, then verify | `scripts/restore_drill.sh` |
| Benchmark through the service layer | 1M events, 50 tenants, medians of 5 |
| Dependency trial in a separate venv | upgrade adopted only after the full suite passed on it |

## 4. Workstreams

### 4.1 Detection credibility (HONEY-003/004, severity)
* **Ingest origin**: `PUBLIC_INGEST_BASE_URL` (validated https origin, required in production);
  generators receive it as a parameter. Artifacts never point at the customer domain.
* **Per type**: URL/LINK unchanged in mechanism; PIXEL no longer emits a page snippet (every
  visitor would fire it) — only `embed_html` for decoy documents/emails with a placement warning;
  FORM_FIELD is now an **empty** off-screen honeypot (`html_snippet`, bot-attractive names, no
  fake CSRF value), detected by the customer; API_KEY detection via the customer hook.
* **Severity by type** (URL/PIXEL HIGH, LINK/FORM_FIELD MEDIUM, API_KEY CRITICAL), never from
  the caller.
* **Rotation bug found and fixed**: rotation copied the old artifact metadata, so a rotated URL
  token's artifact still pointed at the revoked value. Rotation now regenerates value and
  artifact (keeping provider style / field name).

### 4.2 Ingestion reliability (HONEY-001)
Token resolved **before** any limiter; valid hits stored even with exhausted global/key budgets;
per-(IP, token) evidence counter that fails open; repeats above 60/min summarised by one audit
record; HTTP response depends only on the caller's rate, so it is not a validity oracle; nginx
`limit_req` bounds the per-request lookup. Verified in tests and live (120-request burst → 60×429
at the edge, valid hits still recorded).

### 4.3 Provenance and manual events (HONEY-006)
`detection_events.source` (no default, CHECK-constrained), `created_by_user_id` required for MANUAL
(CHECK), mandatory `reason`, event and audit committed atomically. Migration labels existing rows
`LEGACY_UNVERIFIED` using a catalog-only `ADD COLUMN … DEFAULT` so the immutability trigger never
fires (verified on 5 000 rows), constraints added `NOT VALID` then validated.

### 4.4 Client IP (HONEY-005)
Right-to-left X-Forwarded-For walk skipping trusted proxies; one implementation for ingestion,
login and the API limiter; nginx overwrites XFF; compose trusts only nginx's fixed address.
Live: a spoofed `X-Forwarded-For: 6.6.6.6` was ignored.

### 4.5 Database least privilege (HONEY-002)
Three identities (bootstrap superuser / `honeyshield_owner` / `honeyshield_app`). Grant policy as
code with mandatory classification of every table (fail closed). Start-up and readiness guard
refuses a privileged runtime role. Compose `migrate` job runs migrations + grants as owner.
Verified with 26 PostgreSQL cases and live probes (permission denied / must be owner for every
evidence-rewriting or DDL statement; triggers block even the owner).

### 4.6 Customer integrations (HONEY-004 API_KEY/FORM_FIELD)
Per-project credentials whose secrets are **derived** (HMAC of a master key, public id and salt) —
nothing secret stored. HMAC-signed requests over method/path/timestamp/body; ±5 min window;
idempotency enforced by a unique constraint (replays and concurrent duplicates store one event,
verified on PostgreSQL); opaque `decoy_id` + SHA-256 manifest so keys are never transmitted;
uniform 202 for unknown/foreign decoys; credential-like headers and reports containing the key
rejected without echoing values; separate failure/success/evidence limiters; reference client
with bounded queue, bounded retries and non-blocking checks. 35 tests + 2 PostgreSQL tests + E2E.

### 4.7 Host separation (HONEY-003/018/033)
Two nginx vhosts (ingest host serves only four prefixes; control host refuses them; unknown Host
→ 444) **and** an app middleware enforcing the same split; API docs off in production. Edge TLS
1.2/1.3 with modern ciphers, HSTS, body/header/time limits, per-zone `limit_req`/`limit_conn`.

### 4.8 Durable alerting (HONEY-007)
Transactional outbox rows inserted in the event transaction; lease-based worker using `FOR UPDATE
SKIP LOCKED` (horizontally scalable); signed webhook (HMAC over timestamp.body) or Slack/Teams
text; retry policy with capped exponential backoff and jitter; dead letter + audit; delivery
history API; SSRF guard re-resolving and **pinning** the validated address per delivery with
hostname-verified TLS. A test caught the token value leaking into alert payloads through
`request_path`; payloads now carry `{token}` instead.

### 4.9 Evidence integrity (Phase 9)
Per-tenant hash chain in an append-only table, head row locked per tenant inside the event
transaction; verifier detects modified fields, broken links, gaps, missing/unchained events, head
mismatch and — with HMAC-signed checkpoints written write-once by a dedicated service — a fully
recomputed chain. Exports are re-verifiable offline. Verified with 12 tamper tests, 40 concurrent
hits on PostgreSQL (gapless), deployed checkpoints, and after restore.

### 4.10 Streaming (HONEY-014/025)
Streams carry the JWT `exp` and stop at it; revalidation also ends streams on role or tenant
change; 500 global / 25 per-tenant connection caps (SSE 429, WS 1013); dropped events counted.

### 4.11 Disclosure and identity hardening
HONEY-012 (tenant-chosen token values → oracle; now server-generated, identical 422 for taken
and free values), HONEY-013 (global domain check leaked other tenants' domains; now per-tenant,
matching the DB constraint), HONEY-015 (masking for TENANT_USER, redaction in streams and
alerts), HONEY-020 (denial audit committed the caller's work; now an independent session —
proven on PostgreSQL), HONEY-022 (lower-cased emails, `unique(lower(email))`, stop-on-collision
migration), HONEY-023 (row-locked last-SYSTEM_ADMIN guard), HONEY-024/032 (hostname validation,
metadata and payload caps), HONEY-033 (inbound request IDs validated), HONEY-034 (cached heads),
HONEY-010 (audit FKs `SET NULL` → no action).

### 4.12 Accounts (HONEY-029)
`/auth/logout` and `/auth/change-password` revoke every token via `token_version`; `/auth/me`.
MFA/reset/SSO deferred with rationale (security-model.md).

### 4.13 Observability (HONEY-027)
Token-gated Prometheus `/metrics` (ingest outcomes, hook outcomes, HTTP status/latency, outbox
backlog/age, stream health, DB pool, DB up); SLOs and alert rules documented.

### 4.14 Deployment, CI, dependencies (HONEY-016/017/018/028)
Compose rewritten around the role split and services; Dockerfile hardened (OS security updates,
code read-only for the runtime user); CI workflow with Python 3.12, PostgreSQL service, migration
round-trip, PG tests that must not skip, `pip-audit --strict`, image/compose/nginx checks,
SHA-pinned actions, `permissions: contents: read`. Dependencies upgraded (FastAPI 0.163.1 /
Starlette 1.10.0 …) after a trial venv passed the full suite. Restore drill script.

### 4.15 Operator console (M12)
Static, same-origin console (no framework, no external code): login, overview + live feed (WS),
projects and decoy lifecycle with placement guidance, events with provenance, integrations
(secret shown once), alert destinations and deliveries, audit history, evidence verification,
password change and global sign-out. All API data rendered with `textContent`; strict CSP.
Served and CSP-checked in E2E; interactive browser walkthrough: NOT RUN.

## 5. Defects found only by running the real system

| Defect | How found | Fix |
|---|---|---|
| Image code unreadable by the runtime user (host umask 077 → files 600/700) | `migrate` exited 255 ("No script_location") | `chmod -R u=rwX,go=rX` in the Dockerfile |
| nginx kept a replaced backend's IP → 502 after every backend redeploy | E2E after recreating backend | Docker DNS `resolver` + variable upstream |
| Webhook creation would always fail in production (API network has no public DNS) | reasoning from the deployed topology, then live test | DNS advisory at creation; authoritative check at delivery |
| Python 3.15 strict X.509 rejected the first test certificate | verification client | proper CA/leaf extensions (real CAs already comply) |
| Image base had 2 HIGH zlib CVEs | `docker scout cves` | `apt-get upgrade` in build; rescan clean |
| Image health check would mark worker/checkpointer unhealthy and ignored host separation | review during compose rewrite | health checks per compose service |

## 6. Test report

| Suite | Command / environment | Result |
|---|---|---|
| Full suite | `pytest -q` with `HS_TEST_PG_ADMIN_URL` (Python 3.12.16, upgraded deps, PostgreSQL 17) | **523 passed, 0 failed, 0 skipped, 1 warning** (test-client tooling), 80 s (2026-11-16) |
| of which PostgreSQL | `tests/postgres/` | 37 passed (26 privilege + 11 API/hook/concurrency/chain/hidden-commit) |
| Migrations on PostgreSQL | seeded legacy DB; `upgrade head` → `downgrade 20261019_01` → `upgrade head` | passed; 1 000/5 000 legacy events preserved |
| Deployment E2E | `scripts/verify_deployment.py` on compose stack via nginx/TLS | **40 passed, 0 failed** (3 runs, last on the final image) |
| Live privilege probes | psql as `honeyshield_app` | 6/6 refused |
| Worker on deployed stack | queued delivery, worker stopped/started | claimed, DEAD + audit, graceful SIGTERM |
| Restore drill | `scripts/restore_drill.sh --cleanup` | **passed twice** (counts equal, head, 6 triggers, chain OK, role OK) |
| Dependency audit | `pip-audit -r backend/requirements.txt` | no known vulnerabilities |
| Image scan | `docker scout cves --only-severity critical,high` | no vulnerable packages |
| CI config steps | compose config (full/empty env), non-root, nginx -t | passed locally |
| GitHub Actions run | – | **NOT RUN** (nothing pushed) |
| Benchmark | 1M events | see production-readiness.md; 10M NOT RUN |
| Browser walkthrough of console | real browser against the real backend + console files (§12) | **PASS**: forced enrolment, wrong-password handling, TOTP + recovery-code sign-in, decoy generation, pixel hit → event, MFA reset, audit trail, evidence verify; no script errors |
| External webhook receiver, real DNS/CA TLS | – | BLOCKED (environment/authorization) |

## 7. Milestones M1–M16B (summary)

| Milestone | Final state | Key evidence |
|---|---|---|
| M1 infrastructure | production config validation, reproducible env template, pinned deps | config tests, compose refuses missing secrets |
| M2 backend | host routing, request IDs validated, cached readiness | middleware tests |
| M3 database | linear chain, 6 new migrations, owner/runtime split | PG tests, migration rehearsal |
| M4 models | provenance, integrations, alerting, evidence tables with constraints | PG constraint tests |
| M5 repositories | tenant-scoped lookups, ambiguity guard, keyset pagination | tests, benchmark |
| M5.5 exceptions | integration/not-configured errors; generic validation errors | tests |
| M6 services | hook, alerting, evidence services; no hidden commits | PG hidden-commit test |
| M7 API | integrations, destinations, audit, evidence, me/logout/password | API tests |
| M8/M14 auth | revocation, stream expiry, case-insensitive identity | auth + stream tests |
| M9 token engine | server-generated values, regenerating rotation, empty honeypot | lifecycle tests |
| M10 detection | ingest-host artifacts, hook detection, per-type severity | E2E all five types |
| M11 analytics | ranking fixed; heuristic (not ML) stated; measured at 1M | benchmark |
| M12 dashboard | operator console | served with CSP in E2E |
| M13 audit | audit listing; denial audits independent; manual reason | tests |
| M15 isolation | cross-tenant tests per resource family incl. new ones | tests |
| M16 users | reactivation fixed; last-admin guard | tests |
| M16B streaming | expiry, role change, caps, drop counters | stream tests |

## 8. File inventory (this work)

**New**: migrations `20261113_01…06`; `app/api/ingestion/integrations.py`, `app/api/metrics.py`,
`app/api/v1/{alerting,audit_logs,evidence,integrations}.py`, `app/core/{integration_auth,metrics,
redaction}.py`, `app/db/{privileges,runtime_guard}.py`, `app/middleware/host_routing.py`,
`app/models/{alerting,evidence,integration}.py`, `app/schemas/integration.py`,
`app/services/{integration,evidence}.py`, `app/services/alerting/{__init__,webhook}.py`,
`app/workers/{outbox,evidence}.py`; tests under `tests/{alerting,deployment,evidence,integrations,
postgres}/` and `tests/{auth/test_session_lifecycle,security/test_metrics,security/test_viewer_masking,
streaming/test_stream_lifecycle,user/test_identity_hardening,user/test_user_activation,
security/test_client_ip_resolution,ingestion/test_severity_by_type,database/test_top_attackers_ranking,
forensics/test_event_provenance,honey_token/test_ingest_artifacts}.py`;
`frontend/console/{index.html,app.js,app.css}`; `integrations/python/honeyshield_hook.py`;
`proxy/templates/default.conf.template`, `proxy/hs_proxy_headers.conf`;
`scripts/{verify_deployment.py,restore_drill.sh}`; 21 documents in `docs/` (this file included).

**Modified (targeted)**: config, main, routers, services, repositories, schemas and models listed
in the sections above; `docker-compose.yml`, `docker/Dockerfile.backend`, `docker/init-db.sh`,
`.env.example`, `.dockerignore`, `.github/workflows/ci.yml`, `backend/requirements.txt`,
`backend/pytest.ini`, `backend/alembic/env.py`, `scripts/restore_postgres.sh` (post-restore note),
existing tests whose contract changed (documented in each test), existing docs (superseded
banners, corrected readiness contract, updated limits).

**Not touched**: `.env`, `proxy/certs/`, `proxy/nginx.conf` (superseded by the template, left in
place), scratch/patch scripts (`scratch/`, `backend/scratch/`, `patch_compose*.py`,
`backend/fix_threat.py`, `backend/patch_imports.py`) — excluded from the image; owner to decide.

## 9. Not done

Real DNS/CA certificates on a staging host; delivery to a customer's real webhook, mail relay or
SIEM; a real S3 Object Lock bucket (all verified against local equivalents only); GitHub CI run
(the owner pushes); a managed cloud Kubernetes cluster (verified on k3s); a commercial IdP for SSO
(verified against a local OIDC provider); external penetration test;
WebAuthn/passkeys. Everything else listed here in earlier versions was completed (§12, §13).

## 10. Final handoff

* Committed (on the owner's instruction) on branch `remediation/deployment-candidate`, created
  from local `main` at `2d704f3`. Nothing pushed. Local `main` is **1 commit behind
  `origin/main`**; that upstream commit's files were already in the worktree and are included in
  this commit, so merging `origin/main` afterwards needs a deliberate review (HONEY-031).
* Not committed (ownership not established, HONEY-030): root `scratch/`, `backend/scratch/`,
  `patch_compose.py`, `patch_compose_p14.py`. They remain in the working tree untouched.
* Verification stack still running as Compose project `hsverify` (ports 18080/18443 on
  127.0.0.1); stop with `docker compose -p hsverify down` (add `-v` only to discard its test data).
* Next actions, in order: push the branch and let CI run → staging with real DNS/certs →
  `scripts/verify_deployment.py` + `scripts/restore_drill.sh` there → external webhook test and
  WORM checkpoint shipping → MFA decision → pilot.

## 11. Pre-commit re-verification (2026-11-15)

Everything was re-run on the exact tree being committed, after the final changes:

| Check | Result |
|---|---|
| Full test suite, PostgreSQL tests required (`--strict-markers -rs`) | 506 passed, 0 failed, 0 skipped |
| Deprecation clean-up (Starlette 1.x status constant names, pytest-asyncio loop scope) | warnings 49 → 1 (test-client tooling only) |
| Image rebuilt from this tree, stack redeployed, `scripts/verify_deployment.py` through TLS | 40/40 PASS (run twice) |
| `python -m app.db.privileges check` in the deployed backend | passed |
| `scripts/restore_drill.sh --cleanup` against the deployed stack | PASSED (chain verified per tenant, least privilege on the restored copy) |
| `pip-audit -r backend/requirements.txt --strict` | no known vulnerabilities |
| Image user | UID 10001 |

New defect found during this pass and fixed: `backups/` (the default output directory of
`backup_postgres.sh` and `restore_drill.sh`) was not git-ignored, so a database dump containing
live decoy values could have been committed. `.gitignore` now excludes `backups/`, `*.dump`,
`*.dump.sha256` and `*.env`; `.dockerignore` excludes the same plus key material from the build
context. The drill's dump was moved out of the repository.

## 12. Second session (2026-11-16): sync, MFA, browser walkthrough, production-mode run

**Git.** The work was committed on `remediation/deployment-candidate` (`e9a2e31`). `origin/main`
(`868a111`, an earlier snapshot of the same work) was compared line by line: every line it adds is
either on the branch or deliberately superseded (artifacts now target the ingest host, PyJWT
upgraded for a CVE, top-attackers ordering fixed, tests updated for server-generated values and
mandatory reasons). Its scratch scripts were byte-identical to the working tree, which settled
their ownership; they were committed unchanged and `origin/main` was merged (`ded6b33`), so the
branch merges cleanly into `main`. Pushing failed: this machine has no GitHub credentials.

**Operator MFA (HONEY-029, now CLOSED).** Method: RFC 6238 TOTP implemented with the standard
library and checked against the RFC 4226/6238 test vectors.
* Secrets are derived (HMAC of `MFA_SECRET_KEY`, user id and a per-enrolment nonce), never stored,
  the same pattern as integration secrets; recovery codes are stored as keyed hashes.
* Replay guard: the accepted 30 s step is stored and must increase, under a row lock.
* Enforcement lives in token resolution: tokens carry `amr`; an enrolled user's password-only
  token is refused; a role in `MFA_REQUIRED_ROLES` without MFA gets an enrolment-only session
  (also refused by streams). Production defaults to admins and refuses to start without
  `MFA_SECRET_KEY`.
* Admin reset with an audited reason; nobody can reset their own MFA.
* Tests: `tests/auth/test_mfa.py` (13) plus configuration tests; existing tests updated only where
  the contract intentionally changed (`amr` claim, `/auth/me` fields, production config fixtures).

**Defects found this session.**
1. `backups/` was not git-ignored, so a dump holding live decoy values could have been
   committed. Fixed in `.gitignore` and `.dockerignore` (§11).
2. ORM constraint names differed from the migrated schema, and the `lower(email)` index was not
   declared. Aligned; `alembic check` now reports no drift and runs in CI.
3. Uvicorn's default proxy-header handling rewrote the client address before the app's
   trusted-proxy walk. In the compose stack Nginx is not a loopback peer, so it was latent there,
   but running the backend in production mode outside Docker recorded a spoofed
   `X-Forwarded-For`. The image now runs Uvicorn with `--no-proxy-headers`; a test pins it.
4. Console: any 401 signed the user out, including a mistyped current password. Credential checks
   now keep the session. Its MFA reset used a blocking `prompt()` dialog; replaced with an inline
   form.

**Browser walkthrough (real browser, real backend, console files).** Covered:
* forced enrolment screen;
* wrong password shows an error and keeps the session;
* secret and `otpauth://` URI shown; a code computed by an independent authenticator
  implementation enables MFA; recovery codes shown once;
* full console with the live feed connected;
* sign-out, then sign-in challenge, then recovery-code sign-in;
* pixel decoy generated, triggered, and the event shown;
* Users view: MFA reset with reason;
* audit trail shows every step; evidence chain verifies;
* no script errors.

**Production-mode run without Docker.** Docker Desktop's engine hung on start (VM up, engine socket
timing out) and did not recover after a restart; a factory reset would destroy Docker data, so it
was not attempted. Instead the backend ran natively in production mode, reproducing the compose
security model:
* `docker/init-db.sh` created the owner and runtime roles on PostgreSQL;
* migrations and grants ran as the owner, the API as the runtime role, so the start-up guard and
  `privileges check` passed;
* TLS with a CA-signed certificate; `scripts/verify_deployment.py` ran through it.

Result: **41/43 PASS**. The 2 failures are the checks only Nginx performs (dropping unknown
`Host` headers, serving the console). The edge rate-limit check was skipped. The MFA checks
passed both ways: the first run enrolled the system admin, the second used the TOTP challenge.

**Compose stack with the MFA build (later the same day).** Docker Desktop came back after a
restart. The image was rebuilt from `b63abab` (tag `verify2`) and the full stack (postgres,
migrate, backend, worker, checkpointer, nginx) started healthy as a fresh project with its own
volumes, ports, subnet and CA-signed certificate; the pre-MFA stack was stopped, not removed.
* The first system admin was created with `python -m app.bootstrap` inside the backend container,
  using a generated password kept in a mode-600 file.
* `scripts/verify_deployment.py` ran twice through Nginx and TLS with `--totp-secret-file`:
  **45 passed, 0 failed** each time, no skips (edge rate limit included). Run 1 enrolled the system
  admin in MFA and stored the secret mode 600. Run 2 signed in through the TOTP challenge. Both runs
  also passed the per-run checks for forced tenant-admin enrolment, refusal without a code, and
  TOTP sign-in.
* `scripts/restore_drill.sh --cleanup` against this stack: **PASSED**. The dump was
  checksummed, then restored into a new database owned by the schema owner, and grants were
  re-applied (22 statements). Checks on the copy:
  * migration head `20261116_01`;
  * row counts identical to the source;
  * 6 immutability triggers;
  * both tenants' evidence chains verify;
  * the runtime role passes the least-privilege check.

  Only the drill's own database was dropped afterwards.

This closes the gap left by the native run: the two Nginx-only checks (unknown `Host` dropped,
console served with CSP) pass in the compose stack.

| Check (2026-11-16) | Result |
|---|---|
| Test suite, PostgreSQL required | 523 passed, 0 failed, 0 skipped |
| Migration round trip + `alembic check` on PostgreSQL | passed; no drift |
| `pip-audit --strict` | no known vulnerabilities |
| Browser walkthrough of the console | PASS |
| Native production-mode E2E (TLS, owner/runtime roles) | 41/43 (2 Nginx-only checks) |
| Compose stack E2E with MFA (via Nginx/TLS) | **45/45 PASS**, twice (enrol run + TOTP run) |
| Restore drill on the MFA stack | **PASSED** (head `20261116_01`, counts match, 6 triggers, chains verify, least privilege) |
| GitHub CI | NOT RUN (no credentials to push) |

## 13. Third session (2026-11-17): closing the remaining product gaps

The owner asked for an industry-deployable product ready for customers, built and tested
end to end. Every item below was implemented, tested at the level it needs, and committed on
`remediation/deployment-candidate` (`9ea53dd` … `edc759f`). Nothing was pushed.

### What was built

| Area | What | Evidence |
|---|---|---|
| Tamper-evident audit log | hash chain sealed after commit by the checkpointer; head in signed checkpoints | unit + PostgreSQL tests; verified in E2E, restore drill and the cluster |
| WORM evidence | checkpoints shipped to S3 Object Lock (COMPLIANCE) with stdlib SigV4 | AWS SigV4 test vectors; real MinIO: overwrite and delete refused; TLS MinIO in Compose incl. outage and catch-up |
| Alert channels | email (SMTP relay, signed headers), SIEM (syslog over TLS, CEF); test alerts; operator-allowed private networks | real SMTP server and TLS syslog listener in tests |
| Scale-out | 2+ API replicas; Redis-shared sliding-window limits and live-stream relay; safe fallback | real Redis tests; E2E with 2 replicas and with Redis stopped |
| Accounts | password reset (admin link, self-service email), per-account login throttle, session renewal with 12 h cap, personal API keys, OIDC SSO | unit tests incl. a real local IdP; E2E checks; browser walkthroughs |
| Data lifecycle | retention: signed write-once archive, then owner-only purge with chain anchors | PostgreSQL tests of the trigger exemption (runtime role cannot delete even with the flag) |
| Operations | CSV export (formula-injection safe), Helm chart, Prometheus rules with promtool tests, hardened edge image | k3s cluster with restricted Pod Security; kubeconform; promtool; Docker Scout |

### Method

The same rules as before (§2): no destructive git or database operations, secrets only in
mode-600 files and never printed, results recorded as measured.
* **Real dependencies.** Each feature was tested against the real thing it depends on: PostgreSQL
  roles and triggers, MinIO with Object Lock, Redis, an SMTP server, a TLS syslog listener, an
  OIDC provider with its own signing keys, and a Kubernetes cluster with Pod Security and
  NetworkPolicy enforcement.
* **Intermittent failures were hunted, not retried.** Tests were looped hundreds of times and
  the failure timestamps recorded. Both intermittent failures this session turned out to be
  product defects (rows 6 and 12 below).

### Defects found and fixed this session

| # | Defect | How it was found | Fix |
|---|---|---|---|
| 1 | change-password returned 500 for passwords over 72 bytes | probe while writing reset tests | validated `Password` type |
| 2 | audit checkpoint of an empty chain reported a mismatch | worker round-trip test | genesis anchor at seq 0 |
| 3 | checkpointer restart-looped while S3 was unreachable | Compose run with the TLS MinIO down | exit 3 keeps the loop; catch-up next cycle; health check |
| 4 | password-reset traffic shared the login edge budget | Compose verifier (429 on login) | separate nginx zone |
| 5 | console reopened an admin view for a viewer | browser walkthrough | view checked against the role |
| 6 | fixed windows allowed 2× bursts across a boundary (a flaky test) | probe loop: failure exactly at :59.8 → :00.4 | sliding-window counter, local and Redis |
| 7 | caller authenticated twice per request (double limiter charges) | API-key flood test | resolved once per request |
| 8 | API keys reached `/auth/*` endpoints | session-renewal work | keys refused on `/auth/*` |
| 9 | IdP key rotation failed for 30 s after any JWKS fetch | key-rotation test | forced-refresh limit tracked separately |
| 10 | migration 20261117_05 downgrade failed | PostgreSQL round trip | constraint name via `op.f()` |
| 11 | Helm `--wait` hung on an unbound archive volume | real k3s install | retention archives only to S3 in Kubernetes |
| 12 | **syslog alerts could be lost after being recorded as delivered** (TCP RST on close) | 40-run loop caught a 1-in-16 failure | TLS close_notify / TCP half-close + drain |
| 13 | edge base nginx 1.28 out of support: 3 critical / 4 high CVEs | Docker Scout | nginx 1.30.6, unused modules removed: 0 critical / 1 high (unfixed upstream) |
| 14 | rolling restarts dropped requests (4 of 1,759) | continuous HTTPS load during `rollout restart` | preStop delay + graceful stop: 0 of 2,554 and 0 of 2,524 |
| 15 | SSO sessions inherited the IdP's (possibly days-old) `auth_time`, so the first renewal signed the user out | code re-read | HoneyShield sign-in time; regression test |
| 16 | **event pagination and CSV export silently skipped events** (cursor on `id`, order on `triggered_at`) | export review + failing test | `(triggered_at, id)` keyset, composite index, eager loading |
| 17 | **self-service reset emails could never be delivered in the reference deployments**: the API sent them, but the API has no internet egress (Compose internal network, Kubernetes NetworkPolicy) | tracing email delivery against the deployed topology | queued for the worker (no secret stored, link built at send time); verified end to end through STARTTLS on the stack |
| 18 | **SSO could never work in the reference deployments**: the API calls the IdP but has no egress | same topology review | `docker-compose.sso.yml` / chart egress rule when `OIDC_ISSUER` is set; verified with an IdP container through the stack (fails closed with `idp_unreachable` without it) |
| 19 | SSO-return and reset links did nothing in an already-open console tab (fragment change, no reload) | browser walkthrough | `hashchange` routing; verified in the browser |
| 20 | ingest spent 12 SQL statements per hit (3 re-reading committed rows) | profiling the deployed stack under load | 7 statements; +26–47% throughput; query-budget test |
| 21 | **at 10M events the dashboard failed**: statistics 7–43 s, analytics > 120 s (limits 5 s / 15 s) | 10M-event benchmark | trigger-maintained totals, database-set `tenant_id` + index, bounded three-stage analytics, 503 on timeout |
| 22 | the migration that added `tenant_id` blocked decoy-hit inserts: per-batch `DISABLE TRIGGER` takes a table lock (2 of 2,064 inserts failed on a 5 s timeout, p99 1.8 s) | running the migration on 10M events under insert load | online migration: one narrow, verified fill exception in the immutability trigger, primary-key batches, concurrent index, `NOT VALID` foreign key; same test: 0 of 42,384 failed, p99 6.6 ms |
| 23 | **Helm upgrades with migrations dropped requests** (11 of 6,993 got HTTP 502): readiness demanded the exact migration head, so old pods went unready the moment the pre-upgrade migration finished | rechecking the final build on Kubernetes under continuous load | readiness refuses only a database *behind* the code; same upgrade replayed: 0 of 5,069 failed |

### Verification (2026-11-17)

| Check | Result |
|---|---|
| Test suite, real PostgreSQL + MinIO + Redis, none skipped | **725 passed, 0 failed**, three consecutive runs |
| Migrations upgrade → downgrade → upgrade + `alembic check` | passed, no drift (head `20261117_05`) |
| `pip-audit --strict` (incl. new `cryptography` dependency) | no known vulnerabilities |
| Compose stack, 2 replicas, upgraded in place from the MFA build | **56/56** |
| Compose stack with Redis stopped | 49/51 (only the two shared-state checks; detection unaffected), 51/51 after recovery |
| Restore drill on the upgraded stack | **PASSED** (8 tenant chains + audit chain, 8 triggers, least privilege) |
| Kubernetes (k3s v1.31, Pod Security `restricted`) via Helm | **56/56** after install, after a backend upgrade and after the edge upgrade |
| NetworkPolicy enforcement probes | backend unreachable except from the edge; no internet egress from the API |
| Zero-downtime rolling restart under load | 0 failed requests in two runs |
| `helm upgrade` with database migrations under load | 0 of 4,049 requests failed; verifier 56/56 afterwards |
| Ingest capacity (2 replicas × 1 CPU, laptop) | 446 / 405 / 396 hits/s at concurrency 8 / 32 / 64 (was 353 / 276 / 277 before cutting a hit from 12 to 7 SQL statements); 68,884 events = 68,884 chain links afterwards, chain verifies |
| 10M-event benchmark | first run: statistics 7–43 s, top attackers / summary > 120 s (timeout), export walk up to 40 s. After the fixes: every listing ≤ 2.5 ms, statistics ≤ 2.6 ms, analytics ≤ 1.5 s, export walk ≤ 0.71 s |
| Online `tenant_id` migration on 10M events, insert every ~10 ms | 0 of 42,384 inserts failed, p50 0.6 ms, p99 6.6 ms, max 626 ms; no NULL `tenant_id`; counters = 10,044,446 = event count |
| Daily-totals migration (20261118_03) on 10M events, insert every ~10 ms | 5.2 s; 0 of 785 inserts failed (p99 15 ms); totals = 10,045,231 = events, no mismatched day/severity/tenant bucket |
| Activity chart query at 10M events | 4.0 s → 21 ms (system admin), 0.8 s → 3.5 ms (5M-event tenant) |
| Kubernetes upgrade 1.0.6 → 1.0.7 with a migration, continuous HTTPS load (after the readiness fix) | **0 of 6,431** requests failed (the same kind of upgrade lost 11 of 6,993 before); verifier **59/59** |
| Kubernetes rolling restart only | 0 of 3,895 |
| Compose, rebuilt from the console-redesign branch and migrated in place | verifier **58/58**; restore drill PASSED (23 tenant chains, audit chain, daily totals consistent, 13 triggers, least privilege) |
| Console | redesigned (see `console-design.md`); light, dark and phone layouts checked in a browser; contract tests guard ids, CSP compatibility, HTML sinks, token handling and theme tokens; text contrast ≥ 4.5:1 |
| Test suite after the last code change (console redesign branch) | **772 passed, 0 failed, 0 skipped** (real PostgreSQL, MinIO, Redis) |
| Kubernetes upgrade 1.0.7 → 1.0.8 (runtime image without pip, admin console pages) under continuous HTTPS load | **0 of 6,728** requests failed; verifier **62/62** (adds: event by id, another tenant's event id → 404, unsafe tenant slug refused) |
| Compose rebuilt with the pip-less image | verifier **60/60**; restore drill PASSED (every tenant chain and the audit chain verify after restore; least privilege) |
| Image vulnerability gate (Trivy, fixable HIGH/CRITICAL) | backend and edge pass; Python package findings 6 → 0 after removing pip; gate proven to fail on a known-vulnerable image (61 findings) |
| CI test gate | old step reproduced passing with failing and with skipped tests (HONEY-060); fixed step fails on both, passes on success |
| Test suite after the last code change | **780 passed, 0 failed, 0 skipped** (real PostgreSQL, MinIO, Redis) |
| Quick start from a fresh clone (`scripts/quickstart_env.sh`) | stack healthy, first admin, verifier 61/61 then 62/62; documented test command 715 passed / 68 skipped without services, as the README says |
| Store Redis 7.4.7 → Valkey 9.0.7 (licence, CVEs) | shared-state tests 37/37; Compose 61/61 with 2 replicas; Kubernetes swap under load 0 of 6,136 failed, verifier 62/62 |
| Database image `honeyshield-db` (16.16, non-root, no capabilities) | in-place upgrade from 16.10 on the existing volume: verifier 61/61, 26 tenant chains + audit chain verify, restore drill PASSED; fresh volume: verifier 61/61 |
| Image gate over every deployed image | backend, edge, database, Valkey: 0 fixable HIGH/CRITICAL |
| Test suite after the last code change (Valkey) | **786 passed, 0 failed, 0 skipped** (real PostgreSQL, MinIO, Valkey) |
| Helm chart 1.1.0 (registry defaults, pull secret on every workload) on k3s under load | **0 of 6,030** requests failed; verifier **62/62**; all 7 pods ready with the pull secret |
| Decoy hits during outages (Compose): every API replica stopped, then the database stopped (HONEY-067) | **50 of 50** hits recorded after recovery, **0 duplicates**, original edge times, evidence chains verify; visitors got normal responses (pixel byte-identical) |
| Decoy hits during an outage (Kubernetes, API scaled to 0) | **20 of 20** recovered by the edge sidecars, 0 duplicates; verifier **61/61** on the upgraded cluster |
| Ingest load through the TLS edge (2 API replicas x 1 CPU, laptop, rate limiting off) | 382 / 353 / 312 hits/s at 8 / 16 / 32 connections (p99 81 / 198 / 509 ms); **31,442 responses = 31,442 events**, 31,542 chain links for 31,542 events, chain verifies |
| Installer from a registry, empty folder | healthy in under a minute, verifier **61/61**; upgrade 1.2.0 to 1.2.1 kept every record; works without a terminal |
| Reference hook client during a HoneyShield outage | reports kept and retried with the same idempotency key until accepted (no longer dropped after 3 tries); optional spool survives a restart |
| Images (Docker Scout) | backend 0 critical / 0 high; edge 0 critical / 1 high (musl, not yet in Alpine) |
| Browser walkthroughs | reset flow, admin reset link, API keys, CSV export, test alerts; no script errors |
| Concurrent ingest through both replicas (16 threads, 40 s, above the edge budget) | 976 responses (129 × 204, 847 × 429). Every hit that reached the app was recorded exactly once: 833 events = 129 accepted + 704 app-throttled (recorded by design) = the sum of both replicas' `valid_recorded` counters = 833 chain links; chain verifies |
| Alert delivery through the deployed worker | HTTPS receiver on a private network: test alert + real decoy alert DELIVERED on the first attempt, HMAC signatures verified by the receiver, no token value in the payload. TLS syslog receiver: RFC 5424 + CEF delivered first attempt, token masked |
| SSO through the deployed stack | standalone OIDC provider (TLS, PKCE): edge → IdP → callback → one-time code → session; MFA from `amr`; code replay 401 |
| Self-service password reset, production mode | request via edge → worker → STARTTLS mail server → link to the public control host → reset 204 → new password 200, old 401 |
| Event pagination | `id`-cursor skipped events whose trigger time is out of id order (2 of 8 returned; CSV export 2 of 6). Fixed with a `(triggered_at, id)` keyset and composite index: 0.28 ms at row 250,000 of 500,000 |
