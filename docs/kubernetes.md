# Kubernetes (Helm)

Chart: `deploy/helm/honeyshield`. It runs:
* the API (2+ replicas, Redis-shared state);
* the alert worker and the evidence checkpointer (PVC, plus S3 Object Lock when configured);
* the nginx edge with the console (`docker/Dockerfile.edge`, the same two-vhost configuration as
  Compose);
* an ephemeral Valkey (Redis-protocol shared state; BSD-licensed, unlike Redis 7.4+);
* a migration hook Job and a retention CronJob.

## Verified (2026-11-17, k3s v1.31.4 in Docker, Pod Security `restricted` enforced on the namespace)

* `helm install --wait` and a rolling `helm upgrade` to a new image (zero downtime: maxUnavailable 0, PDBs).
* `scripts/verify_deployment.py` through the edge LoadBalancer: **51/51** after install, with 2
  replicas and MFA enrolment, and **51/51** again after the upgrade, using the TOTP challenge.
* Every pod is admitted under `restricted`, and a privileged pod is refused in the namespace.
* NetworkPolicies enforced:
  * a probe pod reaches the edge but not the backend or Redis;
  * the backend reaches PostgreSQL but not the internet;
  * Prometheus in the allowed namespace scrapes each replica (404 without the token), and other
    namespaces are blocked.
* `python -m app.workers.evidence verify` inside the cluster: both tenant chains and the audit chain OK.
* **Zero-downtime rollouts.** HTTPS requests hit the edge continuously, every 20 ms, while edge
  and backend were restarted together:

  | Run | Failed requests |
  |---|---|
  | before the fix | 4 of 1,759 (TLS EOF / timeout) |
  | with the fix | 0 of 2,554 |
  | with the fix, again | 0 of 2,524 |

  The fix is a `preStop` delay, so endpoint removal reaches the load balancer before the process
  stops, followed by a graceful stop (nginx SIGQUIT, uvicorn finishing in-flight requests). The
  edge readiness probe checks the listeners.
* **Upgrade with database migrations under traffic.** `helm upgrade` to a new backend image with
  two migrations (a new index and a new table): **0 of 4,049** continuous requests failed, the
  database reached the new head, and the verifier passed 56/56 afterwards.
* **Regression found and fixed (2026-11-17).** A later upgrade that changed both images and ran
  two migrations lost **11 of 6,993** requests (HTTP 502). Readiness required the database to be
  exactly at the pod's own head, so the old pods turned unready as soon as the pre-upgrade
  migration finished; for a moment no backend was ready. Readiness now refuses only a database
  that is *behind* the code (see the migration runbook). Replaying the same upgrade (previous
  release on revision `20261117_07` to the current one, both migrations running mid-upgrade):
  **0 of 5,069** requests failed. A rolling restart alone: **0 of 3,895**.
* CI runs `helm lint`, renders the chart, validates it with `kubeconform -strict` (Kubernetes 1.31)
  and checks that retention without S3 is refused.

## Install

1. **PostgreSQL** (managed is recommended: RDS, Cloud SQL, Azure Database, with PITR). Create the
   schema-owner and runtime roles with the SQL in `docker/init-db.sh` (`docs/database-roles.md`).
2. **Secrets.** Never put them in values:
   ```bash
   kubectl create namespace honeyshield
   kubectl label namespace honeyshield pod-security.kubernetes.io/enforce=restricted
   kubectl -n honeyshield create secret generic honeyshield-secrets \
     --from-literal=JWT_SECRET_KEY=$(openssl rand -hex 32) \
     --from-literal=INTEGRATION_SIGNING_KEY=$(openssl rand -hex 32) \
     --from-literal=MFA_SECRET_KEY=$(openssl rand -hex 32) \
     --from-literal=POSTGRES_PASSWORD='<runtime role password>' \
     --from-literal=POSTGRES_MIGRATION_PASSWORD='<owner role password>' \
     --from-literal=REDIS_PASSWORD=$(openssl rand -hex 32) \
     --from-literal=METRICS_TOKEN=$(openssl rand -hex 24)
   # optional keys: SMTP_PASSWORD, OIDC_CLIENT_SECRET, EVIDENCE_S3_SECRET_ACCESS_KEY,
   #   BACKUP_S3_SECRET_ACCESS_KEY, WATCHDOG_NOTIFY_WEBHOOK_URL, WATCHDOG_HEARTBEAT_URL
   ```
3. **TLS.** A `kubernetes.io/tls` Secret named `honeyshield-tls` covering both hosts, for example
   from cert-manager.
4. **Images.** Each version tag publishes `honeyshield-backend`, `honeyshield-edge` and
   `honeyshield-db` to `ghcr.io/karthikbalaji1111-wq/` for amd64 and arm64
   (by the release workflow); the chart's defaults point there at its `appVersion`. Each image
   carries an SBOM and build provenance: `docker buildx imagetools inspect
   ghcr.io/karthikbalaji1111-wq/honeyshield-backend:1.1.0 --format '{{json .Provenance}}'`.
   If the packages are private, give the cluster a read-only token:
   ```bash
   kubectl -n honeyshield create secret docker-registry ghcr-pull --docker-server=ghcr.io \
     --docker-username=<account> --docker-password=<token with read:packages>
   # then: --set 'imagePullSecrets[0].name=ghcr-pull'   (every workload uses it; CI checks this)
   ```
   Your own registry works too: build the Dockerfiles and set `image.*.repository/tag`.
5. **Install:**
   ```bash
   helm install hs deploy/helm/honeyshield -n honeyshield \
     --set hosts.control=app.example.com --set hosts.ingest=ingest.example.com \
     --set postgresql.host=<db host> --set networkPolicy.databaseCidr=<db CIDR> \
     --set trustedProxies=<pod CIDR> --wait
   kubectl -n honeyshield exec -it deploy/hs-backend -- python -m app.bootstrap --email you@example.com
   ```
6. Point DNS for both hosts at the `hs-edge` LoadBalancer. It uses `externalTrafficPolicy: Local`,
   so client IPs (evidence) are preserved. Run the verifier.

Non-secret settings (SMTP host, OIDC issuer, MFA roles and so on) go in `backend.extraEnv`.
Setting `backend.extraEnv.OIDC_ISSUER` also opens HTTPS egress for the API, which SSO needs.
Retention needs `s3.bucket`, because in Kubernetes archives go only to S3 Object Lock; the chart
refuses otherwise.

## Watchdog, backups, decoy paths and the allowlist (1.3.0)

* **Watchdog** (on by default): a Deployment that sends a self-test hit through the `hs-edge`
  Service with the ingest host name every 5 minutes and checks it reached the database
  (docs/watchdog.md). Put the notice and heartbeat URLs in the Secret, since they usually contain
  tokens: keys `WATCHDOG_NOTIFY_WEBHOOK_URL`, `WATCHDOG_HEARTBEAT_URL`, `WATCHDOG_HEARTBEAT_FAIL_URL`.
  With a certificate from a private CA set `watchdog.probeVerifyTls=false`; the certificate check
  then warns. Verified on k3s under the chart's NetworkPolicies: the self-test passes in under 200 ms.
* **Backups** (`backup.enabled=true`): a CronJob that dumps, encrypts to `backup.ageRecipients` and
  uploads to `backup.bucket`; nothing is kept in the cluster. Add `BACKUP_S3_SECRET_ACCESS_KEY` to the
  Secret. A managed database's point-in-time recovery remains the first line; this is the copy you
  hold the key to (docs/backup-and-restore.md).
* **Decoy paths**: `decoyPaths.link/pixel/collect/legacy` reach both the backend and the edge
  (docs/decoy-paths.md).
* **Allowlist**: `controlAllowCidrs` limits the operator host at the edge and in the backend. It
  depends on the real client address, which the edge Service's `externalTrafficPolicy: Local`
  preserves.

Upgrading from 1.2.x with `--reuse-values` would leave the new values undefined; use
`--reset-then-reuse-values` (Helm 3.14+):

```bash
helm upgrade hs deploy/helm/honeyshield -n honeyshield --reset-then-reuse-values --wait
```

## Decoy hits during an outage

Each edge pod runs nginx and an `ingest-replay` sidecar sharing an `emptyDir` spool. If the backend
Service has no ready pod, or the database is down, nginx still answers decoy hits and spools them;
the sidecar replays them to the backend Service once it is ready. Verified on k3s with the API scaled
to zero: 20 of 20 hits recovered, none twice. The spool survives container restarts but not pod
deletion, so during an outage let the edge pods be (no rollout, no drain) until the sidecar logs show
the spool has drained.

## Security posture of the chart

* All pods run as non-root with a read-only root filesystem, all capabilities dropped, no
  privilege escalation, seccomp `RuntimeDefault` and no service-account token. The edge listens
  on 8080/8443.
* The edge image is nginx 1.30 stable with OS updates applied, unused modules (XSLT, njs, image
  filter, GeoIP) removed and no debug modules. Docker Scout: 0 critical, 1 high (musl, waiting on
  Alpine's repository; the next rebuild picks it up). The 1.28 base it replaced had 3 critical and
  4 high after updates. The backend image: 0 critical, 0 high.
* NetworkPolicy:
  * default deny for every HoneyShield pod;
  * only the edge reaches the API, and it is the only trusted `X-Forwarded-For` writer;
  * the API reaches only PostgreSQL and Redis;
  * the worker and checkpointer get internet egress on delivery and S3 ports, with link-local
    (metadata) excluded and the application SSRF guard on top;
  * Redis accepts only HoneyShield components.
* Probes are `exec`, so they work under every NetworkPolicy engine.
* Migrations and grants run once per install/upgrade as the schema owner (hook Job); the
  runtime pods use the least-privileged role, checked at start-up.

## Monitoring

`deploy/monitoring/prometheus-rules.yml` holds 10 alert rules (availability, database, 5xx rate,
Redis, decoy floods, hook auth failures, alert backlog, dead deliveries, live-feed drops, DB
pool). They come with `promtool` unit tests (`prometheus-rules.test.yml`), which run in CI.
Scrape every backend pod's `:8000/metrics` with `Authorization: Bearer $METRICS_TOKEN` and set
`metrics.prometheusNamespace`. The API accepts `/metrics` addressed to a pod IP and never on the
ingest host.
