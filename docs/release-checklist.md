# Release checklist

Mark each item with evidence (command output, link). An unchecked blocker means no release.

## Build and test
- [ ] CI green on the release commit (PostgreSQL tests ran, not skipped; `pip-audit --strict` clean)
- [ ] Single Alembic head; upgrade → downgrade → upgrade passed in CI
- [ ] `deploy/helm/honeyshield/Chart.yaml` `version`/`appVersion` and `values.yaml` image tags set to the release
- [ ] Tag pushed (`git tag vX.Y.Z && git push origin vX.Y.Z`); the *Release images* workflow published backend,
      edge and database images (amd64 + arm64) after its vulnerability gate, with SBOM and provenance
- [ ] The *Publish source* job copied the release to the public repository `HoneyShield-source` and
      tagged `vX.Y.Z` there (without the secret `SOURCE_REPO_DEPLOY_KEY` it only warns: run
      `scripts/publish_source_repo.sh` by hand, as its header shows);
      `curl -fsSI https://raw.githubusercontent.com/<owner>/HoneyShield-source/vX.Y.Z/deploy/install/install.sh`
- [ ] Each image's provenance and SBOM are present: `docker buildx imagetools inspect ghcr.io/<owner>/honeyshield-backend:X.Y.Z --format '{{json .Provenance}}'`
      (and `gh attestation verify oci://… --owner <owner>` when the repository is public)
- [ ] Backend runs as UID 10001, database as 999; every deployed image (including Valkey) passes the CI gate
- [ ] CI: Helm chart lint + kubeconform passed; Prometheus rule tests passed

## Configuration (blockers)
- [ ] Env file outside the repo, mode 600, every secret independently generated
- [ ] `APP_ENV=production`; `ENFORCE_DB_LEAST_PRIVILEGE=true`
- [ ] Real DNS for control and ingest hosts; real CA-issued certificates covering both
- [ ] `NGINX_BIND_ADDRESS=0.0.0.0`, ports 80/443; firewall allows only 80/443 inbound
- [ ] `METRICS_TOKEN` set and Prometheus scraping

## Deployment verification (blockers)
- [ ] `docker compose config -q` passes; `migrate` exits 0; backend healthy
- [ ] `scripts/verify_deployment.py --expect-replicas <n>` against the public endpoint: all checks PASS (62 with a second tenant present)
- [ ] `python -m app.db.privileges check` in the backend: passes
- [ ] `scripts/restore_drill.sh` passed on this release's schema
- [ ] Each production alert destination received a test alert (`Send test` / `POST …/test`)
- [ ] Evidence checkpoints are shipping to the S3 Object Lock bucket (`verify --checkpoints s3` passes)
- [ ] `REDIS_PASSWORD` set; `honeyshield_shared_state_up 1` on every replica
- [ ] Kubernetes only: namespace enforces Pod Security `restricted`; NetworkPolicies enabled; a rolling restart under load drops no requests

## Operations
- [ ] Alerts from monitoring-and-slos.md configured and test-fired
- [ ] Backups scheduled daily, encrypted, off-host; drill scheduled monthly
- [ ] First SYSTEM_ADMIN created; a second SYSTEM_ADMIN created (break-glass)
- [ ] If SSO is used: sign-in tested with the IdP; `OIDC_MFA` chosen deliberately (docs/sso.md)
- [ ] Retention period decided (`EVENT_RETENTION_DAYS` / `AUDIT_RETENTION_DAYS`, archives to S3)
- [ ] Every SYSTEM_ADMIN / TENANT_ADMIN enrolled in MFA (`GET /api/v1/users` shows `mfa_enabled`); recovery codes stored
- [ ] `MFA_SECRET_KEY` generated independently and backed up with the other secrets
- [ ] Incident-response contacts and runbook reviewed
