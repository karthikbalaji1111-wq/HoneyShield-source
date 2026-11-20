# Operations runbook

`E="--env-file /etc/honeyshield/prod.env"`; all commands from the repository root.

| Task | Command |
|---|---|
| Status | `docker compose $E ps` (migrate Exited 0; others running/healthy) |
| Logs | `docker compose $E logs -f --tail=200 backend worker nginx` |
| Readiness | `curl -fsS https://app.example.com/api/v1/ready` |
| Upgrade | backup + drill → `git pull` → `docker compose $E build` → `docker compose $E up -d` → `scripts/verify_deployment.py` |
| Re-apply DB grants | `docker compose $E run --rm migrate python -m app.db.privileges grant` |
| Runtime role check | `docker compose $E exec backend python -m app.db.privileges check` |
| First admin | `docker compose $E exec backend python -m app.bootstrap --email …` |
| Evidence verify | `docker compose $E run --rm checkpointer python -m app.workers.evidence verify --checkpoints /evidence` |
| Backup + restore proof | `COMPOSE="docker compose $E" BACKUP_DIR=/var/backups/honeyshield scripts/restore_drill.sh --cleanup` |
| Scale alert workers | `docker compose $E up -d --scale worker=3` (API must stay at 1) |
| Retry dead alerts | fix the receiver, then as the owner: `UPDATE outbox_events SET status='PENDING', attempts=0, next_attempt_at=now() WHERE status='DEAD' AND destination_id=…` |
| Rotate TLS | replace files in `proxy/certs`, `docker compose $E exec nginx nginx -s reload` |
| Lost authenticator | another admin: console → Users → Reset MFA (reason required), or `POST /api/v1/users/{id}/mfa/reset`; the user re-enrols at next sign-in |
| MFA lock-out of the only SYSTEM_ADMIN | prevent it: keep a second SYSTEM_ADMIN (break-glass) and the recovery codes. Last resort, as the schema owner: `UPDATE users SET mfa_enabled=false, mfa_nonce=NULL, mfa_last_step=NULL, mfa_recovery_hashes=NULL, mfa_enabled_at=NULL, token_version=token_version+1 WHERE lower(email)=lower('…')` — the user re-enrols at next sign-in; record it as a security incident |
| Deactivate tenant | console → Tenants → Deactivate (type the slug to confirm), or `DELETE /api/v1/tenants/{slug}` (soft; decoys stop being reportable by hooks, public hits are still recorded) |
| Add an operator | console → Users → Add user: a one-time set-up link (30 min) instead of a password; admins enrol MFA at first sign-in |
| Change role / deactivate a user | console → Users → Make admin / Make read-only / Deactivate (sessions end; you cannot deactivate yourself or the last system admin) |

## Outages: decoy hits are kept at the edge (HONEY-067)

While the database or every API replica is down, the edge still answers decoy hits normally and
appends each one to `/var/spool/honeyshield/ingest.jsonl` (Compose volume `ingest_spool`; on
Kubernetes an `emptyDir` in each edge pod). When the backend is back, the `ingest-replay` worker sends
them, and they appear under Events with the time the edge saw them; the event panel marks them as
recovered and the audit log records `DETECTION_EVENTS_RECOVERED`. Nothing needs doing by hand.

| Situation | What to do |
|---|---|
| Alert `HoneyShieldHitsRecoveredAfterOutage` | Review the recovered events and the cause of the outage |
| Check what is still waiting | `docker compose $E exec nginx wc -l /var/spool/honeyshield/ingest.jsonl` and `docker compose $E logs ingest-replay` |
| Kubernetes, during an outage | Do not delete edge pods until their spool has drained (`kubectl logs <edge pod> -c ingest-replay`); a deleted pod loses its own spool |
| Spool size | About 1 KB per hit; the Kubernetes `emptyDir` is capped by `edge.spoolSizeLimit` (2Gi) |

## Behaviour of inactive objects (HONEY-021)

| Object inactive | Public ingestion | Customer hook | Operators |
|---|---|---|---|
| Token (revoked/rotated) | still recorded (reuse of a retired decoy is evidence) | still recorded | visible as revoked |
| Project / tenant | still recorded (evidence is never discarded) | refused (401) | tenant users cannot log in |
| User | – | – | login refused, tokens and streams revoked |

## Data retention (HONEY-011)

Evidence is retained indefinitely: no API, job or role can delete it. Retention by deletion is
deliberately not implemented; the designed approach (monthly partitions, audited detach-archive-
drop) is in architecture-target.md. Plan storage at ~280 bytes per event (1M events ≈ 277 MB with
indexes, measured).
