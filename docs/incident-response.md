# Incident response

## A decoy fired

1. Open the event (console → Events). Note **source**, severity, decoy type, IP, path, UA, time.
2. Is it plausible noise? (LINK + crawler UA; PIXEL + mail-proxy IP; FORM_FIELD + autofill) — see
   honeytoken-deployment-guide.md. Otherwise treat as an intrusion indicator.
3. Pivot: `GET /api/v1/threats/ip/{ip}` and `/timeline/{ip}` for everything that IP touched.
4. Contain per your IR plan (block IP, rotate the *real* credentials near the decoy's location,
   isolate the host/repo where the decoy was planted). Do **not** revoke the decoy first: it keeps
   recording; rotate it after containment.
5. Preserve: `python -m app.workers.evidence export --tenant <id> --after <seq> --out case.jsonl`
   and the latest checkpoint; both re-verify offline.

## Evidence verification fails

1. Stop writes is *not* required; do not modify the database.
2. Run `verify --checkpoints` to see whether the chain is internally broken (event_modified,
   broken_link, sequence_gap, unchained_after_chain_start) or rewritten (checkpoint_mismatch).
3. Snapshot the database volume and the checkpoint store; restrict DB superuser access; review
   PostgreSQL logs and `audit_logs` around the failing sequence numbers.
4. Restore the last good backup into a separate database (`scripts/restore_drill.sh`) and compare.

## Suspected credential compromise

* Operator account: deactivate (`POST /api/v1/users/{id}/deactivate`) — tokens revoked and live
  streams closed within 30 s; review `AUTH_*` audit events.
* Integration secret: revoke the credential; create a new one; reports with the old one get 401.
* Webhook secret: disable the destination and create a new one.
* `JWT_SECRET_KEY` / `INTEGRATION_SIGNING_KEY`: rotate in the env file and restart; re-issue all
  integration and webhook secrets after rotating the latter.
* Database passwords: `ALTER ROLE` as superuser, update env, restart.

## Alerts not arriving

Console → Alerts → deliveries. DEAD with `HTTP 4xx` = receiver rejects (fix receiver, then the
events remain visible in HoneyShield); `unsafe destination` = URL resolves to a private address;
PENDING with growing attempts = receiver down (retries up to 8 times over ~2 h).
