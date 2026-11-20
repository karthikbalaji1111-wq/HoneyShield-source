# Database roles and privileges (HONEY-002)

| Role | Created by | Used by | Can |
|---|---|---|---|
| bootstrap superuser (`postgres`) | postgres image | `docker/init-db.sh` once; backups/restores | everything |
| `honeyshield_owner` | init-db.sh | `migrate` service only | owns schema and every table; DDL; disables triggers if it wants to (trusted) |
| `honeyshield_app` | init-db.sh | API, worker, checkpointer | exactly the grants below; owns nothing; NOINHERIT; no CREATE on schema/database |

## Runtime grant policy (`backend/app/db/privileges.py`)

| Class | Tables | Runtime privileges |
|---|---|---|
| append-only evidence | `detection_events`, `audit_logs`, `evidence_chain` | SELECT, INSERT |
| mutable state | `tenants`, `projects`, `users`, `honey_tokens`, `application_configs`, `integration_credentials`, `alert_destinations`, `outbox_events`, `evidence_chain_heads` | SELECT, INSERT, UPDATE, DELETE |
| read-only | `alembic_version` | SELECT |
| sequences | all | USAGE, SELECT |

Every table must be classified; `grant` refuses to run if it finds an unclassified table, and an
unclassified table gives the runtime no access (fail closed, visible). The grant step revokes
everything first, so re-running it always converges on exactly this policy.

## Defence in depth for evidence

1. Grants: runtime has no UPDATE/DELETE/TRUNCATE on evidence.
2. Ownership: runtime is not the owner, so it cannot `ALTER TABLE … DISABLE TRIGGER`, drop or
   replace the trigger function.
3. Triggers: `prevent_forensic_modification()` rejects UPDATE/DELETE/TRUNCATE for every role,
   including the owner, until the owner deliberately drops them.
4. Start-up guard: the API refuses to run if its role is superuser, owns tables, can CREATE in the
   schema, has UPDATE/DELETE/TRUNCATE/TRIGGER/REFERENCES on evidence, or is a member of the owner.
5. Detection: the hash chain + external checkpoints detect anything a superuser does anyway.

## Verified (real PostgreSQL, connections authenticated as each role)

`tests/postgres/test_runtime_privileges.py` and the live deployment: runtime UPDATE/DELETE/
TRUNCATE of evidence → `permission denied`; DISABLE TRIGGER/DROP/ALTER → `must be owner`;
CREATE TABLE → `permission denied for schema public`; `SET session_replication_role` → denied;
owner UPDATE → rejected by trigger; start-up guard accepts runtime and refuses the owner.

## Operating

```bash
docker compose run --rm migrate python -m app.db.privileges grant   # after any restore
docker compose exec backend python -m app.db.privileges check        # runtime self-check
```
