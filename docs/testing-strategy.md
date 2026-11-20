# Testing strategy

| Layer | Where | Backend | What it can prove |
|---|---|---|---|
| Unit / API | `backend/tests/**` (excluding `postgres/`) | SQLite in-memory, FastAPI TestClient | behaviour, authorization, validation, tenancy logic, hook/alert/chain logic |
| PostgreSQL integration | `backend/tests/postgres/` | real PostgreSQL; per-run database + owner + runtime roles; every migration applied; grants applied | triggers, grants, ownership, CHECK/unique constraints, concurrency (SKIP LOCKED, idempotency race, chain ordering), API as the runtime role |
| Deployment E2E | `scripts/verify_deployment.py` | the real compose stack through nginx/TLS | host separation, TLS, edge limits, all decoy types end to end, hook, masking, chain, metrics |
| Recovery | `scripts/restore_drill.sh` | the real stack | restorability, grants, triggers, chain after restore |
| Performance | ad-hoc benchmark (see production-readiness.md) | PostgreSQL, 1M events | query latency of listing and analytics |

SQLite results never count as evidence for PostgreSQL behaviour. PostgreSQL tests are **skipped**
(not passed) without `HS_TEST_PG_ADMIN_URL`; CI fails if they skip.

## Running

```bash
cd backend
export JWT_SECRET_KEY=test-secret-key-for-local-pytest-only-0123456789abcdef APP_ENV=test
pytest -q                                            # SQLite + (skipped) PostgreSQL tests
HS_TEST_PG_ADMIN_URL=postgresql+psycopg2://postgres:pw@127.0.0.1:5432/postgres pytest -q
```
`HS_TEST_PG_ADMIN_URL` must point at a **disposable** server: the harness creates and drops its
own database and two roles (`hs_it_*`) and touches nothing else.

## Rules followed

* Tests assert behaviour through the real HTTP path where possible (artifacts are followed as
  delivered, the hook is exercised with the shipped reference client).
* Assertions were never weakened to pass; where a contract changed deliberately (e.g. no
  per-token 429, server-generated values, stricter `Vary`), the test was rewritten to assert the
  new security property and the reason is in the test docstring.
* Tamper tests modify data with Core SQL to prove detection, not just prevention.
