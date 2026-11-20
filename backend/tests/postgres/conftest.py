"""Real-PostgreSQL integration harness.

Runs only when HS_TEST_PG_ADMIN_URL points at a DISPOSABLE PostgreSQL server, e.g.

    HS_TEST_PG_ADMIN_URL=postgresql+psycopg2://postgres:pw@127.0.0.1:5432/postgres

For each test session it creates a uniquely named database plus an owner role and a
runtime role, runs every Alembic migration as the owner, applies the runtime grant policy
(app.db.privileges), and drops all three afterwards. Nothing pre-existing is touched.

SQLite cannot establish any of what these tests check (triggers, grants, ownership,
constraint enforcement, concurrency), so they are reported as SKIPPED - not passed - when
no server is configured.
"""
from __future__ import annotations

import os
import secrets
import subprocess
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, Engine, make_url
from sqlalchemy.orm import Session

BACKEND = Path(__file__).resolve().parents[2]
ADMIN_URL = os.getenv("HS_TEST_PG_ADMIN_URL")

pytestmark = pytest.mark.skipif(not ADMIN_URL, reason="HS_TEST_PG_ADMIN_URL not set: real-PostgreSQL tests not run")


@dataclass
class PgEnv:
    db: str
    owner: str
    owner_url: str
    app: str
    app_url: str
    admin_url: str

    def engine(self, who: str) -> Engine:
        return create_engine({"owner": self.owner_url, "app": self.app_url}[who], future=True)


def _url(base: URL, user: str, password: str, db: str) -> str:
    return base.set(username=user, password=password, database=db).render_as_string(hide_password=False)


def run_backend(args: list[str], env_extra: dict[str, str]) -> subprocess.CompletedProcess:
    env = {**os.environ, **env_extra}
    env.setdefault("JWT_SECRET_KEY", "pg-integration-secret-key-0123456789abcdef")
    env["APP_ENV"] = "test"
    return subprocess.run([sys.executable, *args], cwd=BACKEND, env=env, capture_output=True, text=True, timeout=300)


@pytest.fixture(scope="session")
def pg() -> Iterator[PgEnv]:
    if not ADMIN_URL:
        pytest.skip("HS_TEST_PG_ADMIN_URL not set")
    base = make_url(ADMIN_URL)
    suffix = secrets.token_hex(4)
    db, owner, app = f"hs_it_{suffix}", f"hs_it_owner_{suffix}", f"hs_it_app_{suffix}"
    owner_pw, app_pw = secrets.token_urlsafe(18), secrets.token_urlsafe(18)

    admin = create_engine(ADMIN_URL, isolation_level="AUTOCOMMIT")
    with admin.connect() as c:
        c.execute(text(f'CREATE ROLE "{owner}" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD :p'), {"p": owner_pw})
        c.execute(text(f'CREATE ROLE "{app}" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD :p'), {"p": app_pw})
        c.execute(text(f'CREATE DATABASE "{db}" OWNER "{owner}"'))
        c.execute(text(f'REVOKE ALL ON DATABASE "{db}" FROM PUBLIC'))
    dbadmin = create_engine(_url(base, base.username, base.password, db), isolation_level="AUTOCOMMIT")
    with dbadmin.connect() as c:
        c.execute(text(f'ALTER SCHEMA public OWNER TO "{owner}"'))
        c.execute(text("REVOKE ALL ON SCHEMA public FROM PUBLIC"))
    dbadmin.dispose()

    env = PgEnv(db=db, owner=owner, owner_url=_url(base, owner, owner_pw, db), app=app,
                app_url=_url(base, app, app_pw, db), admin_url=ADMIN_URL)
    try:
        mig = run_backend(["-m", "alembic", "upgrade", "head"], {"MIGRATION_DATABASE_URL": env.owner_url})
        assert mig.returncode == 0, mig.stderr[-3000:]
        grant = run_backend(["-m", "app.db.privileges", "grant", "--role", app],
                            {"MIGRATION_DATABASE_URL": env.owner_url})
        assert grant.returncode == 0, grant.stderr[-3000:]
        yield env
    finally:
        with admin.connect() as c:
            c.execute(text("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = :d"), {"d": db})
            c.execute(text(f'DROP DATABASE IF EXISTS "{db}"'))
            c.execute(text(f'DROP ROLE IF EXISTS "{app}"'))
            c.execute(text(f'DROP ROLE IF EXISTS "{owner}"'))
        admin.dispose()


@pytest.fixture(scope="session")
def app_engine(pg: PgEnv) -> Iterator[Engine]:
    eng = pg.engine("app")
    yield eng
    eng.dispose()


@pytest.fixture(scope="session")
def owner_engine(pg: PgEnv) -> Iterator[Engine]:
    eng = pg.engine("owner")
    yield eng
    eng.dispose()


@pytest.fixture()
def app_session(app_engine: Engine) -> Iterator[Session]:
    s = Session(bind=app_engine, autoflush=True, expire_on_commit=False)
    yield s
    s.rollback()
    s.close()
