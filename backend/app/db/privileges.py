"""Runtime database privilege policy (HONEY-002).

HoneyShield uses three PostgreSQL identities:

* bootstrap superuser - creates the roles and the database once (docker/init-db.sh).
  Never used by the application.
* migration owner      - owns the schema and every table; runs Alembic. Not used to
  serve requests.
* runtime role         - what the API process connects as. It owns nothing, cannot run
  DDL, cannot disable triggers, and has only INSERT/SELECT on forensic tables.

Every table must be classified here. ``grant_statements`` refuses to run when it finds
an unclassified table, so a new table gets no runtime access until someone decides what
the runtime may do with it (fail closed, and visible: the app errors on first use).

Run after every ``alembic upgrade`` as the migration owner::

    python -m app.db.privileges grant --role honeyshield_app
"""
from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection

# Append-only evidence: the runtime may write new rows and read them, nothing else.
APPEND_ONLY_TABLES: frozenset[str] = frozenset({"detection_events", "audit_logs", "evidence_chain",
                                               "audit_chain"})

# Ordinary application state.
MUTABLE_TABLES: frozenset[str] = frozenset({
    "tenants",
    "projects",
    "users",
    "honey_tokens",
    "application_configs",
    "integration_credentials",
    "alert_destinations",
    "outbox_events",
    "evidence_chain_heads",
    "audit_chain_head",
    "api_keys",
    "sso_login_codes",
    "mail_outbox",
    "system_status",
    "passkey_credentials",
    "passkey_challenges",
})

# Read-only for the runtime (readiness compares the revision).
# Retention anchors are written only by the schema owner's purge job.
READ_ONLY_TABLES: frozenset[str] = frozenset({"alembic_version", "evidence_chain_anchors", "audit_chain_anchor",
                                               # maintained only by a SECURITY DEFINER trigger
                                               "tenant_event_counts", "tenant_daily_event_counts"})

APPEND_ONLY_FORBIDDEN = ("UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")


class UnclassifiedTableError(RuntimeError):
    pass


def _quote_ident(conn: Connection, name: str) -> str:
    return conn.execute(text("SELECT quote_ident(:n)"), {"n": name}).scalar_one()


def existing_tables(conn: Connection, schema: str = "public") -> set[str]:
    rows = conn.execute(
        text("SELECT tablename FROM pg_tables WHERE schemaname = :s"), {"s": schema}
    ).scalars()
    return set(rows)


def classify(tables: set[str]) -> dict[str, str]:
    unknown = sorted(t for t in tables if t not in APPEND_ONLY_TABLES | MUTABLE_TABLES | READ_ONLY_TABLES)
    if unknown:
        raise UnclassifiedTableError(
            "Tables without a runtime privilege classification: " + ", ".join(unknown)
            + ". Add them to app/db/privileges.py before granting."
        )
    out: dict[str, str] = {}
    for t in tables:
        if t in APPEND_ONLY_TABLES:
            out[t] = "SELECT, INSERT"
        elif t in MUTABLE_TABLES:
            out[t] = "SELECT, INSERT, UPDATE, DELETE"
        else:
            out[t] = "SELECT"
    return out


def grant_statements(conn: Connection, role: str, schema: str = "public") -> list[str]:
    """Idempotent statements that reset the runtime role to exactly the policy."""
    r = _quote_ident(conn, role)
    s = _quote_ident(conn, schema)
    db = conn.execute(text("SELECT quote_ident(current_database())")).scalar_one()
    stmts = [
        f"REVOKE ALL ON SCHEMA {s} FROM {r}",
        f"GRANT USAGE ON SCHEMA {s} TO {r}",
        f"REVOKE CREATE ON SCHEMA {s} FROM PUBLIC",
        f"REVOKE CREATE, TEMPORARY ON DATABASE {db} FROM {r}",
        f"GRANT CONNECT ON DATABASE {db} TO {r}",
        f"REVOKE ALL ON ALL TABLES IN SCHEMA {s} FROM {r}",
        f"REVOKE ALL ON ALL SEQUENCES IN SCHEMA {s} FROM {r}",
        f"REVOKE ALL ON ALL FUNCTIONS IN SCHEMA {s} FROM PUBLIC",
    ]
    for table, privs in sorted(classify(existing_tables(conn, schema)).items()):
        stmts.append(f"GRANT {privs} ON TABLE {s}.{_quote_ident(conn, table)} TO {r}")
    stmts.append(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA {s} TO {r}")
    return stmts


def apply_grants(conn: Connection, role: str, schema: str = "public") -> list[str]:
    stmts = grant_statements(conn, role, schema)
    for stmt in stmts:
        conn.execute(text(stmt))
    return stmts


@dataclass
class PrivilegeReport:
    role: str
    violations: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.violations


def inspect_current_role(conn: Connection, schema: str = "public") -> PrivilegeReport:
    """Check that the connected role is a least-privilege runtime role."""
    role = conn.execute(text("SELECT current_user")).scalar_one()
    report = PrivilegeReport(role=role)
    attrs = conn.execute(
        text("SELECT rolsuper, rolcreaterole, rolcreatedb, rolbypassrls, rolreplication "
             "FROM pg_roles WHERE rolname = current_user")
    ).one()
    for name, value in zip(("SUPERUSER", "CREATEROLE", "CREATEDB", "BYPASSRLS", "REPLICATION"), attrs):
        if value:
            report.violations.append(f"role has {name}")
    owned = conn.execute(
        text("SELECT tablename FROM pg_tables WHERE schemaname = :s AND tableowner = current_user"),
        {"s": schema},
    ).scalars().all()
    if owned:
        report.violations.append("role owns tables: " + ", ".join(sorted(owned)))
    if conn.execute(text("SELECT has_schema_privilege(current_user, :s, 'CREATE')"), {"s": schema}).scalar_one():
        report.violations.append(f"role can CREATE in schema {schema}")
    tables = existing_tables(conn, schema)
    for table in sorted(tables & APPEND_ONLY_TABLES):
        for priv in APPEND_ONLY_FORBIDDEN:
            if conn.execute(
                text("SELECT has_table_privilege(current_user, :t, :p)"),
                {"t": f"{schema}.{table}", "p": priv},
            ).scalar_one():
                report.violations.append(f"role has {priv} on {table}")
    # Membership in the owning role would let it SET ROLE and regain ownership.
    owners = conn.execute(
        text("SELECT DISTINCT tableowner FROM pg_tables WHERE schemaname = :s"), {"s": schema}
    ).scalars().all()
    for owner in owners:
        if owner != role and conn.execute(
            text("SELECT pg_has_role(current_user, :o, 'MEMBER')"), {"o": owner}
        ).scalar_one():
            report.violations.append(f"role is a member of table owner {owner}")
    return report


def _main(argv: list[str] | None = None) -> int:
    from app.core.config import get_settings

    parser = argparse.ArgumentParser(prog="python -m app.db.privileges")
    sub = parser.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("grant", help="Apply the runtime grant policy (run as the migration owner).")
    g.add_argument("--role", default=None, help="Runtime role (default: POSTGRES_APP_USER).")
    sub.add_parser("check", help="Verify the runtime connection is least-privilege.")
    args = parser.parse_args(argv)

    settings = get_settings()
    if args.cmd == "grant":
        role = args.role or settings.postgres_app_user
        if not role:
            print("No runtime role: pass --role or set POSTGRES_APP_USER", file=sys.stderr)
            return 2
        engine = create_engine(settings.migration_database_uri)
        with engine.begin() as conn:
            stmts = apply_grants(conn, role)
        print(f"Applied {len(stmts)} privilege statements for role {role}.")
        return 0

    engine = create_engine(settings.sqlalchemy_database_uri)
    with engine.connect() as conn:
        report = inspect_current_role(conn)
    if report.ok:
        print(f"Runtime role {report.role}: least-privilege checks passed.")
        return 0
    for v in report.violations:
        print(f"VIOLATION ({report.role}): {v}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(_main())
