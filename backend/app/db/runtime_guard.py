"""Fail-closed check that the API is not running with a privileged database role (HONEY-002)."""
from __future__ import annotations

import logging
import threading

from sqlalchemy.engine import Engine

from app.db.privileges import PrivilegeReport, inspect_current_role

logger = logging.getLogger(__name__)


class PrivilegedRuntimeRoleError(RuntimeError):
    pass


_lock = threading.Lock()
_verified = False


def reset() -> None:
    global _verified
    with _lock:
        _verified = False


def check(engine: Engine) -> PrivilegeReport | None:
    """Return the report, or None when the database is not PostgreSQL (development/tests)."""
    if engine.dialect.name != "postgresql":
        return None
    with engine.connect() as conn:
        return inspect_current_role(conn)


def ensure_least_privilege(engine: Engine) -> bool:
    """True once the runtime role has passed; raises when it is privileged.

    Connection errors propagate to the caller (startup logs them and readiness stays 503)
    so an unreachable database is never mistaken for a verified one.
    """
    global _verified
    if _verified:
        return True
    report = check(engine)
    if report is not None and not report.ok:
        for v in report.violations:
            logger.critical("Runtime database role %s violates least privilege: %s", report.role, v)
        raise PrivilegedRuntimeRoleError(
            f"Runtime database role {report.role} is privileged ({len(report.violations)} violations); "
            "connect as the runtime role and run `python -m app.db.privileges grant`."
        )
    with _lock:
        _verified = True
    return True
