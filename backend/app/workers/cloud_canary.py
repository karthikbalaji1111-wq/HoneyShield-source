"""Cloud canary worker: ``python -m app.workers.cloud_canary``.

The only component with AWS credentials (AWS_CANARY_ACCESS_KEY_ID / _SECRET_ACCESS_KEY) and the
only one that talks to AWS. Every few seconds it creates keys for new AWS_KEY decoys and deletes
the IAM users of revoked ones; every AWS_CANARY_POLL_SECONDS it reads CloudTrail event history
for uses of active keys and records them as CLOUD_AUDIT events (app/services/aws_canary.py).

Its status (account, regions, last cycle, errors) is in system_status "cloud_canary_worker", which
the watchdog checks. SIGTERM/SIGINT finish the current step and exit.
"""
from __future__ import annotations

import logging
import signal
import threading
import time

from app.core.config import get_settings
from app.core.logging import configure_logging
from app.db.session import SessionLocal
from app.services.aws_canary import STATUS_WORKER, AwsClient, AwsError, CanaryManager, regions
from app.services.system_status import put_status

logger = logging.getLogger("honeyshield.cloud_canary")
_stop = threading.Event()
RECONCILE_SECONDS = 10


def _handle(signum, _frame) -> None:  # pragma: no cover - process control
    logger.info("Cloud canary worker received signal %s; stopping", signum)
    _stop.set()


def run_cycle(manager: CanaryManager, poll_due: bool) -> dict:
    """One reconcile step and, when due, one CloudTrail poll. Returns what happened."""
    result = {"reconcile": manager.reconcile()}
    if poll_due:
        started = time.monotonic()
        result["poll"] = manager.poll()
        result["poll_seconds"] = round(time.monotonic() - started, 1)
    return result


def main() -> int:  # pragma: no cover - long-running loop; run_cycle is tested
    settings = get_settings()
    configure_logging(settings.log_level)
    signal.signal(signal.SIGTERM, _handle)
    signal.signal(signal.SIGINT, _handle)
    if not settings.aws_canary_enabled:
        logger.error("AWS_CANARY_ENABLED is not set: nothing to do")
        return 2
    client = AwsClient(settings.aws_canary_access_key_id or "", settings.aws_canary_secret_access_key or "",
                       settings.aws_canary_endpoint_url)
    backoff, identity, last_poll, last_status = 5.0, None, 0.0, {}
    while not _stop.is_set():
        session = SessionLocal()
        try:
            manager = CanaryManager(session, settings, client)
            if identity is None:
                identity = manager.identify()
                logger.info("Cloud canaries in AWS account %s, watching %d region(s)",
                            identity["account"], len(regions(settings)))
            manager.account = identity["account"]
            poll_due = time.monotonic() - last_poll >= settings.aws_canary_poll_seconds
            result = run_cycle(manager, poll_due)
            if poll_due:
                last_poll = time.monotonic()
                last_status = {"account": identity["account"], "regions": len(regions(settings)),
                               "last_poll": result["poll"], "poll_seconds": result["poll_seconds"]}
                if result["poll"]["recorded"]:
                    logger.warning("Cloud canary key use recorded: %s", result["poll"])
            if any(result["reconcile"].values()):
                logger.info("Cloud canaries: %s", result["reconcile"])
            put_status(session, STATUS_WORKER, {**last_status, "ok": True,
                                                "reconcile": result["reconcile"]})
            backoff = 5.0
        except AwsError as exc:
            logger.error("AWS refused the canary worker's request (%s); retrying in %.0fs", exc, backoff)
            try:
                session.rollback()
                put_status(session, STATUS_WORKER, {**last_status, "ok": False, "error": str(exc)[:300]})
            except Exception:
                session.rollback()
            identity = None if exc.code in ("InvalidClientTokenId", "SignatureDoesNotMatch",
                                            "ExpiredToken") else identity
            _stop.wait(backoff)
            backoff = min(backoff * 2, 300.0)
            continue
        except Exception:
            logger.exception("Cloud canary cycle failed; retrying")
            try:
                session.rollback()
            except Exception:
                pass
        finally:
            session.close()
        _stop.wait(RECONCILE_SECONDS)
    logger.info("Cloud canary worker stopped")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
