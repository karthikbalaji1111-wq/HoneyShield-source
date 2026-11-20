"""Alert and account-mail delivery worker: ``python -m app.workers.outbox``.

Runs as its own container (compose service ``worker``) with the runtime database role.
Several workers may run: claims use FOR UPDATE SKIP LOCKED with a lease, so a delivery is
handled by one worker at a time and a crashed worker's leases expire and are retried.
SIGTERM/SIGINT finish the current delivery and exit.
"""
from __future__ import annotations

import logging
import os
import signal
import threading
import time

from app.core.config import get_settings
from app.core.logging import configure_logging
from app.db.session import SessionLocal
from app.services import alerting
from app.services.system_status import put_status

logger = logging.getLogger("honeyshield.worker")
_stop = threading.Event()
HEARTBEAT_SECONDS = 30


def _handle(signum, _frame) -> None:
    logger.info("Worker received signal %s; stopping after the current batch", signum)
    _stop.set()


def main() -> int:
    settings = get_settings()
    configure_logging(settings.log_level)
    signal.signal(signal.SIGTERM, _handle)
    signal.signal(signal.SIGINT, _handle)
    logger.info("Alert worker started (batch=%s, poll=%ss)", settings.alert_worker_batch_size,
                settings.alert_worker_poll_seconds)
    last_beat = 0.0
    while not _stop.is_set():
        session = SessionLocal()
        try:
            if time.monotonic() - last_beat >= HEARTBEAT_SECONDS:
                # The watchdog reads this to tell "no alerts to send" from "worker not running".
                put_status(session, "outbox_worker", {"pid": os.getpid()})
                last_beat = time.monotonic()
            results = alerting.run_once(session)
            if results:
                logger.info("Alert deliveries processed: %s", results)
            from app.services import account_mail
            mail = account_mail.run_once(session)
            if mail:
                logger.info("Account mail processed: %s", mail)
                results = {**results, **{f"mail_{k}": v for k, v in mail.items()}}
        except Exception:
            logger.exception("Alert worker iteration failed; retrying")
            try:
                session.rollback()
            except Exception:
                pass
            results = {}
        finally:
            session.close()
        if not results:
            _stop.wait(settings.alert_worker_poll_seconds)
    logger.info("Alert worker stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
