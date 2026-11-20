"""Replay decoy hits the edge captured while the backend could not record them.

The edge (nginx) appends one JSON line per such hit to the spool file. This worker follows that file
and sends complete lines, in signed batches, to the backend's internal replay endpoint. It moves its
saved position forward only after the backend has accepted a batch, so a hit is never dropped by the
worker: while the backend is down it waits and retries with backoff. Duplicates are harmless (the
backend stores one event per edge request id).

It needs no database access, only the backend's internal address, so it runs next to the edge: a
Compose service sharing the spool volume, or a sidecar in the edge pod on Kubernetes.

Environment: HS_INGEST_SPOOL (file), HS_REPLAY_URL (endpoint), INTEGRATION_SIGNING_KEY.
"""
from __future__ import annotations

import json
import logging
import os
import signal
import threading
import time
import urllib.error
import urllib.request

from app.core.replay_signing import replay_key, sign

logger = logging.getLogger("honeyshield.ingest_replay")

FIELDS = ("request_id", "time", "remote_addr", "method", "uri", "user_agent", "referer", "accept", "accept_language")
BATCH = 500
MAX_BATCH_BYTES = 512 * 1024
_stop = threading.Event()


def _on_signal(signum, _frame) -> None:  # pragma: no cover - process control
    logger.info("Replay worker received signal %s; stopping", signum)
    _stop.set()


def _load_state(path: str) -> tuple[int, int]:
    try:
        with open(path) as fh:
            state = json.load(fh)
        return int(state["inode"]), int(state["offset"])
    except (OSError, ValueError, KeyError):
        return 0, 0


def _save_state(path: str, inode: int, offset: int) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "w") as fh:
        json.dump({"inode": inode, "offset": offset}, fh)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def read_batch(spool: str, offset: int) -> tuple[list[dict], int]:
    """Complete lines from ``offset``: (entries, bytes consumed). A line still being written (no
    trailing newline yet) is left for the next round; a malformed line is skipped and logged."""
    entries: list[dict] = []
    consumed = 0
    with open(spool, "rb") as fh:
        fh.seek(offset)
        while len(entries) < BATCH and consumed < MAX_BATCH_BYTES:
            line = fh.readline()
            if not line or not line.endswith(b"\n"):
                break
            consumed += len(line)
            try:
                raw = json.loads(line)
                entry = {k: raw.get(k) for k in FIELDS}
                entry = {k: (v if v not in ("", "-") else None) for k, v in entry.items()}
                entry["time"] = float(entry["time"])
                if not entry["request_id"] or not entry["uri"] or not entry["remote_addr"]:
                    raise ValueError("missing field")
                entries.append(entry)
            except (ValueError, TypeError):
                logger.error("Skipping malformed spool line at byte %d", offset + consumed - len(line))
    return entries, consumed


def send(url: str, key: bytes, entries: list[dict], timeout: float = 30.0) -> dict:
    body = json.dumps({"entries": entries}, separators=(",", ":")).encode()
    stamp = str(int(time.time()))
    request = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/json", "X-HS-Timestamp": stamp, "X-HS-Signature": sign(key, stamp, body)})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - internal URL from config
        return json.loads(response.read() or b"{}")


def run_once(spool: str, state_file: str, url: str, key: bytes) -> int:
    """Send what is pending. Returns the number of lines handed over (0 when nothing to do).
    Raises when the backend did not accept a batch (the position is then not advanced)."""
    if not os.path.exists(spool):
        return 0
    st = os.stat(spool)
    inode, offset = _load_state(state_file)
    if inode != st.st_ino or offset > st.st_size:
        inode, offset = st.st_ino, 0      # new or rotated file: start from its beginning
    handed = 0
    while not _stop.is_set():
        entries, consumed = read_batch(spool, offset)
        if consumed == 0:
            break
        if entries:
            result = send(url, key, entries)
            logger.warning("Replayed %d captured hit(s): %s", len(entries), result)
        offset += consumed
        _save_state(state_file, inode, offset)
        handed += len(entries)
    return handed


def main() -> None:  # pragma: no cover - long-running loop, exercised end to end
    from app.core.logging import configure_logging
    configure_logging(os.environ.get("LOG_LEVEL", "INFO"))
    spool = os.environ.get("HS_INGEST_SPOOL", "/var/spool/honeyshield/ingest.jsonl")
    url = os.environ.get("HS_REPLAY_URL", "http://backend:8000/internal/v1/ingest-replay")
    state_file = os.environ.get("HS_INGEST_SPOOL_STATE", f"{spool}.offset")
    secret = os.environ.get("INTEGRATION_SIGNING_KEY")
    if not secret:
        raise SystemExit("INTEGRATION_SIGNING_KEY is required")
    key = replay_key(secret)
    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)
    logger.info("Replay worker following %s", spool)
    backoff = 2.0
    while not _stop.is_set():
        try:
            run_once(spool, state_file, url, key)
            backoff = 2.0
            with open("/tmp/ingest-replay.alive", "w") as fh:
                fh.write(str(int(time.time())))
            _stop.wait(2.0)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            logger.warning("Backend not accepting replays yet (%s); retrying in %.0fs", exc, backoff)
            _stop.wait(backoff)
            backoff = min(backoff * 2, 30.0)


if __name__ == "__main__":  # pragma: no cover
    main()
