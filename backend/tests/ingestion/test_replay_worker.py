"""The replay worker never loses a captured hit: it waits for complete lines, keeps its position
until the backend accepts a batch, and starts over on a new (rotated) spool file."""
from __future__ import annotations

import json
import threading
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from app.core.replay_signing import replay_key, sign
from app.workers import ingest_replay

KEY = replay_key("worker-test-signing-key-0123456789abcdef")


def _line(i: int) -> bytes:
    return (json.dumps({"request_id": f"{i:032x}", "time": 1_800_000_000 + i, "remote_addr": "198.51.100.7",
                        "method": "GET", "uri": f"/t/decoy-{i}", "user_agent": "", "referer": "-",
                        "accept": "*/*", "accept_language": "", "upstream_status": "502"}) + "\n").encode()


class _Backend:
    """A stand-in for the internal endpoint: verifies the signature, can be told to fail."""

    def __init__(self):
        self.fail, self.received = False, []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                body = self.rfile.read(int(self.headers["Content-Length"]))
                ok_sig = self.headers["X-HS-Signature"] == sign(KEY, self.headers["X-HS-Timestamp"], body)
                if outer.fail or not ok_sig:
                    self.send_response(503 if outer.fail else 401)
                    self.end_headers()
                    return
                outer.received.extend(json.loads(body)["entries"])
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"recorded": 1}')

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_port}/internal/v1/ingest-replay"

    def close(self):
        self.server.shutdown()


@pytest.fixture
def backend():
    b = _Backend()
    yield b
    b.close()


def test_partial_lines_wait_and_empty_fields_become_null(tmp_path):
    spool = tmp_path / "ingest.jsonl"
    spool.write_bytes(_line(1) + _line(2)[:20])            # second line still being written
    entries, consumed = ingest_replay.read_batch(str(spool), 0)
    assert [e["request_id"] for e in entries] == [f"{1:032x}"] and consumed == len(_line(1))
    assert entries[0]["user_agent"] is None and entries[0]["referer"] is None and "upstream_status" not in entries[0]


def test_position_advances_only_after_the_backend_accepts(tmp_path, backend):
    spool, state = tmp_path / "ingest.jsonl", tmp_path / "state.json"
    spool.write_bytes(b"".join(_line(i) for i in range(3)))
    backend.fail = True
    with pytest.raises(urllib.error.HTTPError):
        ingest_replay.run_once(str(spool), str(state), backend.url, KEY)
    assert backend.received == [] and not state.exists()     # nothing marked as done
    backend.fail = False
    assert ingest_replay.run_once(str(spool), str(state), backend.url, KEY) == 3
    assert [e["uri"] for e in backend.received] == ["/t/decoy-0", "/t/decoy-1", "/t/decoy-2"]
    with spool.open("ab") as fh:                             # more hits arrive later
        fh.write(_line(3))
    assert ingest_replay.run_once(str(spool), str(state), backend.url, KEY) == 1
    assert ingest_replay.run_once(str(spool), str(state), backend.url, KEY) == 0
    assert len(backend.received) == 4


def test_a_rotated_spool_is_read_from_its_start(tmp_path, backend):
    spool, state = tmp_path / "ingest.jsonl", tmp_path / "state.json"
    spool.write_bytes(_line(1) + _line(2))
    ingest_replay.run_once(str(spool), str(state), backend.url, KEY)
    spool.unlink()
    spool.write_bytes(_line(9))                              # new file (new inode), shorter than the old position
    assert ingest_replay.run_once(str(spool), str(state), backend.url, KEY) == 1
    assert backend.received[-1]["uri"] == "/t/decoy-9"


def test_a_malformed_line_is_skipped_not_fatal(tmp_path, backend):
    spool, state = tmp_path / "ingest.jsonl", tmp_path / "state.json"
    spool.write_bytes(_line(1) + b"{not json\n" + _line(2))
    assert ingest_replay.run_once(str(spool), str(state), backend.url, KEY) == 2


def test_the_worker_process_starts_and_stops_cleanly(tmp_path):
    """Runs the real entry point (as Compose and the Helm sidecar do) and stops it with SIGTERM."""
    import os
    import signal
    import subprocess
    import sys
    import time
    env = {"PATH": os.environ.get("PATH", ""), "PYTHONPATH": os.getcwd(), "LOG_LEVEL": "INFO",
           "INTEGRATION_SIGNING_KEY": "worker-test-signing-key-0123456789abcdef",
           "HS_INGEST_SPOOL": str(tmp_path / "ingest.jsonl"), "HS_REPLAY_URL": "http://127.0.0.1:9/none"}
    proc = subprocess.Popen([sys.executable, "-m", "app.workers.ingest_replay"], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(2.5)
    assert proc.poll() is None, proc.stdout.read().decode()[-2000:]
    proc.send_signal(signal.SIGTERM)
    assert proc.wait(timeout=10) == 0
    assert b"following" in proc.stdout.read()
