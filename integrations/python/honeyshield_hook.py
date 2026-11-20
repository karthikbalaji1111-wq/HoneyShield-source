"""HoneyShield customer-side detection hook (reference implementation, Python 3.9+, stdlib only).

Runs inside YOUR application. It recognises planted decoys and reports them to HoneyShield
without ever sending the presented credential, and without ever changing or delaying your
own authentication or form handling.

    hook = HoneyShieldHook("https://ingest.example.com", integration_id, secret)
    hook.start()                      # loads the manifest, starts the background sender

    # in API-key authentication (keep your normal decision; a decoy is still rejected):
    hook.check_api_key(presented_key, source_ip=client_ip, http_method="GET", request_path=path)

    # in a form handler protected by a HoneyShield honeypot field:
    hook.check_form(request.form, source_ip=client_ip, request_path=path)

Guarantees (see docs/customer-integrations.md):
* check_* never raise, never block on the network, and return in O(1).
* Only decoy_id, idempotency_key, time, client IP, method, path (query dropped) and user agent
  are sent. Never the key, the Authorization header, cookies, bodies or query strings.
* Reports go through a bounded queue (``queue_size``, default 10,000); only when it is full is the
  OLDEST report dropped.
* A report that cannot be delivered is kept and retried, with exponential backoff and jitter up to
  ``max_retry_delay`` seconds, until HoneyShield accepts it: an outage delays reports, it does not
  lose them. Every retry carries the same idempotency key, so nothing is recorded twice.
* With ``spool_path`` set, reports still undelivered at ``stop()`` are saved there and sent after the
  next ``start()``, so a graceful restart of your application loses nothing either.
"""
from __future__ import annotations

import collections
import hashlib
import hmac
import json
import logging
import os
import random
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Callable, Mapping, Optional

log = logging.getLogger("honeyshield_hook")

#: transport(method, url, headers, body, timeout) -> (status, response_body)
Transport = Callable[[str, str, dict, bytes, float], "tuple[int, bytes]"]


def _urllib_transport(method: str, url: str, headers: dict, body: bytes, timeout: float) -> "tuple[int, bytes]":
    req = urllib.request.Request(url, data=body if method != "GET" else None, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (https URL from config)
            return resp.status, resp.read(1_000_000)
    except urllib.error.HTTPError as exc:
        return exc.code, b""


def sign(secret: str, method: str, path: str, timestamp: str, body: bytes) -> str:
    canonical = "\n".join(("v1", method.upper(), path, timestamp, hashlib.sha256(body).hexdigest()))
    return "v1=" + hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()


class HoneyShieldHook:
    def __init__(
        self,
        base_url: str,
        integration_id: str,
        secret: str,
        *,
        transport: Optional[Transport] = None,
        queue_size: int = 10000,
        timeout: float = 2.0,
        max_attempts: int = 3,
        backoff_base: float = 0.5,
        max_retry_delay: float = 60.0,
        spool_path: Optional[str] = None,
        manifest_refresh_seconds: float = 300.0,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        parsed = urllib.parse.urlsplit(base_url)
        if parsed.scheme not in ("https", "http") or not parsed.netloc:
            raise ValueError("base_url must be an http(s) origin")
        self._base = f"{parsed.scheme}://{parsed.netloc}"
        self._id = integration_id
        self._secret = secret
        self._transport = transport or _urllib_transport
        self._timeout = timeout
        self._max_attempts = max(1, max_attempts)
        self._backoff = backoff_base
        self._max_retry_delay = max_retry_delay
        self._retry_delay = 0.0
        self._spool_path = spool_path
        self._refresh = manifest_refresh_seconds
        self._clock = clock
        self._sleep = sleep
        self._queue: "collections.deque[dict]" = collections.deque(maxlen=max(1, queue_size))
        self._cv = threading.Condition()
        self._stop = False
        self._thread: Optional[threading.Thread] = None
        self._key_hashes: "dict[str, str]" = {}      # sha256 -> decoy_id
        self._form_fields: "dict[str, str]" = {}     # field_name -> decoy_id
        self._manifest_at = 0.0
        self.stats = collections.Counter()

    # ------------------------------------------------------------------ requests
    def _request(self, method: str, path: str, body: bytes = b"") -> "tuple[int, bytes]":
        ts = str(int(self._clock()))
        headers = {
            "X-HS-Integration": self._id,
            "X-HS-Timestamp": ts,
            "X-HS-Signature": sign(self._secret, method, path, ts, body),
            "Content-Type": "application/json",
            "User-Agent": "honeyshield-hook/1",
        }
        return self._transport(method, self._base + path, headers, body, self._timeout)

    def refresh_manifest(self) -> bool:
        """Load the decoy manifest. On failure the previous manifest is kept."""
        try:
            status, body = self._request("GET", "/integrations/v1/manifest")
            if status != 200:
                self.stats["manifest_errors"] += 1
                return False
            data = json.loads(body)
            keys, fields = {}, {}
            for d in data.get("decoys", []):
                if d.get("token_type") == "API_KEY" and d.get("sha256"):
                    keys[d["sha256"]] = d["decoy_id"]
                elif d.get("token_type") == "FORM_FIELD" and d.get("field_name"):
                    fields[d["field_name"]] = d["decoy_id"]
            self._key_hashes, self._form_fields = keys, fields
            self._manifest_at = self._clock()
            return True
        except Exception:  # never propagate into the host application
            self.stats["manifest_errors"] += 1
            log.warning("HoneyShield manifest refresh failed", exc_info=True)
            return False

    # ------------------------------------------------------------------ detection
    def check_api_key(self, presented: Optional[str], *, source_ip: str, http_method: Optional[str] = None,
                      request_path: Optional[str] = None, user_agent: Optional[str] = None) -> bool:
        """True if ``presented`` is a planted decoy. Your auth decision must not depend on this."""
        try:
            if not presented:
                return False
            digest = hashlib.sha256(presented.encode()).hexdigest()
            decoy_id = self._key_hashes.get(digest)  # dict lookup on a hash; the key is not kept
            if decoy_id is None:
                return False
            self._enqueue(decoy_id, source_ip, http_method, request_path, user_agent)
            return True
        except Exception:
            self.stats["check_errors"] += 1
            return False

    def check_form(self, form: Mapping[str, str], *, source_ip: str, http_method: Optional[str] = "POST",
                   request_path: Optional[str] = None, user_agent: Optional[str] = None) -> bool:
        """True if any honeypot field in ``form`` was filled in."""
        try:
            hit = False
            for field_name, decoy_id in self._form_fields.items():
                value = form.get(field_name)
                if value is not None and str(value).strip():
                    self._enqueue(decoy_id, source_ip, http_method, request_path, user_agent)
                    hit = True
            return hit
        except Exception:
            self.stats["check_errors"] += 1
            return False

    # ------------------------------------------------------------------ queue
    def _enqueue(self, decoy_id: str, source_ip: str, method: Optional[str], path: Optional[str],
                 user_agent: Optional[str]) -> None:
        now = self._clock()
        minute = int(now // 60)
        idem = hashlib.sha256(f"{decoy_id}|{source_ip}|{minute}".encode()).hexdigest()[:40]
        report = {
            "decoy_id": decoy_id,
            "idempotency_key": idem,
            "observed_at": datetime.fromtimestamp(now, timezone.utc).isoformat(),
            "source_ip": source_ip,
        }
        if method:
            report["http_method"] = method.upper()[:10]
        if path:
            report["request_path"] = path.split("?", 1)[0].split("#", 1)[0][:2048]
        if user_agent:
            report["user_agent"] = user_agent[:1024]
        with self._cv:
            if len(self._queue) == self._queue.maxlen:
                self.stats["dropped_queue_full"] += 1  # deque drops the oldest
            self._queue.append(report)
            self._cv.notify()

    def _send(self, report: dict) -> str:
        """'sent', 'rejected' (retrying cannot help) or 'failed' (try again later)."""
        body = json.dumps(report, separators=(",", ":")).encode()
        for attempt in range(self._max_attempts):
            try:
                status, _ = self._request("POST", "/integrations/v1/events", body)
                if status == 202:
                    self.stats["sent"] += 1
                    return "sent"
                if status in (400, 401, 403, 413, 422):
                    self.stats["rejected"] += 1
                    return "rejected"
            except Exception:
                pass
            self.stats["retries"] += 1
            if attempt + 1 < self._max_attempts:
                self._sleep(self._backoff * (2 ** attempt) * (0.5 + random.random()))
        return "failed"

    def drain(self) -> int:
        """Send what is queued, synchronously, in order. Stops at the first report HoneyShield cannot
        take right now and keeps it at the front of the queue. Returns how many were handled."""
        n = 0
        while True:
            with self._cv:
                if not self._queue:
                    self._retry_delay = 0.0
                    return n
                report = self._queue.popleft()
            if self._send(report) == "failed":
                with self._cv:
                    self._queue.appendleft(report)   # same idempotency key next time
                self.stats["deferred"] += 1
                self._retry_delay = min(self._max_retry_delay,
                                        max(self._backoff, self._retry_delay * 2) * (0.5 + random.random()))
                return n
            n += 1

    def _run(self) -> None:
        while True:
            with self._cv:
                while not self._queue and not self._stop:
                    self._cv.wait(timeout=self._refresh)
                    if self._clock() - self._manifest_at >= self._refresh:
                        break
                if self._stop and not self._queue:
                    return
            if self._clock() - self._manifest_at >= self._refresh:
                self.refresh_manifest()
            self.drain()
            if self._retry_delay:
                with self._cv:                        # HoneyShield unreachable: wait, then retry
                    if not self._stop:
                        self._cv.wait(timeout=self._retry_delay)
                    if self._stop:
                        return

    def _load_spool(self) -> None:
        if not self._spool_path:
            return
        try:
            with open(self._spool_path) as fh:
                saved = [json.loads(line) for line in fh if line.strip()]
        except FileNotFoundError:
            return
        except Exception:
            log.warning("HoneyShield spool %s could not be read", self._spool_path, exc_info=True)
            return
        with self._cv:
            for report in reversed(saved):
                self._queue.appendleft(report)
            self._cv.notify()
        self.stats["restored_from_spool"] += len(saved)
        open(self._spool_path, "w").close()

    def _save_spool(self) -> None:
        if not self._spool_path:
            return
        with self._cv:
            pending = list(self._queue)
        tmp = f"{self._spool_path}.tmp"
        with open(tmp, "w") as fh:
            for report in pending:
                fh.write(json.dumps(report, separators=(",", ":")) + "\n")
        os.replace(tmp, self._spool_path)
        self.stats["saved_to_spool"] += len(pending)

    def start(self) -> None:
        self._load_spool()
        self.refresh_manifest()
        if self._thread is None:
            self._thread = threading.Thread(target=self._run, name="honeyshield-hook", daemon=True)
            self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        with self._cv:
            self._stop = True
            self._cv.notify_all()
        if self._thread is not None:
            self._thread.join(timeout)
        self._save_spool()
