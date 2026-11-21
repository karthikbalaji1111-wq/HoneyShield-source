"""Write-once shipping of signed checkpoints to S3 Object Lock (stdlib only, AWS SigV4).

Why: a checkpoint only detects a rewritten evidence/audit chain if the party who rewrote the
chain cannot also rewrite the checkpoint. S3 Object Lock in COMPLIANCE mode makes each object
version undeletable and unmodifiable until its retain-until date, even by the bucket owner or
the account root user.

* Every object is written with ``x-amz-object-lock-mode`` / ``retain-until-date`` and
  ``Content-MD5`` (required by S3 for locked writes) and ``If-None-Match: *`` so an existing
  name is never replaced.
* The bucket must be created with Object Lock enabled (it implies versioning). The credentials
  need only s3:PutObject, s3:PutObjectRetention, s3:GetObject and s3:ListBucket; no delete
  permission (docs/evidence-integrity.md has the IAM policy).
* Works with AWS S3 and S3-compatible stores that implement Object Lock (MinIO, Ceph RGW...).
  Path-style addressing: ``{endpoint}/{bucket}/{key}``.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import json
import ssl
import urllib.parse
from app.core import safexml as ET
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
_S3_NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"


class WormError(RuntimeError):
    pass


class ObjectExistsError(WormError):
    pass


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def _uri_encode(value: str, encode_slash: bool) -> str:
    return urllib.parse.quote(value, safe="-_.~" + ("" if encode_slash else "/"))


def sigv4_headers(method: str, host: str, path: str, query: dict[str, str], headers: dict[str, str],
                  payload_sha256: str, region: str, access_key: str, secret_key: str,
                  now: datetime | None = None, service: str = "s3") -> dict[str, str]:
    """Return ``headers`` plus x-amz-date, x-amz-content-sha256 and Authorization (SigV4)."""
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date = now.strftime("%Y%m%d")
    all_headers = {k.lower(): str(v).strip() for k, v in headers.items()}
    all_headers["host"] = host
    all_headers["x-amz-date"] = amz_date
    all_headers["x-amz-content-sha256"] = payload_sha256
    signed = sorted(all_headers)
    canonical_headers = "".join(f"{k}:{' '.join(all_headers[k].split())}\n" for k in signed)
    canonical_query = "&".join(f"{_uri_encode(k, True)}={_uri_encode(v, True)}" for k, v in sorted(query.items()))
    canonical_request = "\n".join([method, _uri_encode(path, False), canonical_query, canonical_headers,
                                   ";".join(signed), payload_sha256])
    scope = f"{date}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope,
                                hashlib.sha256(canonical_request.encode()).hexdigest()])
    key = _hmac(_hmac(_hmac(_hmac(("AWS4" + secret_key).encode(), date), region), service), "aws4_request")
    signature = hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest()
    out = {k: v for k, v in headers.items()}
    out["x-amz-date"] = amz_date
    out["x-amz-content-sha256"] = payload_sha256
    out["Authorization"] = (f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
                            f"SignedHeaders={';'.join(signed)}, Signature={signature}")
    return out


@dataclass
class S3Config:
    endpoint: str
    bucket: str
    region: str
    access_key_id: str
    secret_access_key: str
    prefix: str = "checkpoints/"
    retention_days: int = 400
    lock_mode: str = "COMPLIANCE"
    timeout: float = 15.0
    ca_file: str | None = None

    @classmethod
    def from_settings(cls, settings: Any) -> "S3Config | None":
        if not settings.evidence_s3_bucket:
            return None
        return cls(endpoint=settings.evidence_s3_endpoint, bucket=settings.evidence_s3_bucket,
                   region=settings.evidence_s3_region, access_key_id=settings.evidence_s3_access_key_id,
                   secret_access_key=settings.evidence_s3_secret_access_key,
                   prefix=settings.evidence_s3_prefix, retention_days=settings.evidence_s3_retention_days,
                   lock_mode=settings.evidence_s3_lock_mode, ca_file=settings.evidence_s3_ca_file)


class S3ObjectLockSink:
    """Puts each checkpoint file into an Object Lock bucket; reads them back for verification."""

    def __init__(self, cfg: S3Config) -> None:
        self.cfg = cfg
        parts = urllib.parse.urlsplit(cfg.endpoint)
        if parts.scheme not in ("https", "http") or not parts.hostname:
            raise WormError("EVIDENCE_S3_ENDPOINT must be an http(s) URL")
        self.scheme = parts.scheme
        self.host = parts.hostname
        self.port = parts.port or (443 if parts.scheme == "https" else 80)
        self.host_header = parts.netloc

    # ------------------------------------------------------------------ transport
    def _request(self, method: str, key: str | None, *, query: dict[str, str] | None = None, body: bytes = b"",
                 headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], bytes]:
        path = f"/{self.cfg.bucket}" + (f"/{key}" if key is not None else "")
        query = query or {}
        signed = sigv4_headers(method, self.host_header, path, query, headers or {}, hashlib.sha256(body).hexdigest(),
                               self.cfg.region, self.cfg.access_key_id, self.cfg.secret_access_key)
        if body:
            signed["Content-Length"] = str(len(body))
        url = _uri_encode(path, False)
        if query:
            url += "?" + "&".join(f"{_uri_encode(k, True)}={_uri_encode(v, True)}" for k, v in sorted(query.items()))
        if self.scheme == "https":
            ctx = ssl.create_default_context(cafile=self.cfg.ca_file)
            conn: http.client.HTTPConnection = http.client.HTTPSConnection(self.host, self.port,
                                                                           timeout=self.cfg.timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(self.host, self.port, timeout=self.cfg.timeout)
        try:
            conn.request(method, url, body=body or None, headers=signed)
            resp = conn.getresponse()
            data = resp.read(10 * 1024 * 1024)
            return resp.status, {k.lower(): v for k, v in resp.getheaders()}, data
        finally:
            conn.close()

    @staticmethod
    def _error(status: int, data: bytes) -> str:
        try:
            root = ET.fromstring(data)
            code = root.findtext("Code") or root.findtext(f"{_S3_NS}Code") or ""
            return f"HTTP {status} {code}".strip()
        except ET.ParseError:
            return f"HTTP {status}"

    # ------------------------------------------------------------------ operations
    def put(self, name: str, data: bytes, now: datetime | None = None) -> str:
        if "/" in name or name.startswith("."):
            raise WormError("invalid object name")
        now = now or datetime.now(timezone.utc)
        retain = (now + timedelta(days=self.cfg.retention_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        headers = {
            "Content-Type": "application/json",
            "Content-MD5": base64.b64encode(hashlib.md5(data, usedforsecurity=False).digest()).decode(),  # S3 integrity header, not security
            "If-None-Match": "*",
            "x-amz-object-lock-mode": self.cfg.lock_mode,
            "x-amz-object-lock-retain-until-date": retain,
        }
        key = self.cfg.prefix + name
        status, resp_headers, body = self._request("PUT", key, body=data, headers=headers)
        if status == 412:
            raise ObjectExistsError(f"{key} already exists")
        if status != 200:
            raise WormError(f"PUT {key}: {self._error(status, body)}")
        return resp_headers.get("x-amz-version-id", "")

    def list_names(self) -> list[str]:
        names: list[str] = []
        token: str | None = None
        while True:
            query = {"list-type": "2", "prefix": self.cfg.prefix}
            if token:
                query["continuation-token"] = token
            status, _, body = self._request("GET", None, query=query)
            if status != 200:
                raise WormError(f"LIST: {self._error(status, body)}")
            root = ET.fromstring(body)
            for c in root.iter(f"{_S3_NS}Contents"):
                key = c.findtext(f"{_S3_NS}Key") or ""
                names.append(key[len(self.cfg.prefix):])
            if (root.findtext(f"{_S3_NS}IsTruncated") or "false") != "true":
                break
            token = root.findtext(f"{_S3_NS}NextContinuationToken")
        return sorted(n for n in names if n)

    def get(self, name: str) -> bytes:
        status, _, body = self._request("GET", self.cfg.prefix + name)
        if status != 200:
            raise WormError(f"GET {name}: {self._error(status, body)}")
        return body

    def retention(self, name: str) -> dict[str, str]:
        status, _, body = self._request("GET", self.cfg.prefix + name, query={"retention": ""})
        if status != 200:
            raise WormError(f"GET retention {name}: {self._error(status, body)}")
        root = ET.fromstring(body)
        return {"mode": root.findtext(f"{_S3_NS}Mode") or root.findtext("Mode") or "",
                "retain_until": root.findtext(f"{_S3_NS}RetainUntilDate") or root.findtext("RetainUntilDate") or ""}

    def checkpoints(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for name in self.list_names():
            if name.startswith("checkpoint-") and name.endswith(".json"):
                out.extend(json.loads(self.get(name)))
        return out


def sync_directory(local_dir: str | Path, sink: S3ObjectLockSink) -> list[str]:
    """Upload every local checkpoint file not yet in the bucket. Returns the names uploaded.

    Run after each checkpoint: a failed upload is retried on the next run instead of leaving a
    permanent gap.
    """
    remote = set(sink.list_names())
    uploaded = []
    for path in sorted(Path(local_dir).glob("checkpoint-*.json")):
        if path.name in remote:
            continue
        try:
            sink.put(path.name, path.read_bytes())
        except ObjectExistsError:
            continue
        uploaded.append(path.name)
    return uploaded
