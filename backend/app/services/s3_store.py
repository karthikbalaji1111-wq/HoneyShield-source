"""Plain S3 object storage for backups (stdlib + SigV4 from app/services/worm.py).

Works with any S3-compatible store with path-style addressing: AWS S3, Oracle Cloud Object Storage
(S3 compatibility endpoint), Backblaze B2, Cloudflare R2, MinIO, Wasabi. Files are streamed from and
to disk, so memory use does not depend on the backup size. Single PUT, so one object is at most 5 GB.
"""
from __future__ import annotations

import hashlib
import http.client
import ssl
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from app.services.worm import _S3_NS, _uri_encode, sigv4_headers

MAX_OBJECT_BYTES = 5 * 1024 ** 3


class S3StoreError(RuntimeError):
    pass


@dataclass
class S3Object:
    key: str
    size: int
    last_modified: str


@dataclass
class S3StoreConfig:
    endpoint: str
    bucket: str
    region: str
    access_key_id: str
    secret_access_key: str
    timeout: float = 60.0
    ca_file: str | None = None


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


class S3Store:
    def __init__(self, cfg: S3StoreConfig) -> None:
        parts = urllib.parse.urlsplit(cfg.endpoint)
        if parts.scheme not in ("https", "http") or not parts.hostname:
            raise S3StoreError("the S3 endpoint must be an http(s) URL")
        self.cfg = cfg
        self.scheme, self.host = parts.scheme, parts.hostname
        self.port = parts.port or (443 if parts.scheme == "https" else 80)
        self.host_header = parts.netloc

    def _conn(self) -> http.client.HTTPConnection:
        if self.scheme == "https":
            ctx = ssl.create_default_context(cafile=self.cfg.ca_file)
            return http.client.HTTPSConnection(self.host, self.port, timeout=self.cfg.timeout, context=ctx)
        return http.client.HTTPConnection(self.host, self.port, timeout=self.cfg.timeout)

    def _signed(self, method: str, key: str | None, query: dict[str, str], payload_sha256: str,
                headers: dict[str, str] | None = None) -> tuple[str, dict[str, str]]:
        path = f"/{self.cfg.bucket}" + (f"/{key}" if key is not None else "")
        signed = sigv4_headers(method, self.host_header, path, query, headers or {}, payload_sha256,
                               self.cfg.region, self.cfg.access_key_id, self.cfg.secret_access_key)
        url = _uri_encode(path, False)
        if query:
            url += "?" + "&".join(f"{_uri_encode(k, True)}={_uri_encode(v, True)}" for k, v in sorted(query.items()))
        return url, signed

    @staticmethod
    def _error(status: int, data: bytes) -> str:
        try:
            root = ET.fromstring(data)
            code = root.findtext("Code") or root.findtext(f"{_S3_NS}Code") or ""
            return f"HTTP {status} {code}".strip()
        except ET.ParseError:
            return f"HTTP {status}"

    def _simple(self, method: str, key: str | None, query: dict[str, str] | None = None) -> tuple[int, bytes]:
        url, headers = self._signed(method, key, query or {}, hashlib.sha256(b"").hexdigest())
        conn = self._conn()
        try:
            conn.request(method, url, headers=headers)
            resp = conn.getresponse()
            return resp.status, resp.read(16 * 1024 * 1024)
        finally:
            conn.close()

    # ------------------------------------------------------------------ operations
    def put_file(self, key: str, path: str | Path, content_type: str = "application/octet-stream") -> None:
        path = Path(path)
        size = path.stat().st_size
        if size > MAX_OBJECT_BYTES:
            raise S3StoreError("backup larger than 5 GB: a single S3 PUT cannot hold it")
        digest = _sha256_file(path)
        url, headers = self._signed("PUT", key, {}, digest, {"Content-Type": content_type,
                                                             "Content-Length": str(size)})
        conn = self._conn()
        try:
            with open(path, "rb") as fh:
                conn.request("PUT", url, body=fh, headers=headers)
                resp = conn.getresponse()
                body = resp.read(65536)
        finally:
            conn.close()
        if resp.status != 200:
            raise S3StoreError(f"PUT {key}: {self._error(resp.status, body)}")

    def head(self, key: str) -> int | None:
        url, headers = self._signed("HEAD", key, {}, hashlib.sha256(b"").hexdigest())
        conn = self._conn()
        try:
            conn.request("HEAD", url, headers=headers)
            resp = conn.getresponse()
            resp.read()
            if resp.status == 404:
                return None
            if resp.status != 200:
                raise S3StoreError(f"HEAD {key}: HTTP {resp.status}")
            return int(resp.getheader("Content-Length") or 0)
        finally:
            conn.close()

    def get_to_file(self, key: str, path: str | Path) -> int:
        url, headers = self._signed("GET", key, {}, hashlib.sha256(b"").hexdigest())
        conn = self._conn()
        try:
            conn.request("GET", url, headers=headers)
            resp = conn.getresponse()
            if resp.status != 200:
                raise S3StoreError(f"GET {key}: {self._error(resp.status, resp.read(65536))}")
            total = 0
            with open(path, "wb") as fh:
                for block in iter(lambda: resp.read(1 << 20), b""):
                    fh.write(block)
                    total += len(block)
            return total
        finally:
            conn.close()

    def list(self, prefix: str) -> list[S3Object]:
        out: list[S3Object] = []
        token: str | None = None
        while True:
            query = {"list-type": "2", "prefix": prefix}
            if token:
                query["continuation-token"] = token
            status, body = self._simple("GET", None, query)
            if status != 200:
                raise S3StoreError(f"LIST {prefix}: {self._error(status, body)}")
            root = ET.fromstring(body)
            for c in root.iter(f"{_S3_NS}Contents"):
                out.append(S3Object(c.findtext(f"{_S3_NS}Key") or "", int(c.findtext(f"{_S3_NS}Size") or 0),
                                    c.findtext(f"{_S3_NS}LastModified") or ""))
            if (root.findtext(f"{_S3_NS}IsTruncated") or "false") != "true":
                return out
            token = root.findtext(f"{_S3_NS}NextContinuationToken")

    def delete(self, key: str) -> None:
        status, body = self._simple("DELETE", key)
        if status not in (200, 204):
            raise S3StoreError(f"DELETE {key}: {self._error(status, body)}")
