"""Native SIEM ingestion: Splunk HTTP Event Collector and Microsoft Sentinel.

SPLUNK_HEC  url = ``splunk://<HEC token>@hec.example.com[:8088][?index=security]``
            One JSON event per alert, POSTed to ``https://<host>:<port>/services/collector/event``
            with ``Authorization: Splunk <token>``. Port 8088 is Splunk Enterprise's default; Splunk
            Cloud uses ``http-inputs-<stack>.splunkcloud.com`` on 443. sourcetype
            ``honeyshield:detection``; the index is the token's default unless ``index`` is given.
            A channel id (X-Splunk-Request-Channel) is always sent, so tokens with indexer
            acknowledgement accept the request too (HoneyShield does not wait for the ack).

SENTINEL    url = ``sentinel://<client id>:<client secret>@<ingestion host>/<DCR immutable id>/<stream>?tenant=<tenant>``
            Azure Monitor Logs Ingestion API, which is how Microsoft Sentinel takes custom data.
            HoneyShield gets a token for the Entra application (client credentials, scope
            https://monitor.azure.com//.default) and POSTs a one-record JSON array to
            ``https://<host>/dataCollectionRules/<dcr>/streams/<stream>?api-version=2023-01-01``.
            The host is the DCR's logs-ingestion endpoint (or a DCE's): ``*.ingest.monitor.azure.com``.
            Azure public cloud only. deploy/sentinel/ has the table and DCR template.

Both deliver through the webhook transport: SSRF checks, the connection pinned to the validated
address, TLS verified against the host name, no redirects.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
import time
import urllib.parse
import uuid
from dataclasses import dataclass
from typing import Any

from app.services.alerting import webhook
from app.services.alerting.webhook import UnsafeWebhookURL

# ----------------------------------------------------------------------------------- Splunk

SPLUNK_PORTS = frozenset({443, 8088, 8443})
SPLUNK_SOURCETYPE = "honeyshield:detection"
_GUID = re.compile(r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")
_SPLUNK_INDEX = re.compile(r"^[a-z0-9_][a-z0-9_-]{0,79}$")
_HOST = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")


@dataclass(frozen=True)
class SplunkTarget:
    host: str
    port: int
    token: str
    index: str | None

    @property
    def endpoint(self) -> str:
        return f"https://{self.host}:{self.port}/services/collector/event"


def parse_splunk(url: str) -> SplunkTarget:
    if len(url) > 2048:
        raise UnsafeWebhookURL("URL too long")
    parts = urllib.parse.urlsplit(url)
    if parts.scheme.lower() != "splunk":
        raise UnsafeWebhookURL("Splunk destinations use splunk://<HEC token>@<host>[:port][?index=<index>]")
    token = urllib.parse.unquote(parts.username or "")
    if parts.password is not None or not _GUID.match(token):
        raise UnsafeWebhookURL("Invalid HEC token: expected the token's GUID before the @")
    host = (parts.hostname or "").lower().rstrip(".")
    if not _HOST.match(host):
        raise UnsafeWebhookURL("Splunk URL needs a host name")
    try:
        port = parts.port or 8088
    except ValueError as exc:
        raise UnsafeWebhookURL("Invalid port") from exc
    if port not in SPLUNK_PORTS:
        raise UnsafeWebhookURL("Splunk HEC port must be 443, 8088 or 8443")
    if parts.path not in ("", "/") or parts.fragment:
        raise UnsafeWebhookURL("Splunk URL must be splunk://<token>@<host>[:port], with no path")
    query = urllib.parse.parse_qs(parts.query, keep_blank_values=True, strict_parsing=False)
    if set(query) - {"index"} or any(len(v) != 1 for v in query.values()):
        raise UnsafeWebhookURL("The only Splunk URL option is index=<index>")
    index = query.get("index", [None])[0]
    if index is not None and not _SPLUNK_INDEX.match(index):
        raise UnsafeWebhookURL("Invalid Splunk index name")
    return SplunkTarget(host, port, token, index)


def splunk_body(data: dict[str, Any], index: str | None, host: str) -> dict[str, Any]:
    event = {k: v for k, v in data.items() if k != "triggered_ms"}
    body: dict[str, Any] = {"time": round((data.get("triggered_ms") or time.time() * 1000) / 1000, 3),
                            "host": host, "source": "honeyshield", "sourcetype": SPLUNK_SOURCETYPE, "event": event}
    if index:
        body["index"] = index
    return body


def splunk_channel(destination_public_id: str) -> str:
    """A stable channel GUID per destination (required when the token has indexer acknowledgement)."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"honeyshield-alert-destination:{destination_public_id}"))


# --------------------------------------------------------------------------------- Sentinel

AZURE_LOGIN = "https://login.microsoftonline.com"
AZURE_SCOPE = "https://monitor.azure.com//.default"   # sic: the double slash is Microsoft's documented scope
INGESTION_SUFFIX = ".ingest.monitor.azure.com"
INGESTION_API_VERSION = "2023-01-01"
_DCR = re.compile(r"^dcr-[0-9a-f]{32}$")
_STREAM = re.compile(r"^Custom-[A-Za-z0-9_]{1,100}$")
_TENANT = re.compile(r"^(?:[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
                     r"|[a-z0-9-]{1,63}\.onmicrosoft\.com)$")
_SECRET = re.compile(r"^[\x21-\x7e]{8,256}$")


@dataclass(frozen=True)
class SentinelTarget:
    tenant: str
    client_id: str
    client_secret: str
    host: str
    dcr: str
    stream: str

    @property
    def endpoint(self) -> str:
        return (f"https://{self.host}/dataCollectionRules/{self.dcr}/streams/{self.stream}"
                f"?api-version={INGESTION_API_VERSION}")

    @property
    def token_endpoint(self) -> str:
        return f"{AZURE_LOGIN}/{self.tenant}/oauth2/v2.0/token"


def parse_sentinel(url: str) -> SentinelTarget:
    if len(url) > 2048:
        raise UnsafeWebhookURL("URL too long")
    parts = urllib.parse.urlsplit(url)
    if parts.scheme.lower() != "sentinel":
        raise UnsafeWebhookURL("Sentinel destinations use sentinel://<client id>:<client secret>@<ingestion host>"
                               "/<DCR immutable id>/<stream>?tenant=<tenant id>")
    client_id = urllib.parse.unquote(parts.username or "")
    secret = urllib.parse.unquote(parts.password or "")
    if not _GUID.match(client_id):
        raise UnsafeWebhookURL("Invalid application (client) id: expected a GUID")
    if not _SECRET.match(secret):
        raise UnsafeWebhookURL("Invalid client secret (percent-encode reserved characters such as @ : / ?)")
    host = (parts.hostname or "").lower().rstrip(".")
    if not _HOST.match(host) or not host.endswith(INGESTION_SUFFIX):
        raise UnsafeWebhookURL(f"The host must be the DCR's logs-ingestion endpoint (*{INGESTION_SUFFIX})")
    try:
        port = parts.port
    except ValueError as exc:
        raise UnsafeWebhookURL("Invalid port") from exc
    if port not in (None, 443):
        raise UnsafeWebhookURL("Sentinel ingestion uses port 443")
    segments = [s for s in parts.path.split("/") if s]
    if len(segments) != 2 or not _DCR.match(segments[0]) or not _STREAM.match(segments[1]):
        raise UnsafeWebhookURL("Path must be /<DCR immutable id (dcr-...)>/<stream (Custom-...)>")
    query = urllib.parse.parse_qs(parts.query, keep_blank_values=True)
    if set(query) != {"tenant"} or len(query["tenant"]) != 1 or not _TENANT.match(query["tenant"][0].lower()):
        raise UnsafeWebhookURL("Add ?tenant=<directory (tenant) id>")
    if parts.fragment:
        raise UnsafeWebhookURL("Sentinel URL must not contain a fragment")
    return SentinelTarget(query["tenant"][0].lower(), client_id.lower(), secret, host, segments[0], segments[1])


def sentinel_record(data: dict[str, Any]) -> dict[str, Any]:
    """One row of the HoneyShield_CL table (columns in deploy/sentinel/honeyshield-sentinel.json)."""
    attack = data.get("attack") or []
    return {
        "TimeGenerated": data.get("triggered_at"),
        "EventId": data.get("event_id"),
        "DeliveryId": data.get("delivery_id"),
        "Severity": data.get("severity"),
        "DetectionSource": data.get("source"),
        "TokenType": data.get("token_type"),
        "DecoyId": data.get("decoy_id"),
        "DecoyLabel": data.get("token_label"),
        "Project": data.get("project"),
        "SourceIp": data.get("ip_address"),
        "HttpMethod": data.get("http_method"),
        "RequestPath": data.get("request_path"),
        "AttackTechniques": ",".join(t["id"] for t in attack),
        "AttackTechniqueNames": "; ".join(f"{t['id']} {t['name']}" for t in attack),
    }


class TokenError(Exception):
    """Entra ID refused the application's credentials (permanent) or could not be reached."""

    def __init__(self, message: str, permanent: bool):
        super().__init__(message)
        self.permanent = permanent


class TokenCache:
    """Access tokens per application, reused until five minutes before they expire."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._tokens: dict[str, tuple[str, float]] = {}

    @staticmethod
    def _key(target: SentinelTarget) -> str:
        return hashlib.sha256(f"{target.tenant}|{target.client_id}|{target.client_secret}".encode()).hexdigest()

    def forget(self, target: SentinelTarget) -> None:
        with self._lock:
            self._tokens.pop(self._key(target), None)

    def get(self, target: SentinelTarget, requester: webhook.Requester, resolver: webhook.Resolver | None,
            timeout: float, allowed_private: tuple = (), now: float | None = None) -> str:
        now = now if now is not None else time.time()
        key = self._key(target)
        with self._lock:
            cached = self._tokens.get(key)
            if cached and cached[1] > now:
                return cached[0]
        login = webhook.validate_url(target.token_endpoint, resolver=resolver, allowed_private=allowed_private)
        form = urllib.parse.urlencode({"client_id": target.client_id, "client_secret": target.client_secret,
                                       "scope": AZURE_SCOPE, "grant_type": "client_credentials"}).encode()
        status, raw = requester(login, {"Content-Type": "application/x-www-form-urlencoded",
                                        "User-Agent": "HoneyShield-Alerts/1"}, form, timeout)
        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
        except (UnicodeDecodeError, ValueError):
            payload = {}
        if status != 200 or not isinstance(payload.get("access_token"), str):
            # AADSTS codes only: the response never echoes the secret, but keep the error short.
            code = str(payload.get("error") or f"HTTP {status}")[:64]
            permanent = status in (400, 401) and code in ("invalid_client", "unauthorized_client",
                                                          "invalid_request", "invalid_scope")
            raise TokenError(f"Entra ID token request failed: {code}", permanent)
        lifetime = float(payload.get("expires_in") or 3600)
        with self._lock:
            self._tokens[key] = (payload["access_token"], now + max(60.0, lifetime - 300))
        return payload["access_token"]


TOKENS = TokenCache()


# ------------------------------------------------------------------------------------- shared

def masked_url(url: str, fmt_value: str) -> str:
    """The destination URL with its secret replaced, for API responses and the console."""
    try:
        if fmt_value == "SPLUNK_HEC":
            t = parse_splunk(url)
            port = "" if t.port == 8088 else f":{t.port}"
            return f"splunk://****{t.token[-4:]}@{t.host}{port}" + (f"?index={t.index}" if t.index else "")
        if fmt_value == "SENTINEL":
            t = parse_sentinel(url)
            return f"sentinel://{t.client_id}:****@{t.host}/{t.dcr}/{t.stream}?tenant={t.tenant}"
    except UnsafeWebhookURL:
        return "(invalid)"
    return url
