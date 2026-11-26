"""Cloud canaries in AWS: create the decoy users and keys, read CloudTrail for their use, clean up.

Run only by the cloud-canary worker (app/workers/cloud_canary.py), the one component holding AWS
credentials. Stdlib only: requests are signed with the SigV4 code the S3 features already use.

Lifecycle of an AWS_KEY decoy (token_metadata["status"]):
  provisioning  generated in the console/API; the worker creates the IAM user under
                AWS_CANARY_IAM_PATH, tags it with the decoy id, attaches a deny-all inline policy
                and creates one access key
  active        the key exists; every use of it in a watched region becomes a CLOUD_AUDIT event
  failed        AWS refused provisioning (details in last_error); nothing to clean up but the user
  deleted       the decoy was revoked or rotated and its IAM user removed

The worker never touches an IAM user it did not create: before reusing or deleting one it checks
the decoy-id tag, and its IAM policy only reaches users under the canary path.
"""
from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import logging
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.core import metrics
from app.core import safexml as ET
from app.core import tls
from app.models.enums import EventSource, HoneyTokenType
from app.models.honey_token import HoneyToken
from app.services.worm import sigv4_headers

logger = logging.getLogger("honeyshield.cloud_canary")

#: Regions enabled in every AWS account (opt-in regions must be listed in AWS_CANARY_REGIONS).
DEFAULT_REGIONS = ("us-east-1", "us-east-2", "us-west-1", "us-west-2", "ca-central-1", "sa-east-1",
                   "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1",
                   "ap-south-1", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
                   "ap-southeast-1", "ap-southeast-2")
TAG_KEY = "honeyshield-decoy"
POLICY_NAME = "deny-all"
DENY_ALL = json.dumps({"Version": "2012-10-17",
                       "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}, separators=(",", ":"))
MAX_PROVISION_ATTEMPTS = 5
LOOKUP_INTERVAL = 0.55        # CloudTrail LookupEvents allows 2 requests per second per region
MAX_LOOKUP_PAGES = 20
MAX_EVENT_JSON = 100_000
STATUS_POLL = "cloud_canary_poll"
STATUS_WORKER = "cloud_canary_worker"
#: Context stored with a cloud event. Never accepted from an HTTP request (see header_security).
CLOUD_CONTEXT = frozenset({"aws-region", "aws-event-source", "aws-event-name", "aws-error-code",
                           "aws-read-only", "aws-source-address", "aws-event-id"})
#: Address stored when CloudTrail names a service instead of an address (the name goes in the context).
UNKNOWN_SOURCE = str(ipaddress.IPv4Address(0))
TRANSIENT = {"Throttling", "ThrottlingException", "RequestLimitExceeded", "ServiceUnavailable",
             "InternalFailure", "InternalError", "ServiceFailure", "RequestTimeout", "network"}


class AwsError(RuntimeError):
    def __init__(self, code: str, message: str = "", status: int = 0) -> None:
        super().__init__(f"{code}: {message}" if message else code)
        self.code, self.message, self.status = code, message, status

    @property
    def transient(self) -> bool:
        return self.code in TRANSIENT or self.status >= 500


class AwsClient:
    """The handful of IAM, STS and CloudTrail calls the canaries need."""

    def __init__(self, access_key_id: str, secret_access_key: str, endpoint_url: str | None = None,
                 timeout: float = 20.0) -> None:
        if not access_key_id or not secret_access_key:
            raise ValueError("AWS_CANARY_ACCESS_KEY_ID and AWS_CANARY_SECRET_ACCESS_KEY are required")
        self._ak, self._sk, self.timeout = access_key_id, secret_access_key, timeout
        self._override = urllib.parse.urlsplit(endpoint_url) if endpoint_url else None
        if self._override and self._override.scheme not in ("http", "https"):
            raise ValueError("AWS_CANARY_ENDPOINT_URL must be an http(s) URL")

    def _post(self, service: str, region: str, host: str, body: bytes, headers: dict[str, str]) -> tuple[int, bytes]:
        scheme, port = "https", 443
        if self._override:
            scheme, host = self._override.scheme, self._override.netloc
            port = self._override.port or (443 if scheme == "https" else 80)
        signed = sigv4_headers("POST", host, "/", {}, headers, hashlib.sha256(body).hexdigest(),
                               region, self._ak, self._sk, service=service)
        hostname = host.split(":")[0] if not host.startswith("[") else host[1:host.index("]")]
        conn = (http.client.HTTPSConnection(hostname, port, timeout=self.timeout, context=tls.client_context())
                if scheme == "https" else http.client.HTTPConnection(hostname, port, timeout=self.timeout))
        try:
            conn.request("POST", "/", body=body, headers={**signed, "Content-Length": str(len(body))})
            resp = conn.getresponse()
            return resp.status, resp.read(8 * 1024 * 1024)
        except (OSError, http.client.HTTPException) as exc:
            raise AwsError("network", str(exc)) from None
        finally:
            conn.close()

    # ------------------------------------------------------------------ query protocol (IAM, STS)
    def _query(self, service: str, version: str, action: str, params: dict[str, str]):
        host = f"{service}.amazonaws.com"
        body = urllib.parse.urlencode({"Action": action, "Version": version, **params}).encode()
        status, data = self._post(service, "us-east-1", host, body,
                                  {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"})
        try:
            root = ET.fromstring(data) if data else None
        except ET.ParseError:
            root = None
        if status != 200:
            code = (root.findtext(".//{*}Code") or root.findtext(".//Code")) if root is not None else None
            msg = (root.findtext(".//{*}Message") or root.findtext(".//Message") or "") if root is not None else ""
            raise AwsError(code or f"HTTP{status}", msg[:300], status)
        if root is None:
            raise AwsError("BadResponse", f"{action}: unreadable response", status)
        return root

    def caller_identity(self) -> dict[str, str]:
        root = self._query("sts", "2011-06-15", "GetCallerIdentity", {})
        return {"account": root.findtext(".//{*}Account") or "", "arn": root.findtext(".//{*}Arn") or ""}

    def _iam(self, action: str, params: dict[str, str]):
        return self._query("iam", "2010-05-08", action, params)

    def create_user(self, name: str, path: str, tags: dict[str, str], boundary: str | None = None) -> str:
        params = {"UserName": name, "Path": path}
        if boundary:
            params["PermissionsBoundary"] = boundary
        for i, (k, v) in enumerate(sorted(tags.items()), 1):
            params[f"Tags.member.{i}.Key"], params[f"Tags.member.{i}.Value"] = k, v
        return self._iam("CreateUser", params).findtext(".//{*}Arn") or ""

    def user_tags(self, name: str) -> dict[str, str]:
        root = self._iam("ListUserTags", {"UserName": name})
        return {m.findtext("{*}Key") or "": m.findtext("{*}Value") or "" for m in root.iter() if m.tag.endswith("member")}

    def put_deny_all(self, name: str) -> None:
        self._iam("PutUserPolicy", {"UserName": name, "PolicyName": POLICY_NAME, "PolicyDocument": DENY_ALL})

    def create_access_key(self, name: str) -> tuple[str, str]:
        root = self._iam("CreateAccessKey", {"UserName": name})
        key_id, secret = root.findtext(".//{*}AccessKeyId"), root.findtext(".//{*}SecretAccessKey")
        if not key_id or not secret:
            raise AwsError("BadResponse", "CreateAccessKey returned no key")
        return key_id, secret

    def access_keys(self, name: str) -> list[str]:
        root = self._iam("ListAccessKeys", {"UserName": name})
        return [e.text for e in root.iter() if e.tag.endswith("AccessKeyId") and e.text]

    def delete_access_key(self, name: str, key_id: str) -> None:
        self._iam("DeleteAccessKey", {"UserName": name, "AccessKeyId": key_id})

    def delete_user(self, name: str) -> None:
        """Remove the user and everything attached to it; parts that are already gone are skipped."""
        for key_id in self.access_keys(name):
            self.delete_access_key(name, key_id)
        for action, params in (("DeleteUserPolicy", {"UserName": name, "PolicyName": POLICY_NAME}),
                               ("DeleteUser", {"UserName": name})):
            try:
                self._iam(action, params)
            except AwsError as exc:
                if exc.code != "NoSuchEntity":
                    raise

    # ------------------------------------------------------------------ CloudTrail (JSON protocol)
    def lookup_events(self, region: str, access_key_id: str, start: datetime, end: datetime) -> list[dict]:
        out: list[dict] = []
        token = None
        for _ in range(MAX_LOOKUP_PAGES):
            payload: dict[str, Any] = {
                "LookupAttributes": [{"AttributeKey": "AccessKeyId", "AttributeValue": access_key_id}],
                "StartTime": int(start.timestamp()), "EndTime": int(end.timestamp()), "MaxResults": 50}
            if token:
                payload["NextToken"] = token
            status, data = self._post("cloudtrail", region, f"cloudtrail.{region}.amazonaws.com",
                                      json.dumps(payload).encode(), {
                                          "Content-Type": "application/x-amz-json-1.1",
                                          "X-Amz-Target": "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents"})
            try:
                body = json.loads(data or b"{}")
            except ValueError:
                body = {}
            if status != 200:
                code = str(body.get("__type") or f"HTTP{status}").rsplit("#", 1)[-1]
                raise AwsError(code, str(body.get("message") or body.get("Message") or "")[:300], status)
            out.extend(e for e in body.get("Events") or [] if isinstance(e, dict))
            token = body.get("NextToken")
            if not token:
                break
            time.sleep(LOOKUP_INTERVAL)
        return out


def regions(settings) -> list[str]:
    if settings.aws_canary_regions:
        return [r.strip() for r in settings.aws_canary_regions.split(",") if r.strip()]
    return list(DEFAULT_REGIONS)


def _now() -> datetime:
    return datetime.now(timezone.utc)


class CanaryManager:
    def __init__(self, session: Session, settings, client: AwsClient) -> None:
        self.session, self.settings, self.client = session, settings, client
        self.account: str | None = None
        self._noted_floods: set[tuple[str, int, int]] = set()

    # ------------------------------------------------------------------ helpers
    def _tokens(self) -> list[HoneyToken]:
        return self.session.query(HoneyToken).filter(HoneyToken.token_type == HoneyTokenType.AWS_KEY).all()

    def _save(self, token: HoneyToken, **changes: Any) -> None:
        token.token_metadata = {**(token.token_metadata or {}), **changes}
        self.session.commit()

    def _audit(self, token: HoneyToken, event_type: str, severity: str, message: str) -> None:
        from app.api.dependencies import get_audit_log_service
        get_audit_log_service(self.session, None).record_action(
            event_type=event_type, severity=severity, message=message, actor_source="cloud_canary",
            target_entity="honey_token", target_id=token.id, tenant_id=token.project.tenant_id,
            project_id=token.project_id)
        self.session.commit()

    def identify(self) -> dict[str, str]:
        ident = self.client.caller_identity()
        self.account = ident["account"]
        return ident

    # ------------------------------------------------------------------ provisioning and clean-up
    def reconcile(self) -> dict[str, int]:
        """Create keys for new decoys and delete the AWS side of revoked ones."""
        done = {"provisioned": 0, "deleted": 0, "failed": 0, "retry": 0}
        for token in self._tokens():
            meta = token.token_metadata or {}
            status = meta.get("status")
            try:
                if token.is_active and status == "provisioning":
                    self._provision(token)
                    done["provisioned"] += 1
                elif not token.is_active and status in ("active", "provisioning", "failed") and meta.get("user_created"):
                    self.client.delete_user(meta["iam_user"])
                    self._save(token, status="deleted", deleted_at=_now().isoformat(), secret_access_key=None)
                    self._audit(token, "CLOUD_CANARY_DELETED", "INFO",
                                f"Deleted the AWS user of revoked cloud canary {token.decoy_id}")
                    done["deleted"] += 1
                elif not token.is_active and status == "provisioning":
                    self._save(token, status="cancelled")
            except AwsError as exc:
                self.session.rollback()
                attempts = int(meta.get("attempts") or 0) + 1
                if token.is_active and status == "provisioning" and (exc.transient is False or attempts >= MAX_PROVISION_ATTEMPTS):
                    self._save(token, status="failed", last_error=str(exc)[:300], attempts=attempts)
                    self._audit(token, "CLOUD_CANARY_FAILED", "WARNING",
                                f"AWS refused to create cloud canary {token.decoy_id}: {str(exc)[:200]}")
                    done["failed"] += 1
                else:
                    self._save(token, last_error=str(exc)[:300], attempts=attempts)
                    done["retry"] += 1
                logger.warning("Cloud canary %s: %s", token.decoy_id, exc)
        return done

    def _provision(self, token: HoneyToken) -> None:
        meta = token.token_metadata or {}
        name, path = meta["iam_user"], self.settings.aws_canary_iam_path
        if not meta.get("user_created"):
            try:
                self.client.create_user(name, path, {TAG_KEY: token.decoy_id},
                                        self.settings.aws_canary_permissions_boundary)
            except AwsError as exc:
                if exc.code != "EntityAlreadyExists":
                    raise
                # Ours only if a previous attempt created it (the tag says so); never anyone else's.
                if self.client.user_tags(name).get(TAG_KEY) != token.decoy_id:
                    raise AwsError("NameInUse", f"an IAM user named {name} already exists") from None
            self._save(token, user_created=True)
        self.client.put_deny_all(name)
        for old in self.client.access_keys(name):  # left by an attempt that died before saving
            self.client.delete_access_key(name, old)
        key_id, secret = self.client.create_access_key(name)
        account = self.account or ""
        self._save(token, status="active", access_key_id=key_id, secret_access_key=secret, account_id=account,
                   iam_arn=f"arn:aws:iam::{account}:user{path}{name}", provisioned_at=_now().isoformat(),
                   last_error=None)
        self._audit(token, "CLOUD_CANARY_PROVISIONED", "INFO",
                    f"Created the AWS access key of cloud canary {token.decoy_id}")

    # ------------------------------------------------------------------ detection
    def poll(self) -> dict[str, Any]:
        """Read CloudTrail in every watched region for uses of active canary keys and record them."""
        from app.services.system_status import get_status, put_status

        keys = {}
        for token in self._tokens():
            meta = token.token_metadata or {}
            if token.is_active and meta.get("status") == "active" and meta.get("access_key_id"):
                keys[meta["access_key_id"]] = token
        row = get_status(self.session, STATUS_POLL)
        last = dict((row.value or {}).get("regions") or {}) if row else {}
        end = _now()
        lookback = timedelta(minutes=self.settings.aws_canary_lookback_minutes)
        watched = regions(self.settings)

        def region_events(region: str) -> tuple[str, list[tuple[str, dict]], str | None]:
            since = datetime.fromtimestamp(last[region], tz=timezone.utc) if region in last else end - timedelta(days=1)
            found: list[tuple[str, dict]] = []
            try:
                for key_id in keys:
                    found += [(key_id, e) for e in self.client.lookup_events(region, key_id, since - lookback, end)]
                    time.sleep(LOOKUP_INTERVAL)
                return region, found, None
            except AwsError as exc:
                return region, found, exc.code

        results = {"events": 0, "recorded": 0, "duplicates": 0, "suppressed": 0, "rejected": 0, "region_errors": {}}
        if keys:
            with ThreadPoolExecutor(max_workers=6) as pool:
                outcomes = list(pool.map(region_events, watched))
        else:
            outcomes = [(r, [], None) for r in watched]
        for region, found, error in outcomes:
            if error:
                results["region_errors"][region] = error
            else:
                last[region] = end.timestamp()
            for key_id, event in found:
                results["events"] += 1
                outcome = self._record(keys[key_id], event)
                results[outcome] += 1
                metrics.inc("honeyshield_cloud_canary_events_total", outcome=outcome)
        put_status(self.session, STATUS_POLL, {"regions": last})
        return results

    def _record(self, token: HoneyToken, event: dict) -> str:
        from app.api.dependencies import get_detection_event_service
        from app.core.exceptions import ValidationError
        from app.core.ip_trust import normalize_ip
        from app.services.detection_event import DuplicatePublicHitError

        event_id = str(event.get("EventId") or "")
        if not event_id or len(event_id) > 64:
            return "rejected"
        raw = event.get("CloudTrailEvent") or "{}"
        try:
            detail = json.loads(raw) if isinstance(raw, str) and len(raw) <= MAX_EVENT_JSON else {}
        except ValueError:
            detail = {}
        try:
            when = datetime.fromtimestamp(float(event.get("EventTime")), tz=timezone.utc)
        except (TypeError, ValueError):
            return "rejected"
        source = str(detail.get("sourceIPAddress") or "")
        try:
            ip = normalize_ip(source)
            source_note = None
        except ValueError:
            ip, source_note = UNKNOWN_SOURCE, source[:200] or None  # e.g. an AWS service name
        name = str(event.get("EventName") or detail.get("eventName") or "unknown")[:128]
        service_name = str(event.get("EventSource") or detail.get("eventSource") or "unknown")[:128]
        context = {"aws-region": detail.get("awsRegion"), "aws-event-source": service_name, "aws-event-name": name,
                   "aws-error-code": detail.get("errorCode"), "aws-read-only": event.get("ReadOnly"),
                   "aws-source-address": source_note, "aws-event-id": event_id}
        from app.models.detection_event import DetectionEvent
        if self.session.query(DetectionEvent.id).filter(
                DetectionEvent.source == EventSource.CLOUD_AUDIT, DetectionEvent.idempotency_key == event_id).first():
            return "duplicates"  # read again because every poll overlaps the previous one
        service = get_detection_event_service(self.session, None)
        minute = int(when.timestamp() // 60)
        cap = self.settings.ingestion_rate_limit_per_minute_token
        stored = service.event_repo.count_for_source_in_window(
            honey_token_id=token.id, ip_address=ip,
            start=datetime.fromtimestamp(minute * 60, tz=timezone.utc),
            end=datetime.fromtimestamp(minute * 60 + 60, tz=timezone.utc))
        if stored >= cap:
            if (ip, token.id, minute) not in self._noted_floods:
                if len(self._noted_floods) > 10_000:
                    self._noted_floods.clear()
                self._noted_floods.add((ip, token.id, minute))
                service.record_suppressed_hits(token, ip, cap)
            return "suppressed"
        try:
            service.record_public_hit(
                token=token, ip_address=ip, request_path=f"{service_name}/{name}", http_method="AWS",
                user_agent=str(detail.get("userAgent") or "")[:1024] or None,
                headers={k: v for k, v in context.items() if v is not None},
                request_id=event_id, triggered_at=when, allowed_headers=CLOUD_CONTEXT,
                source=EventSource.CLOUD_AUDIT)
            return "recorded"
        except DuplicatePublicHitError:
            return "duplicates"
        except ValidationError:
            return "rejected"
