"""A tiny stand-in for the AWS APIs the cloud canaries use (IAM, STS, CloudTrail LookupEvents).

Real HTTP on localhost, so the client's signing, encoding and error handling run unchanged. It
checks each request is SigV4-signed for the right service and region, keeps IAM users in memory and
serves CloudTrail events that tests add with ``add_event``.
"""
from __future__ import annotations

import json
import threading
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

IAM_NS = "https://iam.amazonaws.com/doc/2010-05-08/"


class FakeAws:
    def __init__(self) -> None:
        self.account = "123456789012"
        self.users: dict[str, dict] = {}
        self.events: dict[tuple[str, str], list[dict]] = {}   # (region, key id) -> events
        self.fail: dict[str, tuple[int, str]] = {}            # action -> (status, code)
        self.region_fail: dict[str, tuple[int, str]] = {}     # region -> (status, code)
        self.calls: list[tuple[str, str, str]] = []           # (service, region, action)
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}"
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def add_event(self, region: str, key_id: str, name: str = "GetCallerIdentity", source: str = "sts.amazonaws.com",
                  ip: str = "203.0.113.77", agent: str = "aws-cli/2.17.0", error: str | None = "AccessDenied",
                  when: float | None = None) -> str:
        import time
        event_id = str(uuid.uuid4())
        detail = {"eventVersion": "1.10", "eventName": name, "eventSource": source, "awsRegion": region,
                  "sourceIPAddress": ip, "userAgent": agent, "userIdentity": {"accessKeyId": key_id}}
        if error:
            detail["errorCode"] = error
        self.events.setdefault((region, key_id), []).append({
            "EventId": event_id, "EventName": name, "ReadOnly": "true", "AccessKeyId": key_id,
            "EventTime": when or time.time() - 120, "EventSource": source, "CloudTrailEvent": json.dumps(detail)})
        return event_id

    # ------------------------------------------------------------------ HTTP
    def _handler(self):
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # quiet
                return

            def _reply(self, status: int, body: bytes, ctype: str) -> None:
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                auth = self.headers.get("Authorization", "")
                if not auth.startswith("AWS4-HMAC-SHA256 Credential=AKIDTEST/") or "Signature=" not in auth:
                    return self._reply(403, b'{"__type":"MissingAuthenticationTokenException"}', "application/json")
                scope = auth.split("Credential=AKIDTEST/", 1)[1].split(",", 1)[0].split("/")
                region, service = scope[1], scope[2]
                target = self.headers.get("X-Amz-Target")
                if target:
                    return fake._cloudtrail(self, region, service, target, body)
                return fake._query(self, region, service, dict(urllib.parse.parse_qsl(body.decode())))

        return Handler

    def _xml(self, h, action: str, inner: str, status: int = 200) -> None:
        doc = f'<{action}Response xmlns="{IAM_NS}"><{action}Result>{inner}</{action}Result></{action}Response>'
        h._reply(status, doc.encode(), "text/xml")

    def _error(self, h, status: int, code: str) -> None:
        doc = f'<ErrorResponse xmlns="{IAM_NS}"><Error><Code>{code}</Code><Message>{code} (fake)</Message></Error></ErrorResponse>'
        h._reply(status, doc.encode(), "text/xml")

    def _query(self, h, region: str, service: str, form: dict) -> None:
        action = form.get("Action", "")
        self.calls.append((service, region, action))
        assert region == "us-east-1" and service in ("iam", "sts")
        if action in self.fail:
            status, code = self.fail[action]
            return self._error(h, status, code)
        name = form.get("UserName", "")
        user = self.users.get(name)
        if action == "GetCallerIdentity":
            return self._xml(h, action, f"<Account>{self.account}</Account><Arn>arn:aws:iam::{self.account}:user/hs</Arn>")
        if action == "CreateUser":
            if user:
                return self._error(h, 409, "EntityAlreadyExists")
            tags = {form[k]: form[k.replace(".Key", ".Value")] for k in form if k.endswith(".Key")}
            self.users[name] = {"path": form["Path"], "tags": tags, "policies": {}, "keys": [],
                                "boundary": form.get("PermissionsBoundary")}
            return self._xml(h, action, f"<User><Arn>arn:aws:iam::{self.account}:user{form['Path']}{name}</Arn></User>")
        if user is None:
            return self._error(h, 404, "NoSuchEntity")
        if action == "ListUserTags":
            members = "".join(f"<member><Key>{k}</Key><Value>{v}</Value></member>" for k, v in user["tags"].items())
            return self._xml(h, action, f"<Tags>{members}</Tags>")
        if action == "PutUserPolicy":
            user["policies"][form["PolicyName"]] = json.loads(form["PolicyDocument"])
            return self._xml(h, action, "")
        if action == "CreateAccessKey":
            key_id = "AKIA" + uuid.uuid4().hex[:16].upper()
            user["keys"].append(key_id)
            return self._xml(h, action, f"<AccessKey><UserName>{name}</UserName><AccessKeyId>{key_id}</AccessKeyId>"
                                        f"<Status>Active</Status><SecretAccessKey>s3cr3t{key_id[-6:]}</SecretAccessKey></AccessKey>")
        if action == "ListAccessKeys":
            members = "".join(f"<member><AccessKeyId>{k}</AccessKeyId></member>" for k in user["keys"])
            return self._xml(h, action, f"<AccessKeyMetadata>{members}</AccessKeyMetadata>")
        if action == "DeleteAccessKey":
            user["keys"].remove(form["AccessKeyId"])
            return self._xml(h, action, "")
        if action == "DeleteUserPolicy":
            if form["PolicyName"] not in user["policies"]:
                return self._error(h, 404, "NoSuchEntity")
            del user["policies"][form["PolicyName"]]
            return self._xml(h, action, "")
        if action == "DeleteUser":
            if user["keys"] or user["policies"]:
                return self._error(h, 409, "DeleteConflict")
            del self.users[name]
            return self._xml(h, action, "")
        return self._error(h, 400, "InvalidAction")

    def _cloudtrail(self, h, region: str, service: str, target: str, body: bytes) -> None:
        self.calls.append((service, region, "LookupEvents"))
        assert service == "cloudtrail"
        assert target == "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents"
        assert h.headers.get("Content-Type") == "application/x-amz-json-1.1"
        if region in self.region_fail:
            status, code = self.region_fail[region]
            return h._reply(status, json.dumps({"__type": f"com.amazonaws#{code}", "message": "fake"}).encode(),
                            "application/x-amz-json-1.1")
        req = json.loads(body)
        [attr] = req["LookupAttributes"]
        assert attr["AttributeKey"] == "AccessKeyId"
        events = [e for e in self.events.get((region, attr["AttributeValue"]), [])
                  if req["StartTime"] <= e["EventTime"] <= req["EndTime"]]
        start = int(req.get("NextToken") or 0)
        page = events[start:start + req["MaxResults"]]
        out = {"Events": page}
        if start + req["MaxResults"] < len(events):
            out["NextToken"] = str(start + req["MaxResults"])
        h._reply(200, json.dumps(out).encode(), "application/x-amz-json-1.1")
