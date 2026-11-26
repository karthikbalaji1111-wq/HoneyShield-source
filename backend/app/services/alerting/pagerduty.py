"""PagerDuty Events API v2: a decoy hit opens (or adds to) an incident.

Destination URL: ``pagerduty://<integration key>`` (US service region) or
``pagerduty+eu://<integration key>`` (EU). The integration key is the "Integration Key" of an
Events API v2 integration on a PagerDuty service. Delivery is an HTTPS POST to the Events API
through the webhook transport, so it gets the same SSRF checks, address pinning and retries.

Every event is a "trigger" with dedup_key ``honeyshield-<event id>``: a retried delivery adds to
the same alert instead of paging twice. PagerDuty answers 202; 400 (bad key or payload) is
permanent, 429 and 5xx are retried.
"""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass
from typing import Any

from app.services.alerting.webhook import UnsafeWebhookURL

ENDPOINTS = {
    "pagerduty": "https://events.pagerduty.com/v2/enqueue",
    "pagerduty+eu": "https://events.eu.pagerduty.com/v2/enqueue",
}
SEVERITY = {"CRITICAL": "critical", "HIGH": "error", "MEDIUM": "warning", "LOW": "info"}
_KEY = re.compile(r"^[A-Za-z0-9]{20,64}$")


@dataclass(frozen=True)
class PagerDutyTarget:
    endpoint: str
    routing_key: str


def parse_url(url: str) -> PagerDutyTarget:
    if len(url) > 256:
        raise UnsafeWebhookURL("URL too long")
    parts = urllib.parse.urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in ENDPOINTS:
        raise UnsafeWebhookURL("PagerDuty destinations use pagerduty://<integration key> "
                               "(or pagerduty+eu:// for the EU service region)")
    key = parts.netloc  # not .hostname, which lower-cases: integration keys are case-sensitive
    if parts.path not in ("", "/") or parts.query or parts.fragment or not _KEY.match(key):
        raise UnsafeWebhookURL("Invalid PagerDuty integration key (20-64 letters and digits)")
    return PagerDutyTarget(ENDPOINTS[scheme], key)


def event(data: dict[str, Any], routing_key: str) -> dict[str, Any]:
    """The Events API v2 body for one alert."""
    test = data.get("source") == "TEST"
    if test:
        summary = "HoneyShield test alert: this destination works. No decoy was triggered."
        dedup = f"honeyshield-test-{data.get('delivery_id')}"
    else:
        label = data.get("token_label") or data.get("decoy_id")
        summary = (f"HoneyShield {data['severity']}: {data['token_type']} decoy '{label}' in "
                   f"{data['project']} triggered from {data['ip_address']}")
        dedup = f"honeyshield-{data.get('event_id')}"
    details = {k: v for k, v in data.items() if k not in ("triggered_ms",)}
    if data.get("attack"):
        details["attack"] = ", ".join(f"{t['id']} {t['name']}" for t in data["attack"])
    return {
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": dedup,
        "client": "HoneyShield",
        "payload": {
            "summary": summary[:1024],
            "source": str(data.get("project") or "honeyshield")[:255],
            "severity": "info" if test else SEVERITY.get(data["severity"], "warning"),
            "timestamp": data.get("triggered_at"),
            "component": str(data.get("token_type") or "")[:255],
            "group": str(data.get("project") or "")[:255],
            "class": "honeytoken",
            "custom_details": details,
        },
    }
