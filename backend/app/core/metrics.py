"""Minimal thread-safe Prometheus counters (no external dependency).

Counters are process-local; with the single-worker deployment that is the whole service.
Durable state (outbox backlog, dead letters) is read from the database at scrape time.
"""
from __future__ import annotations

import threading
from collections import defaultdict

_lock = threading.Lock()
_counters: dict[tuple[str, tuple[tuple[str, str], ...]], float] = defaultdict(float)

HELP = {
    "honeyshield_ingest_requests_total": "Public ingestion requests by outcome.",
    "honeyshield_integration_reports_total": "Customer-hook requests by outcome.",
    "honeyshield_http_requests_total": "HTTP requests by status class.",
    "honeyshield_http_request_duration_seconds_sum": "Total request processing time.",
    "honeyshield_http_request_duration_seconds_count": "Requests timed.",
}


def inc(name: str, value: float = 1.0, **labels: str) -> None:
    key = (name, tuple(sorted(labels.items())))
    with _lock:
        _counters[key] += value


def snapshot() -> dict[tuple[str, tuple[tuple[str, str], ...]], float]:
    with _lock:
        return dict(_counters)


def reset() -> None:
    with _lock:
        _counters.clear()


def _fmt_labels(labels: tuple[tuple[str, str], ...]) -> str:
    if not labels:
        return ""
    inner = ",".join(f'{k}="{str(v).replace(chr(92), chr(92) * 2).replace(chr(34), chr(92) + chr(34))}"'
                     for k, v in labels)
    return "{" + inner + "}"


def render(extra: list[tuple[str, str, dict[str, str], float]]) -> str:
    """Prometheus text format. ``extra``: (name, type, labels, value) gauges computed at scrape."""
    lines: list[str] = []
    seen: set[str] = set()
    for (name, labels), value in sorted(snapshot().items()):
        if name not in seen:
            seen.add(name)
            lines.append(f"# HELP {name} {HELP.get(name, name)}")
            lines.append(f"# TYPE {name} counter")
        lines.append(f"{name}{_fmt_labels(labels)} {value:g}")
    for name, kind, labels, value in extra:
        if name not in seen:
            seen.add(name)
            lines.append(f"# TYPE {name} {kind}")
        lines.append(f"{name}{_fmt_labels(tuple(sorted(labels.items())))} {value:g}")
    return "\n".join(lines) + "\n"
