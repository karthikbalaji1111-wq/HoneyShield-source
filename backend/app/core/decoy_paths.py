"""Where decoys report: the URL path prefixes of the public ingest routes.

Out of the box decoy URLs look like ``https://<ingest host>/t/<token>``, ``/px/<token>.gif`` and
``/collect/<token>``. Those prefixes are the same in every HoneyShield installation, so an attacker
who knows the product can recognise a decoy by its URL and leave it alone. DECOY_LINK_PATH,
DECOY_PIXEL_PATH and DECOY_COLLECT_PATH replace them with paths of the operator's choosing (for
example ``static/v2``, ``assets/img`` and ``telemetry/v1``); together with an ingest host name that
fits the company (``cdn.example.com`` rather than ``honeyshield.example.com``) nothing in a decoy
URL points to HoneyShield.

Decoys generated earlier keep working while DECOY_LEGACY_PATHS is true (the default). Once every
old decoy has been rotated, set it to false and the original prefixes stop answering.

The same values must reach the backend and the edge (nginx); docker-compose.yml and the Helm chart
pass them to both.
"""
from __future__ import annotations

import re

LEGACY = {"link": "t", "pixel": "px", "collect": "collect"}
INTEGRATIONS_PREFIX = "/integrations/v1/"

# Lower-case letters, digits and hyphens; one to three segments. No dots or other characters, so
# the values are safe inside nginx regular expressions and cannot form traversal or file names.
PATH_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,30}(/[a-z0-9][a-z0-9-]{0,30}){0,2}$")
RESERVED_FIRST_SEGMENTS = frozenset({
    "api", "auth", "internal", "integrations", "console", "docs", "redoc", "openapi", "health", "ready",
    "metrics", "well-known", "favicon",
})


def validate(link: str, pixel: str, collect: str, legacy: bool) -> None:
    """Raise ValueError unless the configured prefixes are well-formed and cannot shadow each other."""
    custom = {"DECOY_LINK_PATH": link, "DECOY_PIXEL_PATH": pixel, "DECOY_COLLECT_PATH": collect}
    for name, value in custom.items():
        if not PATH_RE.match(value):
            raise ValueError(f"{name} must be 1-3 path segments of lower-case letters, digits and hyphens "
                             f"(for example static/v2), without leading or trailing '/': {value!r}")
        if value.split("/", 1)[0] in RESERVED_FIRST_SEGMENTS:
            raise ValueError(f"{name} must not start with the reserved segment {value.split('/', 1)[0]!r}")
    active = [(name, value) for name, value in custom.items()]
    if legacy:
        configured = {"link": link, "pixel": pixel, "collect": collect}
        for kind, value in LEGACY.items():
            if configured[kind] != value:  # the original prefix stays served for this kind
                active.append((f"legacy /{value}/", value))
    for i, (name_a, a) in enumerate(active):
        for name_b, b in active[i + 1:]:
            sa, sb = a.split("/"), b.split("/")
            n = min(len(sa), len(sb))
            if sa[:n] == sb[:n]:
                raise ValueError(f"{name_a} ({a}) and {name_b} ({b}) overlap; every decoy path prefix must be "
                                 "distinct and none may contain another")


def prefixes(settings) -> dict[str, tuple[str, ...]]:
    """Active prefixes per kind, e.g. {"link": ("static/v2", "t"), ...} (configured one first)."""
    configured = {"link": settings.decoy_link_path, "pixel": settings.decoy_pixel_path,
                  "collect": settings.decoy_collect_path}
    out = {}
    for kind, value in configured.items():
        values = [value]
        if settings.decoy_legacy_paths and LEGACY[kind] != value:
            values.append(LEGACY[kind])
        out[kind] = tuple(values)
    return out


def ingest_prefixes(settings) -> tuple[str, ...]:
    """Every public ingest path prefix with slashes ("/t/", ...), integrations included."""
    out = [f"/{p}/" for values in prefixes(settings).values() for p in values]
    return tuple(out) + (INTEGRATIONS_PREFIX,)


def decoy_prefixes(settings) -> tuple[str, ...]:
    return tuple(f"/{p}/" for values in prefixes(settings).values() for p in values)


def link_path(settings, token: str) -> str:
    return f"/{settings.decoy_link_path}/{token}"


def pixel_path(settings, token: str) -> str:
    return f"/{settings.decoy_pixel_path}/{token}.gif"


def collect_path(settings, token: str) -> str:
    return f"/{settings.decoy_collect_path}/{token}"


def token_from_path(settings, path: str) -> str | None:
    """The token value in a decoy path, or None when the path is not a decoy route."""
    path = path.split("?", 1)[0]
    for kind, values in prefixes(settings).items():
        for prefix in values:
            lead = f"/{prefix}/"
            if path.startswith(lead):
                value = path[len(lead):]
                if not value or "/" in value:
                    return None
                if kind == "pixel":
                    if not value.endswith(".gif"):
                        return None
                    value = value[:-4]
                return value or None
    return None
