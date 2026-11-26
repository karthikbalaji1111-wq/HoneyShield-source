"""Separate the public ingest surface from the operator control plane.

When both PUBLIC_INGEST_BASE_URL and CONTROL_PLANE_HOSTNAMES are configured:

* on the ingest host only the decoy routes (``/t/``, ``/px/``, ``/collect/`` or the DECOY_*_PATH
  prefixes, app/core/decoy_paths.py) and ``/integrations/v1/`` exist;
  the API, docs, OpenAPI schema, health/readiness and streaming return 404;
* on a control-plane host those ingest routes return 404;
* any other Host returns 404 (Nginx already drops unknown hosts; this is defence in depth),
  except ``/metrics`` addressed to an IP literal (per-pod Prometheus scrape; token still required).

The response is a bare 404 so the ingest host reveals nothing about what else runs behind it.
Nginx enforces the same split at the edge (proxy/templates/default.conf.template).
"""
from __future__ import annotations

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from app.core.config import get_settings

_PROBE_PATHS = frozenset({"/health", "/ready", "/api/v1/health", "/api/v1/ready", "/metrics"})


def is_ingest_path(path: str, settings=None) -> bool:
    from app.core import decoy_paths
    return path.startswith(decoy_paths.ingest_prefixes(settings or get_settings()))


def _host(scope: Scope) -> str:
    for name, value in scope.get("headers", []):
        if name == b"host":
            host = value.decode("latin-1").strip().lower()
            if host.startswith("["):
                return host.split("]", 1)[0] + "]"
            return host.split(":", 1)[0].rstrip(".")
    return ""


def _is_ip_literal(host: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


class HostRoutingMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        settings = get_settings()
        path = scope.get("path", "")
        if settings.control_plane_allowed_cidrs and not await self._operator_address_allowed(
                scope, receive, send, settings, path):
            return
        if not settings.host_separation_enabled:
            await self.app(scope, receive, send)
            return
        host = _host(scope)
        ingest = is_ingest_path(path, settings)
        if path.startswith("/internal/"):
            # Service-to-service only (edge replay): never on a public host name, whatever the proxy
            # forwards. The endpoint also requires its own signature.
            allowed = host != settings.ingest_hostname and host not in settings.control_plane_hostnames
        elif host == settings.ingest_hostname:
            allowed = ingest
        elif host in settings.control_plane_hostnames:
            allowed = not ingest
        elif scope.get("path") == "/metrics" and _is_ip_literal(host):
            # Per-replica Prometheus scrape addressed to the pod IP (still needs METRICS_TOKEN).
            allowed = True
        else:
            allowed = False
        if allowed:
            await self.app(scope, receive, send)
            return
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 4404})
            return
        await JSONResponse({"detail": "Not Found"}, status_code=404)(scope, receive, send)

    @staticmethod
    async def _operator_address_allowed(scope: Scope, receive: Receive, send: Send, settings, path: str) -> bool:
        """CONTROL_PLANE_ALLOWED_CIDRS: refuse operator requests from other addresses (403).

        Applies to requests that came through the trusted edge for anything but the ingest host and
        the decoy/integration routes. Requests made directly to the backend come from inside the
        private network (health checks, internal services) and are not affected.
        """
        import ipaddress

        from starlette.datastructures import Headers

        from app.core.ip_trust import is_ip_in_trusted_proxies, resolve_client_ip
        peer = (scope.get("client") or ("", 0))[0]
        if peer in ("testclient", "localhost"):
            peer = "127.0.0.1"
        if not peer or not is_ip_in_trusted_proxies(peer, settings.trusted_proxies):
            return True
        host = _host(scope)
        if (settings.ingest_hostname and host == settings.ingest_hostname) or is_ingest_path(path, settings):
            return True
        if path in _PROBE_PATHS:  # orchestrator health probes; they reveal nothing and need no login
            return True
        client = resolve_client_ip(peer, Headers(scope=scope), settings.trusted_proxies)
        try:
            ip = ipaddress.ip_address(client)
        except ValueError:
            ip = None
        if ip is not None and any(ip in net for net in settings.control_plane_networks):
            return True
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 4403})
        else:
            await JSONResponse({"detail": "Forbidden"}, status_code=403)(scope, receive, send)
        return False
