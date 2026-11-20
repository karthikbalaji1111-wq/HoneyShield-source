"""Serve decoys on the operator's own path prefixes (app/core/decoy_paths.py).

The ingest routes are declared once on their original prefixes (/t/, /px/, /collect/). This
middleware maps a configured prefix onto the original route before routing, keeping the path the
visitor actually requested in ``scope["hs_decoy_path"]`` so that is what gets recorded. With
DECOY_LEGACY_PATHS=false the original prefixes are no longer served (404), unless they are
themselves the configured ones.
"""
from __future__ import annotations

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from app.core import decoy_paths
from app.core.config import get_settings


class DecoyPathMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        settings = get_settings()
        path = scope.get("path", "")
        configured = {"link": settings.decoy_link_path, "pixel": settings.decoy_pixel_path,
                      "collect": settings.decoy_collect_path}
        for kind, prefix in configured.items():
            lead = f"/{prefix}/"
            legacy = f"/{decoy_paths.LEGACY[kind]}/"
            if lead != legacy and path.startswith(lead):
                scope = dict(scope)
                scope["hs_decoy_path"] = path
                scope["path"] = legacy + path[len(lead):]
                scope["raw_path"] = scope["path"].encode("latin-1", "replace")
                break
        else:
            if not settings.decoy_legacy_paths:
                for kind, prefix in configured.items():
                    legacy = f"/{decoy_paths.LEGACY[kind]}/"
                    if prefix != decoy_paths.LEGACY[kind] and path.startswith(legacy):
                        await JSONResponse({"detail": "Not Found"}, status_code=404)(scope, receive, send)
                        return
        await self.app(scope, receive, send)
