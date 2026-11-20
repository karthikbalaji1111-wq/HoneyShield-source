from __future__ import annotations

from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from app.middleware.body_size import RequestBodySizeMiddleware
from app.middleware.decoy_paths import DecoyPathMiddleware
from app.middleware.exception_handler import GlobalExceptionMiddleware
from app.middleware.host_routing import HostRoutingMiddleware
from app.middleware.rate_limit import ApiRateLimitMiddleware
from app.middleware.request_id import RequestIDMiddleware
from app.middleware.request_timing import RequestTimingMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware


def register_middlewares(app: FastAPI) -> None:
    """Register application middlewares in explicit pipeline order.

    Wrapping Order (Outermost to Innermost):
    1. RequestIDMiddleware: Assigns / extracts X-Request-ID header and logging token.
    1b. HostRoutingMiddleware: ingest host serves ingest routes only; control plane the rest.
    2. SecurityHeadersMiddleware: Enforces centralized HTTP response security headers (F-015).
    3. CORSMiddleware: Handles cross-origin requests, preflight OPTIONS, and CORS headers (F-014).
    4. RequestBodySizeMiddleware: Rejects oversized bodies before processing (F-010).
    5. ApiRateLimitMiddleware: Bounded admission control for API traffic (F-011).
    6. RequestTimingMiddleware: Computes execution latency and appends X-Process-Time-Ms.
    7. GlobalExceptionMiddleware: Catch-all fallback for uncaught internal server errors.
    8. DecoyPathMiddleware: maps DECOY_*_PATH prefixes onto the ingest routes.
    """
    settings = get_settings()

    app.add_middleware(DecoyPathMiddleware)
    app.add_middleware(GlobalExceptionMiddleware)
    app.add_middleware(RequestTimingMiddleware)
    app.add_middleware(ApiRateLimitMiddleware)
    app.add_middleware(RequestBodySizeMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allowed_origins,
        allow_methods=settings.cors_allow_methods,
        allow_headers=settings.cors_allow_headers,
        allow_credentials=settings.cors_allow_credentials,
        expose_headers=settings.cors_expose_headers,
        max_age=settings.cors_max_age,
    )
    app.add_middleware(SecurityHeadersMiddleware)
    # Inside RequestID so rejected requests are still correlated; outside everything else so
    # a control-plane path on the ingest host never reaches CORS, rate limits or routing.
    app.add_middleware(HostRoutingMiddleware)
    app.add_middleware(RequestIDMiddleware)
