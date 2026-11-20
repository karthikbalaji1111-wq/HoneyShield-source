from __future__ import annotations

import time

from fastapi import Request

from app.core import metrics
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

PROCESS_TIME_HEADER = "X-Process-Time-Ms"


class RequestTimingMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        start_time = time.perf_counter()
        response = await call_next(request)
        elapsed = time.perf_counter() - start_time
        process_time_ms = elapsed * 1000
        response.headers[PROCESS_TIME_HEADER] = f"{process_time_ms:.2f}"
        status_class = f"{response.status_code // 100}xx"
        metrics.inc("honeyshield_http_requests_total", status=status_class)
        metrics.inc("honeyshield_http_request_duration_seconds_sum", elapsed)
        metrics.inc("honeyshield_http_request_duration_seconds_count")
        return response
