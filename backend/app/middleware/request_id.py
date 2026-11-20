from __future__ import annotations

import re
import uuid

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from app.core.logging import reset_request_id, set_request_id

REQUEST_ID_HEADER = "X-Request-ID"
# HONEY-033: an inbound id is reflected in responses and written to every log line, so only a
# short opaque token is accepted (Nginx supplies a 32-hex $request_id); anything else is replaced.
_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{8,64}$")


class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        inbound = request.headers.get(REQUEST_ID_HEADER, "")
        request_id = inbound if _SAFE_REQUEST_ID.match(inbound) else str(uuid.uuid4())
        request.state.request_id = request_id
        token = set_request_id(request_id)

        try:
            response = await call_next(request)
        finally:
            reset_request_id(token)

        response.headers[REQUEST_ID_HEADER] = request_id
        return response
