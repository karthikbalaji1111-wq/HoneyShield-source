"""Masking of honey-token values for viewers who do not deploy decoys (HONEY-015).

A token value is a live secret: anyone who knows it can trigger (or deliberately avoid) the
decoy. TENANT_USER viewers investigate events but never need the value, so it is masked
everywhere it appears for them (token value, artifact metadata, request paths). Live stream
payloads are masked for everyone because they fan out to all of a tenant's viewers.
"""
from __future__ import annotations

from typing import Any

from app.models.enums import Role


def mask(value: str) -> str:
    return "****" + value[-4:] if len(value) > 8 else "****"


def redact(obj: Any, secret: str, replacement: str | None = None) -> Any:
    if not secret:
        return obj
    replacement = replacement if replacement is not None else mask(secret)
    if isinstance(obj, str):
        return obj.replace(secret, replacement)
    if isinstance(obj, dict):
        return {k: redact(v, secret, replacement) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v, secret, replacement) for v in obj]
    return obj


def viewer_sees_secrets(user: Any) -> bool:
    return getattr(user, "role", None) in (Role.SYSTEM_ADMIN, Role.TENANT_ADMIN)
