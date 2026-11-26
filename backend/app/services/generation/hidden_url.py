"""Hidden URL generator strategy."""
from __future__ import annotations

import secrets
from typing import Any, Mapping

from app.schemas.generation import GeneratedTokenData
from app.services.generation.base import BaseGenerator, build_ingest_url, decoy_path


class HiddenUrlGenerator(BaseGenerator):
    """Generates realistic hidden administration and configuration paths."""

    def generate(
        self,
        project_domain: str,
        params: dict[str, Any],
        ingest_base_url: str | None = None,
        paths: Mapping[str, str] | None = None,
        dns_zone: str | None = None,
    ) -> GeneratedTokenData:
        slug_prefixes = [
            "admin-portal",
            "internal-console",
            "backup-archive",
            "debug-metrics",
            "private-api",
            "config-dump",
            "auth-session",
            "db-export",
        ]
        
        prefix = secrets.choice(slug_prefixes)
        random_suffix = secrets.token_hex(8)
        token_value = f"{prefix}-{random_suffix}"
        path = f"/{decoy_path(paths, 'link')}/{token_value}"
        url = build_ingest_url(ingest_base_url, path)

        return GeneratedTokenData(
            token_value=token_value,
            label=f"Hidden URL: {prefix}",
            metadata={
                "path": path,
                "url": url,
                "decoy_category": prefix.split("-")[0],
                "domain_context": project_domain,
            },
        )
