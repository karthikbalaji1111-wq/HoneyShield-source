"""Decoy HTML link generator strategy."""
from __future__ import annotations

import secrets
from typing import Any, Mapping

from app.schemas.generation import GeneratedTokenData
from app.services.generation.base import BaseGenerator, build_ingest_url, decoy_path


class LinkGenerator(BaseGenerator):
    """Generates realistic decoy hyperlinks to be embedded in HTML comments or hidden elements."""

    def generate(
        self,
        project_domain: str,
        params: dict[str, Any],
        ingest_base_url: str | None = None,
        paths: Mapping[str, str] | None = None,
    ) -> GeneratedTokenData:
        link_types = [
            ("employee-portal", "Employee Portal"),
            ("staging-env", "Staging Environment"),
            ("internal-docs", "Internal Documentation"),
            ("vpn-gateway", "Corporate VPN Gateway"),
            ("legacy-access", "Legacy Admin Access"),
        ]
        prefix, desc = secrets.choice(link_types)
        random_suffix = secrets.token_hex(8)
        token_value = f"link-{prefix}-{random_suffix}"
        path = f"/{decoy_path(paths, 'link')}/{token_value}"
        url = build_ingest_url(ingest_base_url, path)

        return GeneratedTokenData(
            token_value=token_value,
            label=f"Decoy Link: {desc}",
            metadata={
                "path": path,
                "url": url,
                "html_tag": f'<a href="{url}" style="display:none;" aria-hidden="true" rel="nofollow">{desc}</a>',
                "domain_context": project_domain,
            },
        )
