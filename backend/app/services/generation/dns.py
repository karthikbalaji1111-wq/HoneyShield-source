"""DNS decoy generator: a host name that reports every lookup.

The name is <token>.<zone>, where the zone is delegated to HoneyShield's name server. Whoever looks
it up (a person, a script, a scanner following a config file) reaches that server through their
resolver, and the query is recorded. Nothing has to be installed where the name is planted, and DNS
gets out of most networks that block everything else.
"""
from __future__ import annotations

from typing import Any, Mapping

from app.core.dns_tokens import new_token_label
from app.core.exceptions import ValidationError
from app.schemas.generation import GeneratedTokenData
from app.services.generation.base import BaseGenerator

DNS_DETECTION = {
    "status": "PUBLIC_INGEST",
    "rule": "Any DNS lookup of the host name, or of any name ending in it, is recorded.",
    "shows": "The resolver that asked (the user's, their ISP's or a public one), sometimes the "
             "user's network (EDNS client subnet), the query type and the time.",
    "not_detected": "Copies that are never resolved; lookups answered from a resolver's cache within "
                    "the record's TTL.",
    "docs": "docs/dns-tokens.md",
}


class DnsGenerator(BaseGenerator):
    def generate(
        self,
        project_domain: str,
        params: dict[str, Any],
        ingest_base_url: str | None = None,
        paths: Mapping[str, str] | None = None,
        dns_zone: str | None = None,
    ) -> GeneratedTokenData:
        if not dns_zone:
            raise ValidationError("DNS decoys need DNS_TOKEN_ZONE: a zone delegated to the HoneyShield "
                                  "name server (docs/dns-tokens.md)")
        token_value = new_token_label()
        hostname = f"{token_value}.{dns_zone}"
        return GeneratedTokenData(
            token_value=token_value,
            label="DNS host name",
            metadata={
                "hostname": hostname,
                "zone": dns_zone,
                # Anything in front of the name is recorded too, so one decoy can say where it fired.
                "tagged_example": f"$(hostname).{hostname}",
                "examples": {
                    "config": f"DB_HOST={hostname}",
                    "ssh": f"Host backup\n    HostName {hostname}\n    User deploy",
                    "url": f"https://{hostname}/",
                },
                "domain_context": project_domain,
                "detection": dict(DNS_DETECTION),
            },
        )
