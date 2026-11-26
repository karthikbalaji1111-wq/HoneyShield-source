"""Fake API key generator strategy."""
from __future__ import annotations

import secrets
import string
from typing import Any, Mapping

from app.schemas.generation import GeneratedTokenData
from app.services.generation.base import BaseGenerator


#: A decoy key is presented to the *customer's* systems, which HoneyShield cannot observe.
#: Detection therefore requires the customer's authentication middleware to report a match
#: through a signed CUSTOMER_HOOK integration (docs/customer-integrations.md). Use against
#: third-party APIs is NOT detectable.
API_KEY_DETECTION_STATUS = {
    "status": "CUSTOMER_HOOK",
    "rule": "Report the decoy when the SHA-256 of a presented credential matches the manifest entry. "
            "Never send the presented credential.",
    "requires": "An integration credential and the reference middleware or an equivalent.",
    "not_detected": "Use of the key against third-party services; keys copied but never used.",
    "docs": "docs/customer-integrations.md",
}


class ApiKeyGenerator(BaseGenerator):
    """Generates realistic high-entropy API keys.

    ``ingest_base_url`` is accepted for signature compatibility with the other
    generators but is deliberately unused: no HoneyShield-hosted URL can observe
    use of a decoy key, so no ingest URL is embedded. Detection is via CUSTOMER_HOOK.
    """

    def generate(
        self,
        project_domain: str,
        params: dict[str, Any],
        ingest_base_url: str | None = None,
        paths: Mapping[str, str] | None = None,
        dns_zone: str | None = None,
    ) -> GeneratedTokenData:
        provider = params.get("provider_style", "generic").lower()
        
        # 32 characters of randomness encoded in base62-ish characters
        alphabet = string.ascii_letters + string.digits
        random_suffix = "".join(secrets.choice(alphabet) for _ in range(32))
        
        if provider == "stripe":
            prefix = secrets.choice(["sk_live_", "sk_test_"])
            token_value = f"{prefix}{random_suffix}"
            label = "Stripe API Key"
        elif provider == "openai":
            prefix = "sk-"
            token_value = f"{prefix}{random_suffix}"
            label = "OpenAI API Key"
        else:
            prefix = secrets.choice(["ak_", "key_", "prod_", "live_"])
            token_value = f"{prefix}{random_suffix}"
            label = "Generic API Key"

        return GeneratedTokenData(
            token_value=token_value,
            label=label,
            metadata={
                "provider_style": provider,
                "entropy_bytes": 32,
                "detection": dict(API_KEY_DETECTION_STATUS),
            },
        )
