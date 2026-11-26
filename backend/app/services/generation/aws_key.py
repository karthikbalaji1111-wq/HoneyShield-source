"""Cloud canary generator: a real AWS access key that can do nothing.

Generation only chooses the IAM user name (the decoy's value) and marks the decoy "provisioning".
The cloud-canary worker (app/workers/cloud_canary.py), which is the only component with AWS
credentials and internet access, then creates the user with a deny-all policy and its access key,
and from then on reads CloudTrail for any use of that key. Unlike a fake key, it works wherever an
attacker tries it: the AWS CLI, an SDK, a cloud console plugin, a key-validation script.
"""
from __future__ import annotations

import secrets
from typing import Any, Mapping

from app.schemas.generation import GeneratedTokenData
from app.services.generation.base import BaseGenerator

# Ordinary service-account names: the user name is part of the ARN an attacker sees.
USER_PREFIXES = ("svc-deploy", "ci-runner", "backup-sync", "s3-uploader", "terraform", "etl-loader",
                 "build-agent", "data-export", "log-shipper", "release-bot")

AWS_KEY_DETECTION = {
    "status": "CLOUD_AUDIT",
    "rule": "Any AWS API call signed with the key, allowed or (as always here) denied, is read from "
            "CloudTrail event history in the watched regions.",
    "shows": "Source address, user agent and API call as AWS recorded them.",
    "delay": "CloudTrail delivers events up to about 15 minutes after the call, plus the poll interval.",
    "not_detected": "Calls in regions that are not watched; the few AWS APIs CloudTrail does not log; "
                    "keys copied but never used.",
    "docs": "docs/cloud-canaries.md",
}


class AwsKeyGenerator(BaseGenerator):
    def generate(
        self,
        project_domain: str,
        params: dict[str, Any],
        ingest_base_url: str | None = None,
        paths: Mapping[str, str] | None = None,
        dns_zone: str | None = None,
    ) -> GeneratedTokenData:
        user = f"{secrets.choice(USER_PREFIXES)}-{secrets.token_hex(6)}"
        profile = str(params.get("profile_name") or "default")[:64]
        return GeneratedTokenData(
            token_value=user,
            label="AWS access key",
            metadata={
                "status": "provisioning",
                "iam_user": user,
                "profile_name": profile,
                "domain_context": project_domain,
                "detection": dict(AWS_KEY_DETECTION),
            },
        )
