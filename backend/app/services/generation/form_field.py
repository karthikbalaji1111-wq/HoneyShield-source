"""Honeypot form-field generator.

The field is rendered EMPTY and kept off-screen. People never see or fill it; form-filling
bots usually do. The customer's form handler checks it server-side and, when it is
non-empty, reports the decoy through the CUSTOMER_HOOK integration
(docs/customer-integrations.md). A legitimate submission leaves it empty and reports nothing.

Nothing secret is embedded in the page: the token value is an internal identifier only.
"""
from __future__ import annotations

import re
import secrets
from typing import Any, Mapping

from app.core.exceptions import ValidationError
from app.schemas.generation import GeneratedTokenData
from app.services.generation.base import BaseGenerator

#: Names that automated form fillers tend to complete. Not security-looking names
#: (csrf_token etc.): those are skipped by bots and confuse real CSRF handling.
HONEYPOT_FIELD_NAMES = ("website", "homepage", "company_url", "fax_number", "middle_initial", "referral_code")
_FIELD_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")

FORM_FIELD_DETECTION = {
    "status": "CUSTOMER_HOOK",
    "rule": "Report the decoy when the submitted value of field_name is non-empty.",
    "docs": "docs/customer-integrations.md",
}


class FormFieldGenerator(BaseGenerator):
    """Generates an empty, visually hidden honeypot input."""

    def generate(
        self,
        project_domain: str,
        params: dict[str, Any],
        ingest_base_url: str | None = None,
        paths: Mapping[str, str] | None = None,
        dns_zone: str | None = None,
    ) -> GeneratedTokenData:
        field_name = params.get("field_name") or secrets.choice(HONEYPOT_FIELD_NAMES)
        if not isinstance(field_name, str) or not _FIELD_NAME_RE.match(field_name):
            raise ValidationError("field_name must be 1-64 characters: a letter, then letters, digits, '_' or '-'")
        element_id = f"{field_name}-{secrets.token_hex(3)}"
        token_value = f"ff_{secrets.token_hex(16)}"
        html = (
            '<div style="position:absolute;left:-10000px;top:auto;width:1px;height:1px;overflow:hidden" '
            'aria-hidden="true">'
            f'<label for="{element_id}">Leave this field empty</label>'
            f'<input type="text" id="{element_id}" name="{field_name}" value="" tabindex="-1" autocomplete="off" />'
            "</div>"
        )
        return GeneratedTokenData(
            token_value=token_value,
            label=f"Honeypot Form Field: {field_name}",
            metadata={
                "field_name": field_name,
                "html_snippet": html,
                "detection": dict(FORM_FIELD_DETECTION),
                "placement_guidance": (
                    "Insert inside each protected <form>. Do not pre-fill it, do not mark it required, "
                    "and keep it out of client-side validation. Browser autofill can occasionally fill "
                    "it; such events are rare and should be triaged as MEDIUM."
                ),
                "domain_context": project_domain,
            },
        )
