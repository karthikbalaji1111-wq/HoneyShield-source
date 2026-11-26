"""Document decoy generator: a Word file that reports being opened.

Generation chooses the document (one of a few files intruders go looking for) and the pixel URL it
will load; the .docx itself is built on download (app/services/documents.py) from this metadata, so
the same decoy always yields the same file. Hits arrive on the ordinary pixel route and are
recorded against this decoy, with Word's own user agent.
"""
from __future__ import annotations

import secrets
from typing import Any, Mapping

from app.core.exceptions import ValidationError
from app.schemas.generation import GeneratedTokenData
from app.services.generation.base import BaseGenerator, build_ingest_url, decoy_path

# template id -> (title, file name)
TEMPLATES: dict[str, tuple[str, str]] = {
    "vpn_access": ("Contractor VPN access", "VPN access - contractors.docx"),
    "salary_review": ("Salary review - draft", "Salary review (draft).docx"),
    "server_inventory": ("Server inventory and admin accounts", "Server inventory.docx"),
    "board_minutes": ("Board meeting minutes - confidential", "Board minutes (confidential).docx"),
}

DOCUMENT_DETECTION = {
    "status": "PUBLIC_INGEST",
    "rule": "Opening the document in Microsoft Word loads a linked 1-pixel picture from the ingest "
            "host; that request is recorded.",
    "shows": "The opener's address (or their proxy's), Word's user agent and the time.",
    "not_detected": "Protected View (files marked as downloaded from the internet) until editing is "
                    "enabled; viewers that do not load linked pictures; machines with no route to the "
                    "ingest host.",
    "docs": "docs/document-decoys.md",
}


class DocumentGenerator(BaseGenerator):
    def generate(
        self,
        project_domain: str,
        params: dict[str, Any],
        ingest_base_url: str | None = None,
        paths: Mapping[str, str] | None = None,
        dns_zone: str | None = None,
    ) -> GeneratedTokenData:
        if not ingest_base_url:
            raise ValidationError("Document decoys need PUBLIC_INGEST_BASE_URL: the document must load "
                                  "its picture from a host that reaches HoneyShield")
        template = str(params.get("template") or secrets.choice(sorted(TEMPLATES)))
        if template not in TEMPLATES:
            raise ValidationError(f"Unknown document template '{template[:40]}' "
                                  f"(one of: {', '.join(sorted(TEMPLATES))})")
        title, filename = TEMPLATES[template]
        token_value = secrets.token_hex(16)
        pixel_path = f"/{decoy_path(paths, 'pixel')}/{token_value}.gif"
        return GeneratedTokenData(
            token_value=token_value,
            label="Word document",
            metadata={
                "template": template,
                "title": title,
                "filename": filename,
                "pixel_url": build_ingest_url(ingest_base_url, pixel_path),
                "domain_context": project_domain,
                "detection": dict(DOCUMENT_DETECTION),
            },
        )
