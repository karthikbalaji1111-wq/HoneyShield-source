"""Tracking pixel generator strategy."""
from __future__ import annotations

import secrets
from typing import Any, Mapping

from app.schemas.generation import GeneratedTokenData
from app.services.generation.base import BaseGenerator, build_ingest_url, decoy_path


#: Where a pixel may be planted. Browsers fetch images even when hidden with CSS, so a
#: pixel embedded in a page or email that legitimate people view fires for every view.
PIXEL_INTENDED_PLACEMENT = ["decoy_document", "decoy_email"]
PIXEL_PLACEMENT_WARNING = (
    "Embed only in decoy documents or decoy emails that no legitimate person should open. "
    "Do not place on web pages or in real correspondence: every view loads the image and "
    "records a detection."
)


class TrackingPixelGenerator(BaseGenerator):
    """Generates tracking pixels for decoy documents and decoy emails.

    No web-page snippet is produced on purpose: CSS-hidden images are
    still fetched by browsers, so a page-embedded pixel triggers for every visitor.
    """

    def generate(
        self,
        project_domain: str,
        params: dict[str, Any],
        ingest_base_url: str | None = None,
        paths: Mapping[str, str] | None = None,
        dns_zone: str | None = None,
    ) -> GeneratedTokenData:
        # High-entropy random hex token identifying the pixel
        token_value = secrets.token_hex(16)
        pixel_path = f"/{decoy_path(paths, 'pixel')}/{token_value}.gif"
        pixel_url = build_ingest_url(ingest_base_url, pixel_path)

        return GeneratedTokenData(
            token_value=token_value,
            label="Tracking Pixel",
            metadata={
                "pixel_path": pixel_path,
                "pixel_url": pixel_url,
                # For HTML-capable decoy documents and decoy emails only.
                "embed_html": f'<img src="{pixel_url}" width="1" height="1" alt="" />',
                "intended_placement": list(PIXEL_INTENDED_PLACEMENT),
                "placement_warning": PIXEL_PLACEMENT_WARNING,
                "domain_context": project_domain,
            },
        )
