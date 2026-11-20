"""Abstract base generator for honey token strategies."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Mapping

from app.schemas.generation import GeneratedTokenData


#: Default decoy path prefixes; DECOY_*_PATH settings replace them (app/core/decoy_paths.py).
DEFAULT_PATHS = {"link": "t", "pixel": "px", "collect": "collect"}


def decoy_path(paths: Mapping[str, str] | None, kind: str) -> str:
    """The configured prefix for ``kind`` ("link", "pixel" or "collect")."""
    return (paths or DEFAULT_PATHS).get(kind) or DEFAULT_PATHS[kind]


def build_ingest_url(ingest_base_url: str | None, path: str) -> str:
    """Return the externally reachable HoneyShield ingestion URL for ``path``.

    Deception assets must resolve to a HoneyShield-controlled host, never to the
    customer's own domain (which would never report the interaction). When no
    ingest base URL is configured the bare path is returned, which is explicit
    about being host-less instead of silently pointing at the wrong server.
    """
    if not ingest_base_url:
        return path
    return f"{ingest_base_url.rstrip('/')}{path}"


class BaseGenerator(ABC):
    """Abstract base class for all token generation strategies.

    Generators must remain completely pure. They should not access
    repositories, database sessions, settings, or framework specifics;
    environment-derived values such as the ingest base URL are passed in.
    """

    @abstractmethod
    def generate(
        self,
        project_domain: str,
        params: dict[str, Any],
        ingest_base_url: str | None = None,
        paths: Mapping[str, str] | None = None,
    ) -> GeneratedTokenData:
        """Generate a realistic deception asset.

        Args:
            project_domain: Domain of the owning project to contextualize the token.
            params: Strategy-specific parameters guiding generation.
            ingest_base_url: Public HoneyShield ingestion origin (for example
                ``https://ingest.example.com``) that delivered artifacts must target.
            paths: Decoy path prefixes by kind ({"link": "t", "pixel": "px", "collect": "collect"}
                unless the operator configured their own).

        Returns:
            A pure data transfer object containing the token and metadata.
        """
        pass
