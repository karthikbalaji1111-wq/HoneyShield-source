"""THIRD-PARTY-NOTICES.md must name every runtime dependency and the image components.

HoneyShield is proprietary; the open-source code it redistributes needs its notice. A dependency
added to backend/requirements.txt (e.g. by Dependabot) fails this test until its licence has been
reviewed and listed.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
NOTICES = (ROOT / "THIRD-PARTY-NOTICES.md").read_text(encoding="utf-8")
LICENSE = (ROOT / "LICENSE").read_text(encoding="utf-8")


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def test_every_runtime_python_dependency_is_listed():
    reqs = [line.split("==")[0].strip() for line in (ROOT / "backend" / "requirements.txt").read_text().splitlines()
            if line.strip() and not line.lstrip().startswith("#")]
    assert len(reqs) > 20
    listed = {_norm(m) for m in re.findall(r"^\| ([A-Za-z0-9_.\-]+)(?: \(client\))? \|", NOTICES, re.M)}
    missing = sorted(r for r in reqs if _norm(r) not in listed)
    assert not missing, f"review the licence and add to THIRD-PARTY-NOTICES.md: {missing}"


def test_image_components_and_store_are_listed():
    compose = (ROOT / "docker-compose.yml").read_text()
    store = re.search(r"^\s+image: (valkey/valkey|redis):", compose, re.M)
    assert store and store.group(1) == "valkey/valkey", "the shared-state store must stay BSD-licensed Valkey"
    for component in ("Python 3.12", "nginx", "PostgreSQL", "Valkey"):
        assert component in NOTICES


def test_licence_is_proprietary_and_points_at_the_notices():
    assert "All rights reserved" in LICENSE and "THIRD-PARTY-NOTICES.md" in LICENSE
