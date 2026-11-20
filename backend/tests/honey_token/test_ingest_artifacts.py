"""Delivered-artifact end-to-end tests (HONEY-003).

Each test generates a token through the API, takes the artifact HoneyShield
actually hands to the customer (URL, link href, pixel src, form collection URL),
and follows *that* - not a hand-built route - proving the interaction reaches
HoneyShield's ingestion endpoint and is persisted as a DetectionEvent.
"""
from __future__ import annotations

import re

import pytest
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.detection_event import DetectionEvent
from app.models.honey_token import HoneyToken
from app.models.project import Project
from app.models.user import User
from app.services.generation.base import build_ingest_url
from tests.conftest import auth_headers

INGEST_BASE = "https://ingest.honeyshield.test"


@pytest.fixture(autouse=True)
def ingest_base(monkeypatch):
    monkeypatch.setattr(get_settings(), "public_ingest_base_url", INGEST_BASE)


def _generate(client, admin: User, project: Project, token_type: str) -> dict:
    resp = client.post(
        f"/api/v1/projects/{project.domain}/honey-tokens/generate",
        json={"token_type": token_type},
        headers=auth_headers(admin),
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _follow(client, artifact_url: str, method: str):
    """Follow a delivered absolute artifact URL against the local ingestion app."""
    assert artifact_url.startswith(INGEST_BASE + "/"), artifact_url
    return client.request(method, artifact_url[len(INGEST_BASE):])


def _events(db_session: Session, token_value: str) -> list[DetectionEvent]:
    db_session.expire_all()
    token = db_session.query(HoneyToken).filter_by(token_value=token_value).one()
    return db_session.query(DetectionEvent).filter_by(honey_token_id=token.id).all()


def test_url_artifact_reaches_ingestion(client, db_session, admin_a, project_a):
    data = _generate(client, admin_a, project_a, "URL")
    url = data["metadata"]["url"]
    assert project_a.domain not in url
    assert _follow(client, url, "GET").status_code == 204
    events = _events(db_session, data["token_value"])
    assert len(events) == 1 and events[0].http_method == "GET"


def test_link_artifact_reaches_ingestion(client, db_session, admin_a, project_a):
    data = _generate(client, admin_a, project_a, "LINK")
    meta = data["metadata"]
    href = re.search(r'href="([^"]+)"', meta["html_tag"]).group(1)
    assert href == meta["url"]
    assert project_a.domain not in href
    assert _follow(client, href, "GET").status_code == 204
    assert len(_events(db_session, data["token_value"])) == 1


def test_pixel_artifact_reaches_ingestion(client, db_session, admin_a, project_a):
    data = _generate(client, admin_a, project_a, "PIXEL")
    meta = data["metadata"]
    # HONEY-004: no web-page snippet; the embed is for decoy documents and emails only.
    assert "html_tag" not in meta
    assert "display:none" not in meta["embed_html"]
    assert meta["intended_placement"] == ["decoy_document", "decoy_email"]
    assert meta["placement_warning"]
    src = re.search(r'src="([^"]+)"', meta["embed_html"]).group(1)
    assert src == meta["pixel_url"]
    assert project_a.domain not in src
    resp = _follow(client, src, "GET")
    assert resp.status_code == 200 and resp.headers["content-type"] == "image/gif"
    assert len(_events(db_session, data["token_value"])) == 1


def test_form_field_is_an_empty_honeypot_without_embedded_secrets(client, admin_a, project_a):
    """HONEY-004: no pre-filled fake CSRF value; detection is via CUSTOMER_HOOK.

    The end-to-end FORM_FIELD flow (bot fills the field, customer hook reports it, event
    stored) is in tests/integrations/test_customer_hook.py.
    """
    data = _generate(client, admin_a, project_a, "FORM_FIELD")
    meta = data["metadata"]
    html = meta["html_snippet"]
    assert 'value=""' in html
    assert data["token_value"] not in html
    assert re.search(r'name="([^"]+)"', html).group(1) == meta["field_name"]
    assert "csrf" not in meta["field_name"].lower()
    assert meta["detection"]["status"] == "CUSTOMER_HOOK"
    assert not any(k in meta for k in ("collection_url", "collection_path", "html_tag"))


def test_api_key_detection_is_via_customer_hook_only(client, admin_a, project_a):
    """API_KEY use is observed by customer code, never by a HoneyShield URL."""
    data = _generate(client, admin_a, project_a, "API_KEY")
    meta = data["metadata"]
    assert data["token_type"] == "API_KEY"
    assert data["decoy_id"].startswith("dcy_")
    assert meta["detection"]["status"] == "CUSTOMER_HOOK"
    assert "third-party" in meta["detection"]["not_detected"]
    assert not any(k in meta for k in ("url", "pixel_url", "collection_url", "collection_path"))
    assert INGEST_BASE not in str(meta)


def test_artifacts_are_host_less_when_ingest_base_unset(client, admin_a, project_a, monkeypatch):
    monkeypatch.setattr(get_settings(), "public_ingest_base_url", None)
    data = _generate(client, admin_a, project_a, "URL")
    # Never silently pointed at the customer's domain.
    assert data["metadata"]["url"] == data["metadata"]["path"]
    assert project_a.domain not in data["metadata"]["url"]


@pytest.mark.parametrize(
    "base, path, expected",
    [
        ("https://i.example", "/t/x", "https://i.example/t/x"),
        ("https://i.example/", "/t/x", "https://i.example/t/x"),
        (None, "/t/x", "/t/x"),
        ("", "/t/x", "/t/x"),
    ],
)
def test_build_ingest_url(base, path, expected):
    assert build_ingest_url(base, path) == expected
