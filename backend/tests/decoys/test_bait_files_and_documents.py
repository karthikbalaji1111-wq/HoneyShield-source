"""Bait files and Word document decoys.

A document decoy is a .docx whose only active part is a linked 1x1 picture on the pixel route:
opening it in Word requests that URL, and the hit is recorded as a DOCUMENT event. Bait files put
a decoy inside the files intruders look for; only administrators can download them, every
download is audited, and the same decoy always yields the same file.
"""
from __future__ import annotations

import io
import re
import zipfile
from datetime import datetime, timezone

import pytest

from app.core.config import get_settings
from app.models.audit_log import AuditLog
from app.models.detection_event import DetectionEvent
from app.models.enums import EventSeverity, HoneyTokenType
from app.models.honey_token import HoneyToken
from app.services import documents
from tests.conftest import auth_headers

INGEST = "https://ingest.example.com"
ZONE = "dns.example.net"
WORD_UA = "Mozilla/4.0 (compatible; ms-office; MSOffice 16)"


@pytest.fixture(autouse=True)
def configured(monkeypatch):
    monkeypatch.setattr(get_settings(), "public_ingest_base_url", INGEST)
    monkeypatch.setattr(get_settings(), "dns_token_zone", ZONE)


def _generate(client, admin, project, token_type, **params):
    r = client.post(f"/api/v1/projects/{project.domain}/honey-tokens/generate",
                    json={"token_type": token_type, **({"generator_params": params} if params else {})},
                    headers=auth_headers(admin))
    assert r.status_code == 201, r.text
    return r.json()


def _download(client, user, decoy_id, kind):
    return client.get(f"/api/v1/honey-tokens/{decoy_id}/files/{kind}", headers=auth_headers(user))


def _parts(docx: bytes) -> dict[str, str]:
    with zipfile.ZipFile(io.BytesIO(docx)) as zf:
        return {n: zf.read(n).decode() for n in zf.namelist()}


# ----------------------------------------------------------------------------- documents

def test_document_decoy_is_a_word_file_that_loads_its_pixel(client, admin_a, project_a):
    token = _generate(client, admin_a, project_a, "DOCUMENT", template="vpn_access")
    meta = token["metadata"]
    assert meta["pixel_url"] == f"{INGEST}/px/{token['token_value']}.gif"
    assert meta["filename"] == "VPN access - contractors.docx" and meta["detection"]["status"] == "PUBLIC_INGEST"

    r = _download(client, admin_a, token["decoy_id"], "docx")
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == documents.DOCX_MIME
    assert "attachment" in r.headers["content-disposition"] and r.headers["cache-control"] == "no-store"
    parts = _parts(r.content)
    rels = parts["word/_rels/document.xml.rels"]
    assert f'Target="{meta["pixel_url"]}"' in rels and 'TargetMode="External"' in rels
    assert 'r:link="rIdImg1"' in parts["word/document.xml"]            # linked, not embedded
    assert "Contractor VPN access" in parts["word/document.xml"]
    assert "vpn.alpha.example.com" in parts["word/document.xml"]
    # Nothing executable and nothing else external: one external relationship, no macros, no fields.
    assert not any("vba" in n.lower() or n.endswith(".bin") for n in parts)
    assert sum(p.count('TargetMode="External"') for p in parts.values()) == 1
    assert "instrText" not in parts["word/document.xml"] and "attachedTemplate" not in "".join(parts.values())
    assert _download(client, admin_a, token["decoy_id"], "docx").content == r.content   # same file every time


def test_opening_the_document_records_a_document_event(client, db_session, admin_a, project_a):
    token = _generate(client, admin_a, project_a, "DOCUMENT")
    r = client.get(f"/px/{token['token_value']}.gif", headers={"User-Agent": WORD_UA})
    assert r.status_code == 200 and r.headers["content-type"] == "image/gif"
    db_session.expire_all()
    [event] = db_session.query(DetectionEvent).filter_by(honey_token_id=token["id"]).all()
    assert event.severity == EventSeverity.HIGH and event.user_agent == WORD_UA
    [view] = client.get("/api/v1/detection-events", headers=auth_headers(admin_a)).json()
    assert view["decoy_type"] == "DOCUMENT"
    assert [t["id"] for t in view["attack"]] == ["T1005", "T1039"]


def test_document_decoys_need_a_public_ingest_url(client, admin_a, project_a, monkeypatch):
    monkeypatch.setattr(get_settings(), "public_ingest_base_url", None)
    r = client.post(f"/api/v1/projects/{project_a.domain}/honey-tokens/generate", json={"token_type": "DOCUMENT"},
                    headers=auth_headers(admin_a))
    assert r.status_code in (400, 422) and "PUBLIC_INGEST_BASE_URL" in r.text
    types = client.get("/api/v1/honey-tokens/types", headers=auth_headers(admin_a)).json()["types"]
    assert types["DOCUMENT"] is False


def test_unknown_document_template_is_refused(client, admin_a, project_a):
    r = client.post(f"/api/v1/projects/{project_a.domain}/honey-tokens/generate",
                    json={"token_type": "DOCUMENT", "generator_params": {"template": "../../etc"}},
                    headers=auth_headers(admin_a))
    assert r.status_code in (400, 422)


def test_build_docx_escapes_text_and_url_and_is_reproducible():
    when = datetime(2026, 1, 2, tzinfo=timezone.utc)
    kw = dict(title='Q&A <draft> "x"', paragraphs=["a < b & c"], author="A&B",
              image_url='https://h.example/px/a.gif?x="1"&y=<2>', created=when)
    one, two = documents.build_docx(**kw), documents.build_docx(**kw)
    assert one == two
    parts = _parts(one)
    assert "Q&amp;A &lt;draft&gt;" in parts["word/document.xml"]
    assert "a &lt; b &amp; c" in parts["word/document.xml"]
    assert "&quot;1&quot;&amp;y=&lt;2&gt;" in parts["word/_rels/document.xml.rels"]
    with pytest.raises(ValueError):
        documents.build_docx(**{**kw, "image_url": "file:///etc/passwd"})


# ----------------------------------------------------------------------------- bait files

def test_dns_decoy_bait_files_tag_each_file(client, admin_a, project_a):
    token = _generate(client, admin_a, project_a, "DNS")
    assert token["files"] == ["kubeconfig", "ssh-config", "env"]       # in the generate response too
    host = token["metadata"]["hostname"]
    listed = client.get(f"/api/v1/honey-tokens?project_domain={project_a.domain}", headers=auth_headers(admin_a))
    [row] = [t for t in listed.json() if t["id"] == token["id"]]
    assert row["files"] == ["kubeconfig", "ssh-config", "env"]

    kube = _download(client, admin_a, token["decoy_id"], "kubeconfig")
    assert kube.status_code == 200 and kube.headers["content-type"].startswith("text/plain")
    assert f"server: https://k8s-prod.{host}:6443" in kube.text
    assert "certificate-authority-data" not in kube.text and "insecure-skip-tls-verify: true" in kube.text
    ssh = _download(client, admin_a, token["decoy_id"], "ssh-config").text
    assert f"HostName bastion.{host}" in ssh
    env = _download(client, admin_a, token["decoy_id"], "env")
    assert f"@db.{host}:5432/" in env.text and 'filename="production.env"' in env.headers["content-disposition"]
    assert _download(client, admin_a, token["decoy_id"], "env").text == env.text


def test_aws_key_bait_files_only_once_the_key_exists(client, db_session, admin_a, project_a, monkeypatch):
    monkeypatch.setattr(get_settings(), "aws_canary_enabled", True)
    token = _generate(client, admin_a, project_a, "AWS_KEY", profile_name="prod")
    assert _download(client, admin_a, token["decoy_id"], "aws-credentials").status_code == 422   # provisioning
    row = db_session.get(HoneyToken, token["id"])
    row.token_metadata = {**row.token_metadata, "status": "active", "access_key_id": "AKIAEXAMPLE0000001",
                          "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
    db_session.commit()
    creds = _download(client, admin_a, token["decoy_id"], "aws-credentials")
    assert creds.status_code == 200 and 'filename="credentials"' in creds.headers["content-disposition"]
    assert creds.text.startswith("[prod]\naws_access_key_id = AKIAEXAMPLE0000001\n")
    env = _download(client, admin_a, token["decoy_id"], "env").text
    assert "AWS_ACCESS_KEY_ID=AKIAEXAMPLE0000001" in env and "AWS_SECRET_ACCESS_KEY=wJalr" in env


def test_api_key_env_file_and_kinds_that_do_not_apply(client, admin_a, project_a):
    token = _generate(client, admin_a, project_a, "API_KEY")
    assert f"API_KEY={token['token_value']}" in _download(client, admin_a, token["decoy_id"], "env").text
    for kind in ("kubeconfig", "docx", "nonsense"):
        assert _download(client, admin_a, token["decoy_id"], kind).status_code == 422
    url = _generate(client, admin_a, project_a, "URL")
    assert _download(client, admin_a, url["decoy_id"], "env").status_code == 422


def test_bait_files_are_for_administrators_of_the_owning_tenant_only(client, admin_a, admin_b, user_a, project_a):
    token = _generate(client, admin_a, project_a, "DNS")
    assert _download(client, user_a, token["decoy_id"], "kubeconfig").status_code == 403
    assert _download(client, admin_b, token["decoy_id"], "kubeconfig").status_code == 404
    assert client.get(f"/api/v1/honey-tokens/{token['decoy_id']}/files/kubeconfig").status_code == 401
    listed = client.get(f"/api/v1/honey-tokens?project_domain={project_a.domain}", headers=auth_headers(user_a))
    assert all(t["files"] == [] for t in listed.json())
    assert _download(client, admin_a, "dcy_doesnotexist", "kubeconfig").status_code == 404
    assert _download(client, admin_a, "../x", "kubeconfig").status_code in (404, 422)


def test_revoked_decoys_cannot_be_downloaded(client, admin_a, project_a):
    token = _generate(client, admin_a, project_a, "DNS")
    r = client.post("/api/v1/honey-tokens/revoke", json={"token_value": token["token_value"]},
                    headers=auth_headers(admin_a))
    assert r.status_code == 204
    assert _download(client, admin_a, token["decoy_id"], "kubeconfig").status_code == 404


def test_every_download_is_audited(client, db_session, admin_a, project_a):
    token = _generate(client, admin_a, project_a, "DOCUMENT")
    _download(client, admin_a, token["decoy_id"], "docx")
    db_session.expire_all()
    [audit] = db_session.query(AuditLog).filter_by(event_type="HONEY_TOKEN_FILE_DOWNLOADED").all()
    assert audit.event_metadata == {"kind": "docx"} and token["decoy_id"] in audit.message


def test_non_ascii_file_names_get_a_safe_fallback(client, db_session, admin_a, project_a):
    token = _generate(client, admin_a, project_a, "DOCUMENT")
    row = db_session.get(HoneyToken, token["id"])
    row.token_metadata = {**row.token_metadata, "filename": 'Gehälter "2026"\r\n.docx'}
    db_session.commit()
    cd = _download(client, admin_a, token["decoy_id"], "docx").headers["content-disposition"]
    assert re.fullmatch(r'attachment; filename="[A-Za-z0-9._-]+"; filename\*=UTF-8\'\'[A-Za-z0-9%._-]+', cd), cd
    assert HoneyTokenType.DOCUMENT.value == "DOCUMENT"
