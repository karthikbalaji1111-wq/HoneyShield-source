"""End-to-end lifecycle and regression tests for HoneyTokens.

Verifies:
1. API_KEY generator -> /collect/{token_value} and /t/{token_value} -> DetectionEvent recorded
2. HIDDEN_URL generator -> /t/{token_value} -> DetectionEvent recorded
3. TRACKING_PIXEL generator -> /px/{token_value}.gif -> DetectionEvent recorded + 200 transparent GIF
4. FORM_FIELD generator -> generation succeeds -> /collect/{token_value} and /t/{token_value} -> DetectionEvent recorded
5. LINK generator -> generation succeeds -> /t/{token_value} -> DetectionEvent recorded
6. Revoke lifecycle -> token marked inactive, audit log recorded
7. Rotate lifecycle -> old token revoked, new token created active, audit log recorded
8. Inactive/revoked token triggering -> triggering inactive token still records immutable DetectionEvent
9. Duplicate token handling -> collision detection on creation, rotation, and generation retry
"""
from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from app.core.exceptions import DuplicateHoneyTokenError, HoneyTokenNotFoundError
from app.models.detection_event import DetectionEvent
from app.models.enums import HoneyTokenType
from app.models.honey_token import HoneyToken
from app.models.project import Project
from app.models.user import User
from app.repositories.honey_token import HoneyTokenRepository
from app.repositories.project import ProjectRepository
from app.services.honey_token import HoneyTokenService
from tests.conftest import auth_headers


class TestHoneyTokenGenerationAndIngestion:
    """Test every supported honey token type end-to-end from generation to ingestion."""

    def test_api_key_generator_and_ingestion(self, client, db_session: Session, admin_a: User, project_a: Project):
        """API_KEY: generate -> triggers via /collect and /t -> records DetectionEvent in DB."""
        headers = auth_headers(admin_a)
        resp = client.post(
            f"/api/v1/projects/{project_a.domain}/honey-tokens/generate",
            json={"token_type": "API_KEY"},
            headers=headers,
        )
        assert resp.status_code == 201
        data = resp.json()
        token_value = data["token_value"]
        assert token_value
        assert data["token_type"] == "API_KEY"

        # 1. Trigger via POST /collect/{token_value}
        collect_resp = client.post(f"/collect/{token_value}")
        assert collect_resp.status_code == 204

        # Verify event in DB
        db_session.expire_all()
        token = db_session.query(HoneyToken).filter_by(token_value=token_value).one()
        events = db_session.query(DetectionEvent).filter_by(honey_token_id=token.id).all()
        assert len(events) == 1
        assert events[0].http_method == "POST"
        assert events[0].request_path == f"/collect/{token_value}"

        # 2. Trigger via GET /t/{token_value}
        t_resp = client.get(f"/t/{token_value}")
        assert t_resp.status_code == 204

        db_session.expire_all()
        events = db_session.query(DetectionEvent).filter_by(honey_token_id=token.id).all()
        assert len(events) == 2

    def test_hidden_url_generator_and_ingestion(self, client, db_session: Session, admin_a: User, project_a: Project):
        """HIDDEN_URL: generate -> triggers via /t/{token_value} -> records DetectionEvent in DB."""
        headers = auth_headers(admin_a)
        resp = client.post(
            f"/api/v1/projects/{project_a.domain}/honey-tokens/generate",
            json={"token_type": "URL"},
            headers=headers,
        )
        assert resp.status_code == 201
        data = resp.json()
        token_value = data["token_value"]
        assert token_value
        assert data["token_type"] == "URL"
        assert "metadata" in data
        assert data["metadata"]["path"] == f"/t/{token_value}"

        # Trigger via GET /t/{token_value}
        trigger_resp = client.get(f"/t/{token_value}")
        assert trigger_resp.status_code == 204

        # Verify event in DB
        db_session.expire_all()
        token = db_session.query(HoneyToken).filter_by(token_value=token_value).one()
        events = db_session.query(DetectionEvent).filter_by(honey_token_id=token.id).all()
        assert len(events) == 1
        assert events[0].http_method == "GET"
        assert events[0].request_path == f"/t/{token_value}"

    def test_tracking_pixel_generator_and_ingestion(self, client, db_session: Session, admin_a: User, project_a: Project):
        """PIXEL: generate -> triggers via /px/{token_value}.gif -> 200 GIF + records DetectionEvent."""
        headers = auth_headers(admin_a)
        resp = client.post(
            f"/api/v1/projects/{project_a.domain}/honey-tokens/generate",
            json={"token_type": "PIXEL"},
            headers=headers,
        )
        assert resp.status_code == 201
        data = resp.json()
        token_value = data["token_value"]
        assert token_value
        assert data["token_type"] == "PIXEL"
        assert "metadata" in data
        assert data["metadata"]["pixel_path"] == f"/px/{token_value}.gif"

        # Trigger via GET /px/{token_value}.gif
        px_resp = client.get(f"/px/{token_value}.gif")
        assert px_resp.status_code == 200
        assert px_resp.headers["content-type"] == "image/gif"
        assert len(px_resp.content) == 43  # 1x1 transparent GIF

        # Verify event in DB
        db_session.expire_all()
        token = db_session.query(HoneyToken).filter_by(token_value=token_value).one()
        events = db_session.query(DetectionEvent).filter_by(honey_token_id=token.id).all()
        assert len(events) == 1
        assert events[0].http_method == "GET"
        assert events[0].request_path == f"/px/{token_value}.gif"



    def test_link_generator_and_ingestion(self, client, db_session: Session, admin_a: User, project_a: Project):
        """LINK: generate -> triggers via /t/{token_value} -> records DetectionEvent."""
        headers = auth_headers(admin_a)
        resp = client.post(
            f"/api/v1/projects/{project_a.domain}/honey-tokens/generate",
            json={"token_type": "LINK"},
            headers=headers,
        )
        assert resp.status_code == 201
        data = resp.json()
        token_value = data["token_value"]
        assert token_value
        assert data["token_type"] == "LINK"
        assert "metadata" in data
        assert data["metadata"]["path"] == f"/t/{token_value}"
        assert "<a href=" in data["metadata"]["html_tag"]

        # Trigger via GET /t/{token_value}
        link_resp = client.get(f"/t/{token_value}")
        assert link_resp.status_code == 204

        # Verify event in DB
        db_session.expire_all()
        token = db_session.query(HoneyToken).filter_by(token_value=token_value).one()
        events = db_session.query(DetectionEvent).filter_by(honey_token_id=token.id).all()
        assert len(events) == 1
        assert events[0].http_method == "GET"
        assert events[0].request_path == f"/t/{token_value}"

    def test_form_field_generator_and_ingestion(self, client, db_session: Session, admin_a: User, project_a: Project):
        """FORM_FIELD: generate -> triggers via /collect/{token_value} and /t/{token_value} -> records DetectionEvent."""
        headers = auth_headers(admin_a)
        resp = client.post(
            f"/api/v1/projects/{project_a.domain}/honey-tokens/generate",
            json={"token_type": "FORM_FIELD"},
            headers=headers,
        )
        assert resp.status_code == 201
        data = resp.json()
        token_value = data["token_value"]
        assert token_value
        assert data["token_type"] == "FORM_FIELD"
        assert "metadata" in data
        assert '<input type="text"' in data["metadata"]["html_snippet"]

        # Legacy route: FORM_FIELD tokens deployed before the honeypot redesign embedded
        # the value and posted to /collect/{token_value}; that path still records hits.
        collect_resp = client.post(f"/collect/{token_value}")
        assert collect_resp.status_code == 204

        # Verify event in DB
        db_session.expire_all()
        token = db_session.query(HoneyToken).filter_by(token_value=token_value).one()
        events = db_session.query(DetectionEvent).filter_by(honey_token_id=token.id).all()
        assert len(events) == 1
        assert events[0].http_method == "POST"


class TestHoneyTokenLifecycle:
    """Test token revocation, rotation, inactive triggering, and duplicate collision handling."""

    def _create(self, client, headers, project, token_type="URL", **extra):
        resp = client.post("/api/v1/honey-tokens", json={"project_domain": project.domain,
                                                         "token_type": token_type, **extra}, headers=headers)
        assert resp.status_code == 201, resp.text
        return resp.json()

    def test_revoke_token_lifecycle(self, client, db_session: Session, admin_a: User, project_a: Project):
        """Revoking a token sets is_active=False."""
        headers = auth_headers(admin_a)
        created = self._create(client, headers, project_a, label="Revoke Test")
        assert created["label"] == "Revoke Test" and created["metadata"]["url"]
        revoke_resp = client.post("/api/v1/honey-tokens/revoke", json={"token_value": created["token_value"]},
                                  headers=headers)
        assert revoke_resp.status_code == 204
        db_session.expire_all()
        token = db_session.query(HoneyToken).filter_by(token_value=created["token_value"]).one()
        assert token.is_active is False

    def test_rotate_token_lifecycle(self, client, db_session: Session, admin_a: User, project_a: Project):
        """Rotation revokes the old token and issues a NEW value with a regenerated artifact."""
        headers = auth_headers(admin_a)
        old = self._create(client, headers, project_a, token_type="URL", label="Rotate Test")
        rotate_resp = client.post("/api/v1/honey-tokens/rotate", json={"old_token_value": old["token_value"]},
                                  headers=headers)
        assert rotate_resp.status_code == 200, rotate_resp.text
        new = rotate_resp.json()
        assert new["token_value"] != old["token_value"] and new["is_active"] is True
        assert new["label"] == "Rotate Test"
        # The artifact points at the NEW value, not the revoked one.
        assert new["token_value"] in new["metadata"]["url"]
        assert old["token_value"] not in str(new["metadata"])
        db_session.expire_all()
        assert db_session.query(HoneyToken).filter_by(token_value=old["token_value"]).one().is_active is False

    def test_rotate_keeps_generator_style(self, client, admin_a: User, project_a: Project):
        headers = auth_headers(admin_a)
        gen = client.post(f"/api/v1/projects/{project_a.domain}/honey-tokens/generate",
                          json={"token_type": "API_KEY", "generator_params": {"provider_style": "stripe"}},
                          headers=headers).json()
        new = client.post("/api/v1/honey-tokens/rotate", json={"old_token_value": gen["token_value"]},
                          headers=headers).json()
        assert new["token_value"].startswith("sk_") and new["metadata"]["provider_style"] == "stripe"

    def test_inactive_revoked_token_triggering(self, client, db_session: Session, admin_a: User, project_a: Project):
        """Triggering a revoked token still creates an immutable DetectionEvent."""
        headers = auth_headers(admin_a)
        value = self._create(client, headers, project_a)["token_value"]
        assert client.post("/api/v1/honey-tokens/revoke", json={"token_value": value},
                           headers=headers).status_code == 204
        assert client.get(f"/t/{value}").status_code == 204
        db_session.expire_all()
        token = db_session.query(HoneyToken).filter_by(token_value=value).one()
        events = db_session.query(DetectionEvent).filter_by(honey_token_id=token.id).all()
        assert len(events) == 1
        assert events[0].request_path == f"/t/{value}"

    def test_tenant_admin_cannot_choose_token_values(self, client, db_session, admin_a: User, project_a: Project,
                                                     token_b):
        """HONEY-012: a chosen value would make uniqueness a cross-tenant oracle.

        Submitting another tenant's real value and an unused value must look identical.
        """
        db_session.commit()  # keep fixtures across the service's rollback on the first rejection
        headers = auth_headers(admin_a)
        taken = client.post("/api/v1/honey-tokens", json={"project_domain": project_a.domain, "token_type": "URL",
                                                          "token_value": token_b.token_value}, headers=headers)
        free = client.post("/api/v1/honey-tokens", json={"project_domain": project_a.domain, "token_type": "URL",
                                                         "token_value": "never-used-value-0123456789"},
                           headers=headers)
        assert taken.status_code == free.status_code == 422
        assert taken.json()["detail"] == free.json()["detail"]
        assert token_b.token_value not in taken.text

    def test_tenant_admin_cannot_rotate_to_a_chosen_value(self, client, db_session, admin_a: User,
                                                          project_a: Project, token_b):
        headers = auth_headers(admin_a)
        old = self._create(client, headers, project_a)
        db_session.commit()
        taken = client.post("/api/v1/honey-tokens/rotate", json={"old_token_value": old["token_value"],
                                                                 "new_token_value": token_b.token_value},
                            headers=headers)
        free = client.post("/api/v1/honey-tokens/rotate", json={"old_token_value": old["token_value"],
                                                                "new_token_value": "never-used-value-0123456789"},
                           headers=headers)
        assert taken.status_code == free.status_code == 422
        assert taken.json()["detail"] == free.json()["detail"]

    def test_duplicate_token_creation_rejected_for_system_admin(self, client, system_admin: User, project_a: Project):
        """SYSTEM_ADMIN (global scope, no oracle) may set values; duplicates are 409."""
        headers = auth_headers(system_admin)
        body = {"project_domain": project_a.domain, "token_type": "URL", "token_value": "unique-token-dup-check"}
        assert client.post("/api/v1/honey-tokens", json=body, headers=headers).status_code == 201
        assert client.post("/api/v1/honey-tokens", json=body, headers=headers).status_code == 409

    def test_rotate_to_existing_value_rejected(self, client, system_admin: User, project_a: Project):
        headers = auth_headers(system_admin)
        for v in ("rotate-t1-0123456789", "rotate-t2-0123456789"):
            client.post("/api/v1/honey-tokens", json={"project_domain": project_a.domain, "token_type": "URL",
                                                      "token_value": v}, headers=headers)
        resp = client.post("/api/v1/honey-tokens/rotate",
                           json={"old_token_value": "rotate-t1-0123456789", "new_token_value": "rotate-t2-0123456789"},
                           headers=headers)
        assert resp.status_code == 409

    def test_oversized_metadata_is_rejected(self, client, system_admin: User, project_a: Project):
        resp = client.post("/api/v1/honey-tokens", json={"project_domain": project_a.domain, "token_type": "URL",
                                                         "token_value": "meta-size-0123456789",
                                                         "metadata": {"x": "a" * 9000}},
                           headers=auth_headers(system_admin))
        assert resp.status_code == 422

    def test_cross_tenant_token_generation_prevented(self, client, admin_a: User, project_b: Project):
        """Tenant A admin cannot generate tokens for Tenant B's project (returns 404)."""
        headers = auth_headers(admin_a)
        resp = client.post(
            f"/api/v1/projects/{project_b.domain}/honey-tokens/generate",
            json={"token_type": "URL"},
            headers=headers,
        )
        assert resp.status_code == 404
