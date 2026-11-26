"""Case-insensitive email, the last SYSTEM_ADMIN, and project domains."""
from __future__ import annotations

from app.core.security import get_password_hash
from app.models.enums import Role
from app.models.user import User
from tests.conftest import auth_headers


def test_emails_are_normalised_and_unique_case_insensitively(client, db_session, admin_a, tenant_a):
    db_session.commit()
    body = {"email": "New.Person@Tenant-A.com", "password": "correct-horse-1", "role": "TENANT_USER",
            "tenant_id": tenant_a.id}
    resp = client.post("/api/v1/users", json=body, headers=auth_headers(admin_a))
    assert resp.status_code == 201, resp.text
    assert resp.json()["email"] == "new.person@tenant-a.com"
    dup = client.post("/api/v1/users", json={**body, "email": "NEW.PERSON@tenant-a.COM"}, headers=auth_headers(admin_a))
    assert dup.status_code == 409


def test_login_is_case_insensitive(client, db_session, admin_a):
    db_session.commit()
    resp = client.post("/auth/login", json={"email": "ADMIN@Tenant-A.com", "password": "password"})
    assert resp.status_code == 200, resp.text


def test_last_system_admin_cannot_be_demoted_or_deactivated(client, db_session, system_admin, tenant_a):
    other = User(email="second-admin@honeyshield.io", hashed_password=get_password_hash("password"),
                 role=Role.SYSTEM_ADMIN, is_active=True, tenant_id=None)
    db_session.add(other)
    db_session.commit()
    # With two admins, one may deactivate the other ...
    r = client.patch(f"/api/v1/users/{other.id}", json={"is_active": False}, headers=auth_headers(system_admin))
    assert r.status_code == 200, r.text
    # ... but once only one active admin remains it cannot be demoted, even by itself.
    r = client.patch(f"/api/v1/users/{system_admin.id}", json={"role": "TENANT_ADMIN", "tenant_id": tenant_a.id},
                     headers=auth_headers(system_admin))
    assert r.status_code in (409, 422)
    assert "last active SYSTEM_ADMIN" in r.json()["detail"]
    db_session.expire_all()
    assert db_session.get(User, system_admin.id).role == Role.SYSTEM_ADMIN


def test_project_domains_are_per_tenant_and_reveal_nothing(client, db_session, admin_a, admin_b, tenant_a,
                                                           tenant_b, project_a):
    db_session.commit()
    resp = client.post("/api/v1/projects", json={"tenant_slug": tenant_b.slug, "name": "Same",
                                                 "domain": project_a.domain.upper()}, headers=auth_headers(admin_b))
    assert resp.status_code == 201, resp.text      # another tenant's domain is not an oracle
    assert resp.json()["domain"] == project_a.domain
    again = client.post("/api/v1/projects", json={"tenant_slug": tenant_a.slug, "name": "Dup",
                                                  "domain": project_a.domain}, headers=auth_headers(admin_a))
    assert again.status_code == 409               # but it is unique within a tenant


def test_ambiguous_domain_is_refused_for_unscoped_system_admin(client, db_session, admin_b, tenant_b, project_a,
                                                               system_admin):
    db_session.commit()
    client.post("/api/v1/projects", json={"tenant_slug": tenant_b.slug, "name": "Same", "domain": project_a.domain},
                headers=auth_headers(admin_b))
    resp = client.get(f"/api/v1/projects/{project_a.domain}", headers=auth_headers(system_admin))
    assert resp.status_code == 422


def test_project_domain_must_be_a_hostname(client, admin_a, tenant_a):
    for bad in ("https://x.com/path", "no-dot", "a..b.com", "space here.com", "-x.com"):
        resp = client.post("/api/v1/projects", json={"tenant_slug": tenant_a.slug, "name": "X", "domain": bad},
                           headers=auth_headers(admin_a))
        assert resp.status_code == 422, bad
