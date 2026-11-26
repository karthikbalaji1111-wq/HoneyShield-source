"""Deployment contracts exercised independently of Docker availability."""
from __future__ import annotations

import pytest
from pydantic import ValidationError
from sqlalchemy.engine import make_url

from app.core.config import Settings


def test_database_credentials_round_trip_reserved_characters(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    settings = Settings(
        _env_file=None,
        jwt_secret_key="test-only-signing-key-with-at-least-32-characters",
        postgres_user="user@name",
        postgres_password="password@host:/?#%",
    )
    url = make_url(settings.sqlalchemy_database_uri)
    assert url.username == "user@name"
    assert url.password == "password@host:/?#%"
    assert url.host == "localhost"


def test_production_rejects_default_database_password():
    with pytest.raises(ValidationError, match="POSTGRES_PASSWORD must be explicitly configured"):
        Settings(
            _env_file=None,
            app_env="production",
            jwt_secret_key="test-only-signing-key-with-at-least-32-characters",
            postgres_password="honeyshield_dev_password",
        )


def test_production_accepts_explicit_password():
    settings = Settings(
        _env_file=None,
        app_env="production",
        jwt_secret_key="test-only-signing-key-with-at-least-32-characters",
        postgres_password="secure-production-database-password",
        public_ingest_base_url="https://ingest.example.com",
        integration_signing_key="production-integration-master-key-0123456789",
        mfa_secret_key="production-mfa-derivation-key-0123456789abcdef",
        control_plane_hostnames="app.example.com",
    )
    assert settings.postgres_password == "secure-production-database-password"


_PROD = dict(
    _env_file=None,
    app_env="production",
    jwt_secret_key="test-only-signing-key-with-at-least-32-characters",
    postgres_password="secure-production-database-password",
    mfa_secret_key="production-mfa-derivation-key-0123456789abcdef",
)


def test_production_requires_public_ingest_base_url():
    with pytest.raises(ValidationError, match="PUBLIC_INGEST_BASE_URL must be configured"):
        Settings(**_PROD)


def test_production_requires_https_ingest_base_url():
    with pytest.raises(ValidationError, match="must use https"):
        Settings(**_PROD, public_ingest_base_url="http://ingest.example.com")


@pytest.mark.parametrize(
    "value",
    ["ftp://ingest.example.com", "ingest.example.com", "https://ingest.example.com/api",
     "https://u:p@ingest.example.com", "https://ingest.example.com?x=1", "https://ingest.example.com#f"],
)
def test_ingest_base_url_rejects_non_origins(value):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, jwt_secret_key="test-only-signing-key-with-at-least-32-characters",
                 public_ingest_base_url=value)


def test_ingest_base_url_is_normalized_and_optional_outside_production():
    base = dict(_env_file=None, jwt_secret_key="test-only-signing-key-with-at-least-32-characters")
    assert Settings(**base).public_ingest_base_url is None
    assert Settings(**base, public_ingest_base_url="  ").public_ingest_base_url is None
    assert Settings(**base, public_ingest_base_url="HTTPS://Ingest.Example.com/").public_ingest_base_url == "https://ingest.example.com"


@pytest.mark.parametrize("secret", ["", "short", " " * 40])
def test_reject_unsafe_signing_secret(secret):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, jwt_secret_key=secret)


def test_readiness_is_distinct_from_liveness(client):
    assert client.get("/health").status_code == 200
    # Fixture metadata has no Alembic version: an unmigrated DB isn't ready.
    assert client.get("/api/v1/ready").status_code == 503


def test_missing_signing_secret_fails(monkeypatch):
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_bootstrap_first_admin_and_refuse_repeat(db_session):
    from app.bootstrap import create_first_admin
    from app.models.audit_log import AuditLog
    from app.models.enums import Role
    from sqlalchemy import select

    user = create_first_admin(db_session, "bootstrap@example.org", "safe-test-password")
    assert user.role == Role.SYSTEM_ADMIN
    assert user.tenant_id is None
    actor = db_session.scalars(select(AuditLog)).one()
    assert actor.actor_user_id == user.id
    with pytest.raises(ValueError, match="empty users table"):
        create_first_admin(db_session, "second@example.org", "safe-test-password")


@pytest.mark.parametrize("password", ["short", "a" * 73, "é" * 37])
def test_bootstrap_rejects_unsafe_password(db_session, password):
    from app.bootstrap import create_first_admin
    with pytest.raises(ValueError):
        create_first_admin(db_session, "bootstrap@example.org", password)


def test_production_requires_integration_signing_key():
    with pytest.raises(ValidationError, match="INTEGRATION_SIGNING_KEY must be configured"):
        Settings(**_PROD, public_ingest_base_url="https://ingest.example.com")


def test_integration_signing_key_must_differ_from_jwt_key():
    with pytest.raises(ValidationError, match="must differ"):
        Settings(**_PROD, public_ingest_base_url="https://ingest.example.com",
                 integration_signing_key=_PROD["jwt_secret_key"], control_plane_hostnames="app.example.com")


def test_db_least_privilege_is_enforced_by_default_in_production_only():
    prod = Settings(**_PROD, public_ingest_base_url="https://ingest.example.com",
                    integration_signing_key="production-integration-master-key-0123456789",
                    control_plane_hostnames="app.example.com")
    assert prod.db_least_privilege_enforced is True
    dev = Settings(_env_file=None, jwt_secret_key=_PROD["jwt_secret_key"])
    assert dev.db_least_privilege_enforced is False


def test_migration_uri_uses_owner_identity_when_configured():
    s = Settings(_env_file=None, jwt_secret_key=_PROD["jwt_secret_key"], postgres_user="honeyshield_app",
                 postgres_migration_user="honeyshield_owner", postgres_migration_password="pw")
    assert "honeyshield_owner" in s.migration_database_uri
    assert "honeyshield_app" in s.sqlalchemy_database_uri


def test_production_requires_separate_control_plane_host():
    base = dict(_PROD, public_ingest_base_url="https://ingest.example.com",
                integration_signing_key="production-integration-master-key-0123456789")
    with pytest.raises(ValidationError, match="CONTROL_PLANE_HOSTNAMES must be configured"):
        Settings(**base)
    with pytest.raises(ValidationError, match="must differ"):
        Settings(**base, control_plane_hostnames="ingest.example.com")
    ok = Settings(**base, control_plane_hostnames="App.Example.com, admin.example.com")
    assert ok.control_plane_hostnames == ["app.example.com", "admin.example.com"]
    assert ok.host_separation_enabled and ok.api_docs_enabled is False


_PROD_FULL = dict(public_ingest_base_url="https://ingest.example.com",
                  integration_signing_key="production-integration-master-key-0123456789",
                  control_plane_hostnames="app.example.com")


def test_production_requires_mfa_secret_key():
    base = {k: v for k, v in _PROD.items() if k != "mfa_secret_key"}
    with pytest.raises(ValidationError, match="MFA_SECRET_KEY must be configured"):
        Settings(**base, **_PROD_FULL)


def test_mfa_secret_key_must_differ_from_other_keys():
    for reused in (_PROD["jwt_secret_key"], _PROD_FULL["integration_signing_key"]):
        with pytest.raises(ValidationError, match="MFA_SECRET_KEY must differ"):
            Settings(**dict(_PROD, mfa_secret_key=reused), **_PROD_FULL)


def test_mfa_required_roles_default_to_admins_in_production_only():
    assert Settings(**_PROD, **_PROD_FULL).mfa_required_role_names == {"SYSTEM_ADMIN", "TENANT_ADMIN"}
    assert Settings(_env_file=None, jwt_secret_key=_PROD["jwt_secret_key"]).mfa_required_role_names == set()
    explicit = Settings(**_PROD, **_PROD_FULL, mfa_required_roles="system_admin, TENANT_USER")
    assert explicit.mfa_required_role_names == {"SYSTEM_ADMIN", "TENANT_USER"}
    assert Settings(**_PROD, **_PROD_FULL, mfa_required_roles="none").mfa_required_role_names == set()
    with pytest.raises(ValidationError, match="unknown roles"):
        Settings(**_PROD, **_PROD_FULL, mfa_required_roles="SYSTEM_ADMIN,ROOT")


def test_backend_image_disables_uvicorn_proxy_header_rewriting():
    """Only the app's TRUSTED_PROXIES walk may interpret X-Forwarded-For."""
    import json
    import pathlib
    dockerfile = pathlib.Path(__file__).resolve().parents[2] / "docker" / "Dockerfile.backend"
    cmd_line = next(line for line in dockerfile.read_text().splitlines() if line.startswith("CMD "))
    argv = json.loads(cmd_line[len("CMD "):])
    assert argv[0] == "uvicorn" and "--no-proxy-headers" in argv
    assert "--proxy-headers" not in argv and not any(a.startswith("--forwarded-allow-ips") for a in argv)


def test_production_refuses_plaintext_smtp():
    smtp = dict(smtp_host="smtp.example.com", smtp_from="alerts@example.com")
    with pytest.raises(ValidationError, match="SMTP_SECURITY"):
        Settings(**_PROD, **_PROD_FULL, **smtp, smtp_security="none")
    for mode in ("starttls", "tls"):
        assert Settings(**_PROD, **_PROD_FULL, **smtp, smtp_security=mode).smtp_security == mode


def test_compose_passes_alert_channel_settings_to_the_app():
    import pathlib

    compose = (pathlib.Path(__file__).resolve().parents[2] / "docker-compose.yml").read_text()
    for name in ("SMTP_HOST", "SMTP_PORT", "SMTP_SECURITY", "SMTP_USERNAME", "SMTP_PASSWORD", "SMTP_FROM",
                 "ALERT_ALLOWED_PRIVATE_CIDRS"):
        assert f"{name}: ${{{name}:-" in compose, name
