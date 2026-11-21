from __future__ import annotations

from functools import lru_cache
from typing import Any, Literal, Optional, Union
import json
import re
import urllib.parse

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import URL


class Settings(BaseSettings):
    app_name: str = "HoneyShield"
    app_version: str = "0.1.0"
    app_env: str = "development"
    api_v1_prefix: str = "/api/v1"
    log_level: str = "INFO"

    database_url: Optional[str] = None
    postgres_db: str = "honeyshield_dev"
    postgres_user: str = "honeyshield"
    postgres_password: str = Field(default="honeyshield_dev_password", repr=False)
    postgres_host: str = "localhost"
    postgres_port: int = 5432

    # HONEY-002: identities. POSTGRES_USER/PASSWORD above are what the API connects as and
    # must be the unprivileged runtime role in production. The migration owner is used only
    # by Alembic and the grant step (python -m app.db.privileges grant).
    postgres_app_user: Optional[str] = None
    migration_database_url: Optional[str] = Field(default=None, repr=False)
    postgres_migration_user: Optional[str] = None
    postgres_migration_password: Optional[str] = Field(default=None, repr=False)
    # Refuse to start when the runtime connection is a superuser, owns tables, can run DDL,
    # or can UPDATE/DELETE/TRUNCATE evidence. Defaults on in production/staging.
    enforce_db_least_privilege: Optional[bool] = None

    db_pool_size: int = Field(default=10, ge=1, le=50)
    db_max_overflow: int = Field(default=10, ge=0, le=50)
    db_pool_timeout: float = Field(default=10.0, ge=1.0, le=60.0)
    db_pool_recycle: int = Field(default=1800, ge=60, le=7200)
    db_statement_timeout_ms: int = Field(default=5000, ge=500, le=60000)
    db_analytics_timeout_ms: int = Field(default=15000, ge=1000, le=120000)
    # Threat analytics consider at most this many of the most recent events in their window, so
    # their cost is bounded at any data size; responses say when the cap applied.
    analytics_sample_events: int = Field(default=200_000, ge=1_000, le=5_000_000)

    jwt_secret_key: str = Field(repr=False)
    jwt_algorithm: Literal["HS256"] = "HS256"
    access_token_expire_minutes: int = Field(default=30, ge=1, le=1440)
    # Single sign-on (OpenID Connect, app/services/oidc.py). Unset issuer: SSO is off. Users must
    # already exist in HoneyShield; they are matched by (verified) email, never created.
    oidc_issuer: Optional[str] = None
    oidc_client_id: Optional[str] = None
    oidc_client_secret: Optional[str] = Field(default=None, repr=False)
    oidc_redirect_uri: Optional[str] = None  # https://<control host>/auth/oidc/callback
    oidc_display_name: str = Field(default="Single sign-on", min_length=1, max_length=40)
    oidc_scopes: str = "openid email profile"
    oidc_email_claim: str = Field(default="email", pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
    oidc_require_email_verified: bool = True
    # "amr_claim": an SSO session counts as MFA only if the ID token's amr says so (mfa, otp,
    # hwk, ...). "trust_idp": the IdP always enforces MFA, so every SSO session counts as MFA.
    oidc_mfa: Literal["amr_claim", "trust_idp"] = "amr_claim"
    oidc_ca_file: Optional[str] = None  # only for an IdP with a private CA
    # Absolute session length: /auth/refresh renews tokens only until this long after sign-in.
    session_max_hours: int = Field(default=12, ge=1, le=168)
    login_attempts_per_minute: int = Field(default=30, ge=1, le=1000)
    # Failed passwords allowed per account (across all IPs) per window before sign-in is refused
    # for that address (unknown addresses count the same). 0 disables. NIST SP 800-63B: <= 100.
    login_account_failures_allowed: int = Field(default=10, ge=0, le=100)
    login_account_failure_window_seconds: int = Field(default=900, ge=60, le=86400)
    login_global_attempts_per_minute: int = Field(default=600, ge=1, le=10000)

    # Phase 7 — Input Security & Rate Limiting Settings
    max_request_body_bytes: int = Field(default=1_048_576, ge=1024, le=52_428_800)  # Default: 1 MB
    rate_limit_enabled: bool = Field(default=True)
    rate_limit_per_minute_authenticated: int = Field(default=300, ge=1, le=10000)
    rate_limit_per_minute_public: int = Field(default=120, ge=1, le=10000)
    rate_limit_global_per_minute: int = Field(default=5000, ge=10, le=100000)
    ingestion_rate_limit_per_minute_ip: int = Field(default=120, ge=1, le=10000)
    ingestion_rate_limit_per_minute_token: int = Field(default=60, ge=1, le=10000)

    # Phase 7 — Header Security Settings
    header_max_key_length: int = Field(default=64, ge=8, le=256)
    header_max_value_length: int = Field(default=1024, ge=16, le=8192)
    header_max_count: int = Field(default=30, ge=5, le=100)
    header_max_total_bytes: int = Field(default=4096, ge=512, le=32768)

    # Phase 7 — Trusted Proxy Settings
    trusted_proxies: Union[list[str], str] = Field(default_factory=lambda: ["127.0.0.1", "::1"])

    # Public HoneyShield ingestion origin embedded in every generated honey-token artifact
    # (e.g. https://ingest.example.com). Must NOT be the customer's own domain.
    public_ingest_base_url: Optional[str] = None
    # Path prefixes of decoy URLs (app/core/decoy_paths.py). The defaults are the same in every
    # installation and therefore recognisable; choose your own so decoys do not point to HoneyShield.
    decoy_link_path: str = "t"
    decoy_pixel_path: str = "px"
    decoy_collect_path: str = "collect"
    # Keep answering on /t/, /px/ and /collect/ for decoys generated before the paths changed.
    decoy_legacy_paths: bool = True

    # Hostnames that serve the operator API (e.g. app.example.com). When set together with
    # PUBLIC_INGEST_BASE_URL, the app enforces host separation: ingest routes are served only
    # on the ingest host and every other route only on a control-plane host. Required in production.
    control_plane_hostnames: Union[list[str], str] = Field(default_factory=list)
    # Addresses allowed to use the operator console and API (comma-separated IPs/CIDRs). Empty: any
    # address. The edge enforces it (HS_CONTROL_ALLOW_CIDRS) and the backend re-checks every request
    # that arrives through the trusted proxy. The ingest host is never restricted.
    control_plane_allowed_cidrs: Optional[str] = None
    # OpenAPI/Swagger UI. Off by default in production/staging (HONEY-033).
    expose_api_docs: Optional[bool] = None

    # Master key from which every customer-integration signing secret is derived
    # (HMAC-SHA256(key, public_id | salt)). Rotating it invalidates all integration
    # credentials. Required in production; integrations are disabled when unset.
    integration_signing_key: Optional[str] = Field(default=None, repr=False)
    # Operator MFA (HONEY-029). TOTP secrets are derived as HMAC-SHA256(MFA_SECRET_KEY, user | nonce)
    # and never stored. Required in production; development/test derive a key from JWT_SECRET_KEY.
    # Rotating it invalidates every enrolment (users re-enrol after an admin reset).
    mfa_secret_key: Optional[str] = Field(default=None, repr=False)
    # Comma-separated roles that must use MFA. Unset: SYSTEM_ADMIN,TENANT_ADMIN in production/staging,
    # none elsewhere. "none" disables the requirement (a documented risk acceptance).
    mfa_required_roles: Optional[str] = None
    mfa_issuer: str = Field(default="HoneyShield", min_length=1, max_length=64)
    # Passkeys (WebAuthn). The RP ID is the operator host passkeys are bound to; unset: the first
    # CONTROL_PLANE_HOSTNAMES entry (else "localhost"). A passkey only ever works on that host, which
    # is what makes it phishing-resistant: a look-alike site cannot use it.
    webauthn_rp_id: Optional[str] = None
    # Exact console origins allowed in a ceremony (comma-separated). Unset: https://<rp id> on any
    # port, and plain http only when the RP ID is localhost.
    webauthn_origins: Optional[str] = None
    integration_timestamp_tolerance_seconds: int = Field(default=300, ge=30, le=900)
    integration_reports_per_minute: int = Field(default=1200, ge=1, le=100000)

    # Alert delivery (HONEY-007). Webhook signing secrets are derived from
    # INTEGRATION_SIGNING_KEY with a separate label. Private/loopback/link-local targets are
    # always refused; plain http is refused unless explicitly allowed (development only).
    alert_allow_http_webhooks: bool = Field(default=False)
    alert_delivery_timeout_seconds: float = Field(default=5.0, ge=1.0, le=30.0)
    alert_max_attempts: int = Field(default=8, ge=1, le=20)
    alert_worker_batch_size: int = Field(default=20, ge=1, le=500)
    alert_worker_poll_seconds: float = Field(default=2.0, ge=0.2, le=60.0)
    # Self-hosted deployments whose SIEM/webhook receiver sits on a private network may allow
    # specific CIDRs (comma-separated). Loopback, link-local (cloud metadata), multicast and
    # unspecified addresses stay refused even if listed. Leave empty for a multi-tenant SaaS.
    alert_allowed_private_cidrs: Optional[str] = None
    # EMAIL destinations go through this operator-run SMTP relay. Unset: EMAIL is unavailable.
    smtp_host: Optional[str] = None
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_security: Literal["starttls", "tls", "none"] = "starttls"
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = Field(default=None, repr=False)
    smtp_from: Optional[str] = Field(default=None, max_length=254)
    # Shared state for several API replicas (rate limits + live stream fan-out). Unset: process-
    # local state, which is only correct with a single API process. app/core/shared_state.py
    redis_url: Optional[str] = Field(default=None, repr=False)
    # Write-once shipping of signed checkpoints to S3 Object Lock (app/services/worm.py).
    # Unset bucket: checkpoints stay in the local evidence_checkpoints volume only.
    evidence_s3_endpoint: Optional[str] = None
    evidence_s3_bucket: Optional[str] = None
    evidence_s3_region: str = "us-east-1"
    evidence_s3_access_key_id: Optional[str] = Field(default=None, repr=False)
    evidence_s3_secret_access_key: Optional[str] = Field(default=None, repr=False)
    evidence_s3_prefix: str = "checkpoints/"
    evidence_s3_retention_days: int = Field(default=400, ge=1, le=36500)
    evidence_s3_lock_mode: Literal["COMPLIANCE", "GOVERNANCE"] = "COMPLIANCE"
    evidence_s3_ca_file: Optional[str] = None
    # Retention (app.services.retention, run by the owner-role maintenance job). 0 = keep forever;
    # otherwise at least 30 days. Purged data is archived write-once first.
    event_retention_days: int = Field(default=0, ge=0, le=36500)
    audit_retention_days: int = Field(default=0, ge=0, le=36500)
    retention_archive_dir: str = "/evidence-archive"
    # Bearer token for GET /metrics (Prometheus). Unset: the endpoint does not exist.
    metrics_token: Optional[str] = Field(default=None, repr=False)

    # Watchdog (app/workers/watchdog.py): end-to-end self-test, health checks, operator notices
    # and an outgoing heartbeat for an outside dead-man's switch (docs/watchdog.md).
    watchdog_interval_seconds: int = Field(default=300, ge=30, le=3600)
    # Where the self-test hit is sent. Unset: PUBLIC_INGEST_BASE_URL. WATCHDOG_PROBE_CONNECT
    # (host:port) connects somewhere else while keeping that host name for TLS and Host, e.g. the
    # edge's internal address on a server that cannot reach its own public address.
    watchdog_probe_url: Optional[str] = None
    watchdog_probe_connect: Optional[str] = None
    watchdog_probe_verify_tls: bool = True
    watchdog_probe_ca_file: Optional[str] = None
    watchdog_probe_timeout_seconds: float = Field(default=15.0, ge=2.0, le=120.0)
    # Notices go to an operator channel that does not depend on the customer alert pipeline.
    watchdog_notify_webhook_url: Optional[str] = Field(default=None, repr=False)
    watchdog_notify_format: Literal["auto", "json", "text"] = "auto"
    watchdog_notify_email: Optional[str] = Field(default=None, max_length=254)
    # Pinged after every cycle without a critical problem (Healthchecks.io, Uptime Kuma push,
    # Better Stack, Cronitor...). If the server dies, the pings stop and that service warns you.
    watchdog_heartbeat_url: Optional[str] = Field(default=None, repr=False)
    watchdog_heartbeat_fail_url: Optional[str] = Field(default=None, repr=False)
    watchdog_remind_hours: int = Field(default=6, ge=1, le=168)
    watchdog_alert_backlog_minutes: int = Field(default=15, ge=1, le=1440)
    watchdog_spool_path: Optional[str] = None
    watchdog_spool_state_path: Optional[str] = None
    watchdog_spool_max_minutes: int = Field(default=30, ge=5, le=1440)
    watchdog_disk_path: Optional[str] = None
    watchdog_disk_min_free_percent: float = Field(default=10.0, ge=1.0, le=90.0)
    watchdog_cert_warn_days: int = Field(default=14, ge=1, le=90)
    # Name shown in notices. Unset: the first CONTROL_PLANE_HOSTNAMES entry.
    watchdog_instance_name: Optional[str] = Field(default=None, max_length=100)
    checkpoint_interval_seconds: int = Field(default=900, ge=60, le=86400)
    backup_max_age_hours: int = Field(default=26, ge=1, le=24 * 31)

    # Encrypted backups (app/workers/backup.py, docs/backup-and-restore.md). Unset recipients: backups are off.
    # age public keys ("age1..."), comma-separated; the matching identity stays OFF the server.
    backup_age_recipients: Optional[str] = None
    backup_interval_hours: int = Field(default=24, ge=1, le=168)
    backup_dir: str = "/backups"
    backup_keep_local: int = Field(default=3, ge=1, le=100)
    # Off-site copy in any S3-compatible bucket. Unset bucket: backups stay on this server only.
    backup_s3_endpoint: Optional[str] = None
    backup_s3_bucket: Optional[str] = None
    backup_s3_region: str = "us-east-1"
    backup_s3_access_key_id: Optional[str] = Field(default=None, repr=False)
    backup_s3_secret_access_key: Optional[str] = Field(default=None, repr=False)
    backup_s3_prefix: str = "honeyshield-backups/"
    backup_s3_ca_file: Optional[str] = None
    # Off-site copies older than this are deleted, but the newest 7 are always kept.
    backup_keep_days: int = Field(default=30, ge=1, le=3650)
    # Optional: the identity file, to prove regularly that the latest off-site copy decrypts and is
    # a readable dump. Without it the server can write backups but never read them.
    backup_identity_file: Optional[str] = None
    backup_verify_every_days: int = Field(default=7, ge=1, le=90)
    backup_pg_dump: str = "pg_dump"
    backup_pg_restore: str = "pg_restore"

    # Phase 11 — CORS Policy Settings (F-014)
    cors_allowed_origins: Union[list[str], str] = Field(default_factory=list)
    cors_allow_credentials: bool = Field(default=False)
    cors_allow_methods: Union[list[str], str] = Field(
        default_factory=lambda: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
    )
    cors_allow_headers: Union[list[str], str] = Field(
        default_factory=lambda: ["Authorization", "Content-Type", "Accept", "X-Request-ID"]
    )
    cors_expose_headers: Union[list[str], str] = Field(
        default_factory=lambda: ["X-Request-ID", "X-Process-Time-Ms", "Retry-After"]
    )
    cors_max_age: int = Field(default=600, ge=0, le=86400)

    # Phase 10 — Security Headers Settings (F-015)
    security_headers_enabled: bool = Field(default=True)
    security_headers_x_content_type_options: str = Field(default="nosniff")
    security_headers_x_frame_options: str = Field(default="DENY")
    security_headers_referrer_policy: str = Field(default="no-referrer")
    security_headers_csp: str = Field(default="default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
    security_headers_permissions_policy: str = Field(
        default="accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"
    )
    security_headers_cache_control: str = Field(default="no-store")
    security_headers_hsts_enabled: bool = Field(default=False)
    security_headers_hsts_max_age: int = Field(default=31536000, ge=0, le=63072000)
    security_headers_hsts_include_subdomains: bool = Field(default=True)
    security_headers_hsts_preload: bool = Field(default=False)

    @field_validator("trusted_proxies", mode="before")
    @classmethod
    def parse_trusted_proxies(cls, value: Any) -> list[str]:
        if isinstance(value, str):
            trimmed = value.strip()
            if trimmed.startswith("[") and trimmed.endswith("]"):
                try:
                    value = json.loads(trimmed)
                except Exception:
                    pass
        if isinstance(value, str):
            return [p.strip() for p in value.split(",") if p.strip()]
        if isinstance(value, (list, tuple, set)):
            return [str(p).strip() for p in value if str(p).strip()]
        return ["127.0.0.1", "::1"]

    @field_validator("cors_allowed_origins", mode="before")
    @classmethod
    def parse_and_validate_cors_origins(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            trimmed = value.strip()
            if trimmed.startswith("[") and trimmed.endswith("]"):
                try:
                    value = json.loads(trimmed)
                except Exception:
                    pass
        raw_list: list[str]
        if isinstance(value, str):
            raw_list = [item.strip() for item in value.split(",") if item.strip()]
        elif isinstance(value, (list, tuple, set)):
            raw_list = [str(item).strip() for item in value if str(item).strip()]
        else:
            raise ValueError(f"Invalid type for cors_allowed_origins: {type(value)}")

        validated_origins: list[str] = []
        for raw in raw_list:
            if raw == "*":
                raise ValueError("Wildcard '*' CORS origins are strictly forbidden")
            if "*" in raw:
                raise ValueError(f"Wildcard patterns are forbidden in CORS origins: {raw}")

            parsed = urllib.parse.urlsplit(raw)
            scheme = parsed.scheme.lower()
            if scheme not in ("http", "https"):
                raise ValueError(
                    f"Invalid CORS origin scheme '{parsed.scheme}': only http and https are permitted ({raw})"
                )

            netloc = parsed.netloc.lower()
            if not netloc or not parsed.hostname:
                raise ValueError(f"Invalid CORS origin: missing host ({raw})")

            if parsed.username or parsed.password:
                raise ValueError(f"CORS origin must not contain user credentials: {raw}")

            if parsed.path and parsed.path != "/":
                raise ValueError(f"CORS origin must not contain a path component: {raw}")

            if parsed.query:
                raise ValueError(f"CORS origin must not contain query parameters: {raw}")

            if parsed.fragment:
                raise ValueError(f"CORS origin must not contain URL fragments: {raw}")

            canonical_origin = f"{scheme}://{netloc}"
            if canonical_origin not in validated_origins:
                validated_origins.append(canonical_origin)

        return validated_origins

    @field_validator("cors_allow_methods", mode="before")
    @classmethod
    def parse_and_validate_cors_methods(cls, value: Any) -> list[str]:
        if value is None:
            return ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
        if isinstance(value, str):
            trimmed = value.strip()
            if trimmed.startswith("[") and trimmed.endswith("]"):
                try:
                    value = json.loads(trimmed)
                except Exception:
                    pass
        raw_list: list[str]
        if isinstance(value, str):
            raw_list = [item.strip() for item in value.split(",") if item.strip()]
        elif isinstance(value, (list, tuple, set)):
            raw_list = [str(item).strip() for item in value if str(item).strip()]
        else:
            raise ValueError(f"Invalid type for cors_allow_methods: {type(value)}")

        allowed_methods = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}
        validated_methods: list[str] = []
        for raw in raw_list:
            method = raw.upper()
            if method == "*":
                raise ValueError("Wildcard '*' is forbidden in cors_allow_methods; specify explicit methods")
            if method not in allowed_methods:
                raise ValueError(f"Invalid HTTP method '{method}' in cors_allow_methods")
            if method not in validated_methods:
                validated_methods.append(method)
        return validated_methods or ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]

    @field_validator("cors_allow_headers", mode="before")
    @classmethod
    def parse_and_validate_cors_headers(cls, value: Any) -> list[str]:
        if value is None:
            return ["Authorization", "Content-Type", "Accept", "X-Request-ID"]
        if isinstance(value, str):
            trimmed = value.strip()
            if trimmed.startswith("[") and trimmed.endswith("]"):
                try:
                    value = json.loads(trimmed)
                except Exception:
                    pass
        raw_list: list[str]
        if isinstance(value, str):
            raw_list = [item.strip() for item in value.split(",") if item.strip()]
        elif isinstance(value, (list, tuple, set)):
            raw_list = [str(item).strip() for item in value if str(item).strip()]
        else:
            raise ValueError(f"Invalid type for cors_allow_headers: {type(value)}")

        validated_headers: list[str] = []
        for raw in raw_list:
            if raw == "*":
                raise ValueError("Wildcard '*' is forbidden in cors_allow_headers; specify explicit headers")
            if not any(h.lower() == raw.lower() for h in validated_headers):
                validated_headers.append(raw)
        return validated_headers or ["Authorization", "Content-Type", "Accept", "X-Request-ID"]

    @field_validator("cors_expose_headers", mode="before")
    @classmethod
    def parse_and_validate_cors_expose_headers(cls, value: Any) -> list[str]:
        if value is None:
            return ["X-Request-ID", "X-Process-Time-Ms", "Retry-After"]
        if isinstance(value, str):
            trimmed = value.strip()
            if trimmed.startswith("[") and trimmed.endswith("]"):
                try:
                    value = json.loads(trimmed)
                except Exception:
                    pass
        raw_list: list[str]
        if isinstance(value, str):
            raw_list = [item.strip() for item in value.split(",") if item.strip()]
        elif isinstance(value, (list, tuple, set)):
            raw_list = [str(item).strip() for item in value if str(item).strip()]
        else:
            raise ValueError(f"Invalid type for cors_expose_headers: {type(value)}")

        validated_headers: list[str] = []
        for raw in raw_list:
            if raw == "*":
                raise ValueError("Wildcard '*' is forbidden in cors_expose_headers; specify explicit headers")
            if not any(h.lower() == raw.lower() for h in validated_headers):
                validated_headers.append(raw)
        return validated_headers or ["X-Request-ID", "X-Process-Time-Ms", "Retry-After"]

    @field_validator("security_headers_x_frame_options")
    @classmethod
    def validate_x_frame_options(cls, value: str) -> str:
        val = value.strip().upper()
        if val not in ("DENY", "SAMEORIGIN"):
            raise ValueError(f"Invalid X-Frame-Options '{value}': must be DENY or SAMEORIGIN")
        return val

    @field_validator("security_headers_referrer_policy")
    @classmethod
    def validate_referrer_policy(cls, value: str) -> str:
        valid_policies = {
            "no-referrer",
            "no-referrer-when-downgrade",
            "origin",
            "origin-when-cross-origin",
            "same-origin",
            "strict-origin",
            "strict-origin-when-cross-origin",
            "unsafe-url",
        }
        val = value.strip().lower()
        if val not in valid_policies:
            raise ValueError(f"Invalid Referrer-Policy '{value}'")
        return val

    @field_validator("security_headers_csp")
    @classmethod
    def validate_csp(cls, value: str) -> str:
        val = value.strip()
        if not val:
            raise ValueError("Content-Security-Policy must not be empty")
        if "'unsafe-inline'" in val or "'unsafe-eval'" in val:
            raise ValueError("Unsafe CSP directives ('unsafe-inline', 'unsafe-eval') are forbidden for the API")
        return val

    @field_validator("public_ingest_base_url", mode="before")
    @classmethod
    def validate_public_ingest_base_url(cls, value: Any) -> Optional[str]:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("PUBLIC_INGEST_BASE_URL must be a string")
        raw = value.strip()
        if not raw:
            return None
        parsed = urllib.parse.urlsplit(raw)
        if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
            raise ValueError("PUBLIC_INGEST_BASE_URL must be an http(s) origin such as https://ingest.example.com")
        if parsed.username or parsed.password:
            raise ValueError("PUBLIC_INGEST_BASE_URL must not contain user credentials")
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise ValueError("PUBLIC_INGEST_BASE_URL must be an origin only (no path, query or fragment)")
        return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"

    @field_validator("control_plane_hostnames", mode="before")
    @classmethod
    def parse_control_plane_hostnames(cls, value: Any) -> list[str]:
        if value is None:
            return []
        items = value.split(",") if isinstance(value, str) else list(value)
        hosts = []
        for item in items:
            host = str(item).strip().lower().rstrip(".")
            if not host:
                continue
            if not re.fullmatch(r"[a-z0-9.-]{1,253}|\[[0-9a-f:]+\]", host):
                raise ValueError(f"Invalid control-plane hostname: {item!r}")
            hosts.append(host)
        return hosts

    @field_validator("integration_signing_key")
    @classmethod
    def validate_integration_signing_key(cls, value: Optional[str]) -> Optional[str]:
        if value is None or not value.strip():
            return None
        if len(value.encode("utf-8")) < 32 or value != value.strip():
            raise ValueError("INTEGRATION_SIGNING_KEY must contain at least 32 bytes without surrounding whitespace")
        return value

    @field_validator("mfa_secret_key")
    @classmethod
    def validate_mfa_secret_key(cls, value: Optional[str]) -> Optional[str]:
        if value is None or not value.strip():
            return None
        if len(value.encode("utf-8")) < 32 or value != value.strip():
            raise ValueError("MFA_SECRET_KEY must contain at least 32 bytes without surrounding whitespace")
        return value

    @field_validator("mfa_required_roles")
    @classmethod
    def validate_mfa_required_roles(cls, value: Optional[str]) -> Optional[str]:
        if value is None or not value.strip():
            return None
        if value.strip().lower() == "none":
            return "none"
        allowed = {"SYSTEM_ADMIN", "TENANT_ADMIN", "TENANT_USER"}
        roles = [r.strip().upper() for r in value.split(",") if r.strip()]
        unknown = [r for r in roles if r not in allowed]
        if unknown:
            raise ValueError(f"MFA_REQUIRED_ROLES contains unknown roles: {unknown}")
        return ",".join(roles)

    @field_validator("jwt_secret_key")
    @classmethod
    def validate_signing_key(cls, value: str) -> str:
        if len(value.encode("utf-8")) < 32 or value != value.strip() or not value.strip():
            raise ValueError("JWT_SECRET_KEY must contain at least 32 bytes without surrounding whitespace")
        return value

    @model_validator(mode="after")
    def validate_production_configuration(self) -> Settings:
        if self.app_env.lower() in ("production", "prod", "staging"):
            if not self.database_url:
                if not self.postgres_password or self.postgres_password in (
                    "honeyshield_dev_password", "postgres", "password", "admin", "root"
                ):
                    raise ValueError("POSTGRES_PASSWORD must be explicitly configured with a secure value in production")

            insecure_key_patterns = (
                "dev_secret", "test_secret", "change_me", "placeholder",
                "default_secret", "example_secret", "secret_key_12345"
            )
            key_lower = self.jwt_secret_key.lower()
            if any(pattern in key_lower for pattern in insecure_key_patterns):
                raise ValueError("JWT_SECRET_KEY must not contain insecure default/placeholder patterns in production")

            # Generated honey-token artifacts must resolve to HoneyShield; without this origin
            # every delivered token would silently never report an interaction.
            if not self.public_ingest_base_url:
                raise ValueError("PUBLIC_INGEST_BASE_URL must be configured in production")
            if not self.public_ingest_base_url.startswith("https://"):
                raise ValueError("PUBLIC_INGEST_BASE_URL must use https in production")
            if not self.integration_signing_key:
                raise ValueError("INTEGRATION_SIGNING_KEY must be configured in production")
            if not self.control_plane_hostnames:
                raise ValueError("CONTROL_PLANE_HOSTNAMES must be configured in production")
            if self.ingest_hostname in self.control_plane_hostnames:
                raise ValueError("The ingest host must differ from every CONTROL_PLANE_HOSTNAMES entry")
            if self.alert_allow_http_webhooks:
                raise ValueError("ALERT_ALLOW_HTTP_WEBHOOKS must be false in production")
            if self.smtp_host and self.smtp_security == "none":
                raise ValueError("SMTP_SECURITY must be starttls or tls in production")
            if self.integration_signing_key == self.jwt_secret_key:
                raise ValueError("INTEGRATION_SIGNING_KEY must differ from JWT_SECRET_KEY")
            if not self.mfa_secret_key:
                raise ValueError("MFA_SECRET_KEY must be configured in production")
            if self.mfa_secret_key in (self.jwt_secret_key, self.integration_signing_key):
                raise ValueError("MFA_SECRET_KEY must differ from JWT_SECRET_KEY and INTEGRATION_SIGNING_KEY")
        return self

    @model_validator(mode="after")
    def validate_alert_channels(self) -> Settings:
        if self.smtp_host and not self.smtp_from:
            raise ValueError("SMTP_FROM is required when SMTP_HOST is set")
        if bool(self.smtp_username) != bool(self.smtp_password):
            raise ValueError("SMTP_USERNAME and SMTP_PASSWORD must be set together")
        self.alert_private_networks  # validates the CIDR list
        self.control_plane_networks  # validates the operator allowlist
        return self

    @model_validator(mode="after")
    def validate_oidc(self) -> Settings:
        if not self.oidc_issuer:
            return self
        missing = [n for n, v in (("OIDC_CLIENT_ID", self.oidc_client_id),
                                  ("OIDC_CLIENT_SECRET", self.oidc_client_secret),
                                  ("OIDC_REDIRECT_URI", self.oidc_redirect_uri)) if not v]
        if missing:
            raise ValueError("OIDC_ISSUER requires " + ", ".join(missing))
        if "openid" not in self.oidc_scopes.split():
            raise ValueError("OIDC_SCOPES must include openid")
        if self.app_env.lower() in ("production", "prod", "staging"):
            for name, url in (("OIDC_ISSUER", self.oidc_issuer), ("OIDC_REDIRECT_URI", self.oidc_redirect_uri)):
                if not url.startswith("https://"):
                    raise ValueError(f"{name} must use https in production")
        return self

    @model_validator(mode="after")
    def validate_decoy_paths(self) -> Settings:
        from app.core import decoy_paths
        self.decoy_link_path = self.decoy_link_path.strip().strip("/").lower()
        self.decoy_pixel_path = self.decoy_pixel_path.strip().strip("/").lower()
        self.decoy_collect_path = self.decoy_collect_path.strip().strip("/").lower()
        decoy_paths.validate(self.decoy_link_path, self.decoy_pixel_path, self.decoy_collect_path,
                             self.decoy_legacy_paths)
        return self

    @model_validator(mode="after")
    def validate_backups(self) -> Settings:
        if self.backup_age_recipients is not None and not self.backup_age_recipients.strip():
            self.backup_age_recipients = None
        if self.backup_age_recipients:
            from app.core import agecrypt
            for r in self.backup_recipient_list:
                try:
                    agecrypt.parse_recipient(r)
                except agecrypt.AgeError as exc:
                    raise ValueError(f"BACKUP_AGE_RECIPIENTS: {exc}") from exc
        if self.backup_s3_bucket is not None and not self.backup_s3_bucket.strip():
            self.backup_s3_bucket = None
        if self.backup_s3_bucket:
            missing = [n for n, v in (("BACKUP_S3_ENDPOINT", self.backup_s3_endpoint),
                                      ("BACKUP_S3_ACCESS_KEY_ID", self.backup_s3_access_key_id),
                                      ("BACKUP_S3_SECRET_ACCESS_KEY", self.backup_s3_secret_access_key)) if not v]
            if missing:
                raise ValueError("BACKUP_S3_BUCKET requires " + ", ".join(missing))
            if not self.backup_s3_endpoint.startswith(("https://", "http://")):
                raise ValueError("BACKUP_S3_ENDPOINT must be an http(s) URL")
            if self.is_production_like and not self.backup_s3_endpoint.startswith("https://"):
                raise ValueError("BACKUP_S3_ENDPOINT must use https in production")
            if self.backup_s3_prefix.startswith("/") or not self.backup_s3_prefix.endswith("/"):
                raise ValueError("BACKUP_S3_PREFIX must be a relative path ending in '/'")
            if not self.backup_age_recipients:
                raise ValueError("BACKUP_S3_BUCKET needs BACKUP_AGE_RECIPIENTS: backups never leave the "
                                 "server unencrypted")
        return self

    @property
    def backup_recipient_list(self) -> list[str]:
        return [r.strip() for r in (self.backup_age_recipients or "").split(",") if r.strip()]

    @model_validator(mode="after")
    def validate_watchdog(self) -> Settings:
        for name in ("watchdog_probe_url", "watchdog_notify_webhook_url", "watchdog_heartbeat_url",
                     "watchdog_heartbeat_fail_url"):
            value = getattr(self, name)
            if value is not None and not value.strip():
                setattr(self, name, None)
                continue
            if value is None:
                continue
            parts = urllib.parse.urlsplit(value.strip())
            if parts.scheme not in ("http", "https") or not parts.hostname:
                raise ValueError(f"{name.upper()} must be an http(s) URL")
            if self.is_production_like and parts.scheme != "https" and name != "watchdog_probe_url":
                raise ValueError(f"{name.upper()} must use https in production")
        if self.watchdog_probe_connect:
            if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}:\d{1,5}|\[[0-9A-Fa-f:]+\]:\d{1,5}",
                                self.watchdog_probe_connect.strip()):
                raise ValueError("WATCHDOG_PROBE_CONNECT must be host:port")
        else:
            self.watchdog_probe_connect = None
        if self.watchdog_notify_email is not None:
            if not self.watchdog_notify_email.strip():
                self.watchdog_notify_email = None
            elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", self.watchdog_notify_email.strip()):
                raise ValueError("WATCHDOG_NOTIFY_EMAIL must be one email address")
        return self

    @property
    def oidc_enabled(self) -> bool:
        return bool(self.oidc_issuer)

    @model_validator(mode="after")
    def validate_retention(self) -> Settings:
        for name, days in (("EVENT_RETENTION_DAYS", self.event_retention_days),
                           ("AUDIT_RETENTION_DAYS", self.audit_retention_days)):
            if 0 < days < 30:
                raise ValueError(f"{name} must be 0 (keep forever) or at least 30")
        return self

    @model_validator(mode="after")
    def validate_evidence_s3(self) -> Settings:
        if not self.evidence_s3_bucket:
            return self
        missing = [name for name, value in (
            ("EVIDENCE_S3_ENDPOINT", self.evidence_s3_endpoint),
            ("EVIDENCE_S3_ACCESS_KEY_ID", self.evidence_s3_access_key_id),
            ("EVIDENCE_S3_SECRET_ACCESS_KEY", self.evidence_s3_secret_access_key)) if not value]
        if missing:
            raise ValueError("EVIDENCE_S3_BUCKET requires " + ", ".join(missing))
        if not self.evidence_s3_endpoint.startswith(("https://", "http://")):
            raise ValueError("EVIDENCE_S3_ENDPOINT must be an http(s) URL")
        if self.app_env.lower() in ("production", "prod", "staging") and not self.evidence_s3_endpoint.startswith("https://"):
            raise ValueError("EVIDENCE_S3_ENDPOINT must use https in production")
        if not self.evidence_s3_prefix or self.evidence_s3_prefix.startswith("/") or not self.evidence_s3_prefix.endswith("/"):
            raise ValueError("EVIDENCE_S3_PREFIX must be a relative path ending in '/'")
        return self

    @property
    def control_plane_networks(self) -> tuple:
        import ipaddress

        if not self.control_plane_allowed_cidrs:
            return ()
        nets = []
        for part in self.control_plane_allowed_cidrs.replace(" ", ",").split(","):
            part = part.strip()
            if not part:
                continue
            try:
                nets.append(ipaddress.ip_network(part, strict=False))
            except ValueError as exc:
                raise ValueError(f"CONTROL_PLANE_ALLOWED_CIDRS: invalid network {part!r}") from exc
        return tuple(nets)

    @property
    def alert_private_networks(self) -> tuple:
        import ipaddress

        if not self.alert_allowed_private_cidrs:
            return ()
        nets = []
        for part in self.alert_allowed_private_cidrs.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                nets.append(ipaddress.ip_network(part, strict=False))
            except ValueError as exc:
                raise ValueError(f"ALERT_ALLOWED_PRIVATE_CIDRS: invalid network {part!r}") from exc
        return tuple(nets)

    @model_validator(mode="after")
    def validate_cors_credentials(self) -> Settings:
        if self.cors_allow_credentials and "*" in self.cors_allowed_origins:
            raise ValueError("Wildcard origins cannot be used when cors_allow_credentials is True")
        return self

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        hide_input_in_errors=True,
    )

    @property
    def sqlalchemy_database_uri(self) -> str:
        if self.database_url:
            return self.database_url

        return URL.create(
            "postgresql+psycopg2",
            username=self.postgres_user,
            password=self.postgres_password,
            host=self.postgres_host,
            port=self.postgres_port,
            database=self.postgres_db,
        ).render_as_string(hide_password=False)

    @property
    def migration_database_uri(self) -> str:
        """Owner connection for Alembic and grants; falls back to the runtime URI (development)."""
        if self.migration_database_url:
            return self.migration_database_url
        if self.postgres_migration_user:
            return URL.create(
                "postgresql+psycopg2",
                username=self.postgres_migration_user,
                password=self.postgres_migration_password,
                host=self.postgres_host,
                port=self.postgres_port,
                database=self.postgres_db,
            ).render_as_string(hide_password=False)
        return self.sqlalchemy_database_uri

    @property
    def ingest_hostname(self) -> Optional[str]:
        if not self.public_ingest_base_url:
            return None
        return urllib.parse.urlsplit(self.public_ingest_base_url).hostname

    @property
    def host_separation_enabled(self) -> bool:
        return bool(self.ingest_hostname and self.control_plane_hostnames)

    @property
    def api_docs_enabled(self) -> bool:
        if self.expose_api_docs is not None:
            return self.expose_api_docs
        return not self.is_production_like

    @property
    def is_production_like(self) -> bool:
        return self.app_env.lower() in ("production", "prod", "staging")

    @property
    def mfa_required_role_names(self) -> frozenset[str]:
        if self.mfa_required_roles == "none":
            return frozenset()
        if self.mfa_required_roles:
            return frozenset(self.mfa_required_roles.split(","))
        return frozenset({"SYSTEM_ADMIN", "TENANT_ADMIN"}) if self.is_production_like else frozenset()

    @property
    def webauthn_rp(self) -> str:
        if self.webauthn_rp_id:
            return self.webauthn_rp_id.strip().lower().rstrip(".")
        return self.control_plane_hostnames[0] if self.control_plane_hostnames else "localhost"

    def webauthn_origin_allowed(self, origin: str) -> bool:
        if self.webauthn_origins:
            return origin in [o.strip() for o in self.webauthn_origins.split(",") if o.strip()]
        parts = urllib.parse.urlsplit(origin)
        rp = self.webauthn_rp
        if parts.path or parts.query or parts.fragment or (parts.hostname or "") != rp:
            return False
        return parts.scheme == "https" or (parts.scheme == "http" and rp == "localhost")

    @property
    def mfa_key_bytes(self) -> bytes:
        if self.mfa_secret_key:
            return self.mfa_secret_key.encode("utf-8")
        # Development/test only (production requires MFA_SECRET_KEY): domain-separated from the JWT key.
        import hashlib
        return hashlib.sha256(b"honeyshield-mfa-dev|" + self.jwt_secret_key.encode("utf-8")).digest()

    @property
    def db_least_privilege_enforced(self) -> bool:
        if self.enforce_db_least_privilege is not None:
            return self.enforce_db_least_privilege
        return self.is_production_like


@lru_cache
def get_settings() -> Settings:
    return Settings()
