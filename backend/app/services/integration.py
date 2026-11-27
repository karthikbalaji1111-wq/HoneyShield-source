"""Customer integrations: credential lifecycle and CUSTOMER_HOOK report handling.

See docs/customer-integrations.md for the wire contract.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core import integration_auth
from app.core.exceptions import (
    IntegrationNotFoundError,
    ProjectNotFoundError,
    ServiceNotConfiguredError,
)
from app.models.detection_event import DetectionEvent
from app.models.enums import EventSource, HoneyTokenType, Role
from app.models.honey_token import HoneyToken
from app.models.integration import IntegrationCredential
from app.models.project import Project
from app.services.base import BaseService

if TYPE_CHECKING:
    from app.schemas.integration import IntegrationReport

logger = logging.getLogger(__name__)

#: Token types whose use can only be observed by the customer's own code.
HOOK_TOKEN_TYPES = frozenset({HoneyTokenType.API_KEY, HoneyTokenType.FORM_FIELD})
MAX_REPORT_AGE = timedelta(hours=24)
MAX_CLOCK_SKEW = timedelta(minutes=5)


def _signing_key() -> str:
    from app.core.config import get_settings

    key = get_settings().integration_signing_key
    if not key:
        raise ServiceNotConfiguredError("Customer integrations are not configured on this deployment")
    return key


class IntegrationCredentialService(BaseService):
    """Create, list and revoke integration credentials (control plane, TENANT_ADMIN+)."""

    def _project(self, project_domain: str) -> Project:
        from app.core.auth_exceptions import ForbiddenError
        from app.repositories.project import ProjectRepository

        tenant_id = None
        if self.current_user and self.current_user.role != Role.SYSTEM_ADMIN:
            tenant_id = self.current_user.tenant_id
        project = ProjectRepository(self.session).get_by_domain(project_domain, tenant_id=tenant_id)
        if not project:
            raise ProjectNotFoundError(f"Project '{project_domain}' not found")
        try:
            self._authorize_tenant_access(project.tenant_id)
        except ForbiddenError:
            raise ProjectNotFoundError(f"Project '{project_domain}' not found")
        return project

    def create(self, project_domain: str, label: str | None) -> tuple[IntegrationCredential, str]:
        master = _signing_key()
        project = self._project(project_domain)
        cred = IntegrationCredential(
            project_id=project.id,
            label=label,
            created_by_user_id=self.current_user.id if self.current_user else None,
        )
        self.session.add(cred)
        self.session.flush()
        if self.audit_service:
            self.audit_service.record_action(
                event_type="INTEGRATION_CREDENTIAL_CREATED",
                severity="INFO",
                message=f"Integration credential {cred.public_id} created for project {project.id}",
                actor_source="api",
                actor_user_id=self.current_user.id if self.current_user else None,
                target_entity="integration_credential",
                target_id=cred.public_id,
                tenant_id=project.tenant_id,
                project_id=project.id,
                event_metadata={"label": label, "scopes": cred.scopes},
            )
        self.session.commit()
        return cred, integration_auth.derive_secret(master, cred.public_id, cred.key_salt)

    def list(self, project_domain: str) -> list[IntegrationCredential]:
        project = self._project(project_domain)
        stmt = (
            select(IntegrationCredential)
            .where(IntegrationCredential.project_id == project.id)
            .order_by(IntegrationCredential.id.desc())
        )
        return list(self.session.scalars(stmt))

    def revoke(self, project_domain: str, public_id: str) -> IntegrationCredential:
        project = self._project(project_domain)
        cred = self.session.scalar(
            select(IntegrationCredential).where(
                IntegrationCredential.project_id == project.id,
                IntegrationCredential.public_id == public_id,
            )
        )
        if cred is None:
            raise IntegrationNotFoundError(f"Integration '{public_id}' not found")
        if cred.is_active:
            cred.is_active = False
            cred.revoked_at = datetime.now(timezone.utc)
            if self.audit_service:
                self.audit_service.record_action(
                    event_type="INTEGRATION_CREDENTIAL_REVOKED",
                    severity="WARNING",
                    message=f"Integration credential {cred.public_id} revoked",
                    actor_source="api",
                    actor_user_id=self.current_user.id if self.current_user else None,
                    target_entity="integration_credential",
                    target_id=cred.public_id,
                    tenant_id=project.tenant_id,
                    project_id=project.id,
                )
            self.session.commit()
        return cred


@dataclass
class AuthResult:
    credential: IntegrationCredential | None
    failure: str | None = None


class IntegrationReportService:
    """Authenticate signed integration requests and record CUSTOMER_HOOK events."""

    def __init__(self, session: Session) -> None:
        self.session = session

    # -- authentication -------------------------------------------------
    def authenticate(self, headers: Any, method: str, path: str, body: bytes, scope: str,
                     now: float | None = None) -> AuthResult:
        from app.core.config import get_settings

        master = _signing_key()
        public_id = headers.get(integration_auth.HEADER_INTEGRATION) or ""
        raw_ts = headers.get(integration_auth.HEADER_TIMESTAMP)
        signature = headers.get(integration_auth.HEADER_SIGNATURE) or ""
        ts = integration_auth.parse_timestamp(raw_ts)
        if not public_id or len(public_id) > 40 or ts is None or not signature:
            return AuthResult(None, "malformed")
        tolerance = get_settings().integration_timestamp_tolerance_seconds
        if abs((now if now is not None else time.time()) - ts) > tolerance:
            return AuthResult(None, "stale_timestamp")
        cred = self.session.scalar(select(IntegrationCredential).where(IntegrationCredential.public_id == public_id))
        # Derive and compare even for unknown ids so timing does not reveal which ids exist.
        secret = integration_auth.derive_secret(master, public_id, cred.key_salt if cred else "unknown")
        valid = integration_auth.verify(secret, method, path, str(raw_ts), body, signature)
        if cred is None or not valid:
            return AuthResult(None, "bad_signature")
        if not cred.is_active:
            return AuthResult(None, "revoked")
        project = cred.project
        if not project.is_active or not project.tenant.is_active:
            return AuthResult(None, "inactive_owner")
        if not cred.has_scope(scope):
            return AuthResult(None, "scope")
        return AuthResult(cred)

    # -- manifest -------------------------------------------------------
    def manifest(self, cred: IntegrationCredential) -> dict[str, Any]:
        stmt = (
            select(HoneyToken)
            .where(HoneyToken.project_id == cred.project_id, HoneyToken.token_type.in_(list(HOOK_TOKEN_TYPES)))
            .order_by(HoneyToken.id)
        )
        decoys = []
        for token in self.session.scalars(stmt):
            entry: dict[str, Any] = {
                "decoy_id": token.decoy_id,
                "token_type": token.token_type.value,
                # Revoked decoys stay listed: reuse of a retired decoy is still worth reporting.
                "is_active": token.is_active,
            }
            if token.token_type == HoneyTokenType.API_KEY:
                entry["sha256"] = integration_auth.sha256_hex(token.token_value)
            else:
                entry["field_name"] = (token.token_metadata or {}).get("field_name")
            decoys.append(entry)
        return {
            "version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "decoys": decoys,
        }

    # -- reports ----------------------------------------------------------
    def resolve_decoy(self, cred: IntegrationCredential, decoy_id: str) -> HoneyToken | None:
        """Only decoys of the credential's own project can be reported."""
        token = self.session.scalar(
            select(HoneyToken).where(HoneyToken.decoy_id == decoy_id, HoneyToken.project_id == cred.project_id)
        )
        if token is None or token.token_type not in HOOK_TOKEN_TYPES:
            return None
        return token

    def report_leaks_secret(self, token: HoneyToken, report: "IntegrationReport") -> bool:
        """True if any reported value contains the decoy key itself (a misbehaving client)."""
        if token.token_type != HoneyTokenType.API_KEY:
            return False
        secret = token.token_value
        values = [report.request_path or "", report.user_agent or ""]
        values += [str(v) for v in (report.headers or {}).values()]
        return any(secret in v for v in values)

    def record(self, cred: IntegrationCredential, token: HoneyToken, report: "IntegrationReport",
               event_service: "DetectionEventService") -> DetectionEvent | None:
        """Persist one CUSTOMER_HOOK event. Returns None for a duplicate idempotency key."""
        existing = self.session.scalar(
            select(DetectionEvent.id).where(
                DetectionEvent.integration_credential_id == cred.id,
                DetectionEvent.idempotency_key == report.idempotency_key,
            )
        )
        if existing is not None:
            return None
        try:
            event = event_service.record_hook_report(
                token=token,
                integration_credential_id=cred.id,
                idempotency_key=report.idempotency_key,
                ip_address=report.source_ip,
                observed_at=report.observed_at,
                request_path=report.request_path or "",
                http_method=report.http_method or "",
                user_agent=report.user_agent,
                headers=report.headers,
                extra_commit=lambda: self._touch(cred),
            )
        except IntegrityError:
            # Concurrent duplicate: the unique (integration, idempotency_key) constraint won.
            self.session.rollback()
            return None
        return event

    @staticmethod
    def _touch(cred: IntegrationCredential) -> None:
        now = datetime.now(timezone.utc)
        last = cred.last_used_at
        if last is not None and last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        if last is None or now - last > timedelta(minutes=1):
            cred.last_used_at = now


from app.services.detection_event import DetectionEventService  # noqa: E402  (type reference)
