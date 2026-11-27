"""Active Directory decoys: what domain controllers fetch and report.

The HoneyShield collector (``deploy/active-directory/HoneyShield-DCCollector.ps1``, served to
administrators as the decoy's ``dc-collector`` file) runs on each domain controller every minute.
It signs its requests with a customer-integration credential (app/core/integration_auth.py):

* ``GET /integrations/v1/directory-manifest``: the project's decoy accounts, one entry per name.
* ``POST /integrations/v1/directory-events``: one Windows Security event about a decoy account.

Events are CUSTOMER_HOOK: the customer's controller asserted them. What the event *means* (its kind,
ATT&CK technique and severity) is decided here from the Windows event id, never by the reporter.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.detection_event import DetectionEvent
from app.models.enums import EventSeverity, HoneyTokenType
from app.models.honey_token import HoneyToken
from app.models.integration import IntegrationCredential

if TYPE_CHECKING:
    from app.schemas.integration import DirectoryReport
    from app.services.detection_event import DetectionEventService

#: Context keys stored with a directory event (in place of HTTP headers).
AD_CONTEXT = frozenset({"ad-event-id", "ad-domain-controller", "ad-target", "ad-workstation", "ad-actor",
                        "ad-status", "ad-logon-type", "ad-ticket-encryption", "ad-record-id"})
#: Stored as the event's address when the Windows event has none (4776 names only a workstation).
UNKNOWN_SOURCE = str(ipaddress.IPv4Address(0))


def event_kind(windows_event_id: int, succeeded: bool) -> str:
    """The event's request_path, which also selects its ATT&CK technique (app/core/attack.py)."""
    if windows_event_id == 4769:
        return "ad/service-ticket"
    if windows_event_id == 4662:
        return "ad/object-read"
    if windows_event_id == 4771:
        return "ad/preauth-failure"
    if windows_event_id == 4768:
        return "ad/tgt-issued" if succeeded else "ad/tgt-failure"
    if windows_event_id == 4776:
        return "ad/ntlm-validated" if succeeded else "ad/ntlm-failure"
    if windows_event_id == 4624:
        return "ad/logon-success"
    return "ad/logon-failure"  # 4625


def severity_for(kind: str) -> EventSeverity:
    # Reading the object is what every enumeration tool does to every account: suspicious, but it
    # does not say the reader wanted this one. Everything else is an attempt to use it.
    return EventSeverity.HIGH if kind == "ad/object-read" else EventSeverity.CRITICAL


_PREFIX = re.compile(r"^[^\\]*\\")


def bare_account(name: str) -> str:
    """'CORP\\svc_x', 'svc_x@corp.local' and 'SVC_X' all name svc_x."""
    return _PREFIX.sub("", name).split("@", 1)[0].rstrip("$").lower()


class DirectoryReportService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def _decoys(self, project_id: int) -> list[HoneyToken]:
        stmt = (select(HoneyToken)
                .where(HoneyToken.project_id == project_id, HoneyToken.token_type == HoneyTokenType.AD_ACCOUNT)
                .order_by(HoneyToken.id))
        return list(self.session.scalars(stmt))

    def manifest(self, cred: IntegrationCredential) -> dict[str, Any]:
        """One entry per account name: the active decoy, or else the newest revoked one.

        A rotated decoy keeps its account, and an account whose decoy was revoked but which is
        still in the directory is still worth an alert, so revoked decoys stay listed.
        """
        chosen: dict[str, HoneyToken] = {}
        for token in self._decoys(cred.project_id):
            name = bare_account(str((token.token_metadata or {}).get("account_name") or ""))
            if not name:
                continue
            current = chosen.get(name)
            if current is None or token.is_active or not current.is_active:
                chosen[name] = token
        decoys = []
        for token in sorted(chosen.values(), key=lambda t: t.id):
            meta = token.token_metadata or {}
            decoys.append({"decoy_id": token.decoy_id, "account_name": meta.get("account_name"),
                           "spn": meta.get("spn"), "audit_reads": bool(meta.get("audit_reads")),
                           "is_active": token.is_active})
        self._touch(cred)  # the console shows when each controller last checked in
        self.session.commit()
        return {"version": 1, "generated_at": datetime.now(timezone.utc).isoformat(), "decoys": decoys}

    def resolve(self, cred: IntegrationCredential, decoy_id: str) -> HoneyToken | None:
        token = self.session.scalar(
            select(HoneyToken).where(HoneyToken.decoy_id == decoy_id, HoneyToken.project_id == cred.project_id))
        if token is None or token.token_type != HoneyTokenType.AD_ACCOUNT:
            return None
        return token

    @staticmethod
    def names_match(token: HoneyToken, report: "DirectoryReport") -> bool:
        """The event must be about the decoy's account (a collector bug must not raise false alarms)."""
        expected = bare_account(str((token.token_metadata or {}).get("account_name") or ""))
        return bool(expected) and bare_account(report.target_name) == expected

    def record(self, cred: IntegrationCredential, token: HoneyToken, report: "DirectoryReport",
               event_service: "DetectionEventService") -> DetectionEvent | None:
        """Store one directory event. None for a duplicate (the collector re-sends after a failure)."""
        from app.services.integration import IntegrationReportService

        existing = self.session.scalar(select(DetectionEvent.id).where(
            DetectionEvent.integration_credential_id == cred.id,
            DetectionEvent.idempotency_key == report.idempotency_key))
        if existing is not None:
            return None
        kind = event_kind(report.windows_event_id, report.succeeded)
        context = {
            "ad-event-id": str(report.windows_event_id), "ad-domain-controller": report.domain_controller,
            "ad-target": report.target_name, "ad-workstation": report.workstation, "ad-actor": report.actor,
            "ad-status": report.status, "ad-logon-type": report.logon_type,
            "ad-ticket-encryption": report.ticket_encryption, "ad-record-id": report.record_id,
        }
        try:
            return event_service.record_hook_report(
                token=token, integration_credential_id=cred.id, idempotency_key=report.idempotency_key,
                ip_address=report.source_ip or UNKNOWN_SOURCE, observed_at=report.observed_at,
                request_path=kind, http_method="AD", user_agent=None,
                headers={k: v for k, v in context.items() if v is not None},
                extra_commit=lambda: IntegrationReportService._touch(cred),
                allowed_headers=AD_CONTEXT, severity=severity_for(kind))
        except IntegrityError:
            self.session.rollback()
            return None

    @staticmethod
    def _touch(cred: IntegrationCredential) -> None:
        from app.services.integration import IntegrationReportService

        IntegrationReportService._touch(cred)
