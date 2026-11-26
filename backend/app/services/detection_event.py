"""Detection-event service operations."""
from __future__ import annotations


import logging
from collections.abc import Callable
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.core.exceptions import DetectionEventNotFoundError, HoneyTokenNotFoundError, ValidationError
from app.models.detection_event import DetectionEvent
from app.models.enums import EventSeverity, EventSource, HoneyTokenType
from app.models.honey_token import HoneyToken
from app.repositories.detection_event import DetectionEventRepository
from app.repositories.honey_token import HoneyTokenRepository
from app.services.base import BaseService

class DuplicatePublicHitError(Exception):
    """A public hit with this edge request id is already stored (replay after a partial failure)."""


def _is_duplicate_public_hit(exc: Exception) -> bool:
    """True when the insert hit the one-event-per-edge-request index (PostgreSQL or SQLite wording)."""
    from sqlalchemy.exc import IntegrityError
    if not isinstance(exc, IntegrityError):
        return False
    message = str(getattr(exc, "orig", exc))
    return any(name in message for name in (
        "uq_detection_events_public_request", "uq_detection_events_cloud_event", "detection_events.idempotency_key"))


#: Default severity of a public trigger, by what an interaction with that type implies.
#: URL: someone requested a hidden path nobody is linked to.
#: LINK: hidden link; generic crawlers can follow it, so lower confidence.
#: PIXEL: a decoy document or email was opened somewhere.
#: FORM_FIELD: an automated form submitter, usually a bot.
#: API_KEY: a planted credential was presented.
#: DNS: a decoy host name was looked up; someone read it somewhere and used it.
#: AWS_KEY: a planted cloud credential was used against AWS.
#: DOCUMENT: a decoy Word document was opened.
DEFAULT_SEVERITY_BY_TOKEN_TYPE: dict[HoneyTokenType, EventSeverity] = {
    HoneyTokenType.URL: EventSeverity.HIGH,
    HoneyTokenType.LINK: EventSeverity.MEDIUM,
    HoneyTokenType.PIXEL: EventSeverity.HIGH,
    HoneyTokenType.FORM_FIELD: EventSeverity.MEDIUM,
    HoneyTokenType.API_KEY: EventSeverity.CRITICAL,
    HoneyTokenType.DNS: EventSeverity.HIGH,
    HoneyTokenType.AWS_KEY: EventSeverity.CRITICAL,
    HoneyTokenType.DOCUMENT: EventSeverity.HIGH,
}

#: Longest token value ever stored (honey_tokens.token_value is VARCHAR(512)).
MAX_TOKEN_VALUE_LENGTH = 512


class DetectionEventService(BaseService):
    """Coordinate immutable detection-event recording and retrieval."""

    def __init__(
        self,
        session: Session,
        event_repo: DetectionEventRepository,
        token_repo: HoneyTokenRepository,
        current_user: "User" | None = None,
        audit_service: "AuditLogService" | None = None,
    ) -> None:
        """Initialize the service with event and token repositories.

        Args:
            session: The transaction session for event operations.
            event_repo: Repository used to persist and retrieve events.
            token_repo: Repository used to resolve honey tokens.
            current_user: The authenticated user making the request.
            audit_service: Optional audit service for security events.

        Returns:
            None.
        """
        super().__init__(session, current_user=current_user, audit_service=audit_service)
        self.event_repo = event_repo
        self.token_repo = token_repo

    def _resolve_token_id(self, token_value: str | None) -> int | None:
        """Resolve an optional token value to its database identifier.

        Args:
            token_value: Optional globally unique honey token value.

        Returns:
            The token identifier, or None when no token filter is supplied.

        Raises:
            ValidationError: If a supplied token value is blank.
            HoneyTokenNotFoundError: If no matching token exists.
        """
        if token_value is None:
            return None

        self._validate_required_fields(("Token value", token_value))
        token = self.token_repo.get_by_token(token_value)
        if not token:
            raise HoneyTokenNotFoundError(f"Token '{token_value}' not found")
        return token.id

    @property
    def _scoped_tenant_id(self) -> int | None:
        if self.current_user and self.current_user.role.name != "SYSTEM_ADMIN":
            return self.current_user.tenant_id
        return None

    def record_event(
        self,
        token_value: str,
        ip_address: str,
        request_path: str,
        http_method: str,
        severity: EventSeverity,
        user_agent: str | None = None,
        headers: dict[str, Any] | None = None,
        reason: str | None = None,
    ) -> DetectionEvent:
        """Record an immutable event for an existing honey token.

        Args:
            token_value: Globally unique honey token value that was triggered.
            ip_address: Source IP address of the request.
            request_path: Request path observed during the event.
            http_method: HTTP method observed during the event.
            severity: Classified severity of the event.
            user_agent: Optional request user-agent value.
            headers: Optional captured request headers.

        Returns:
            The persisted detection event.

        Raises:
            ValidationError: If a required value is blank.
            HoneyTokenNotFoundError: If the referenced token does not exist.
        """
        self._validate_required_fields(
            ("Token value", token_value),
            ("IP address", ip_address),
            ("Request path", request_path),
            ("HTTP method", http_method),
        )

        from app.core.config import get_settings
        from app.core.header_security import sanitize_forensic_headers
        from app.core.ip_trust import normalize_ip

        settings = get_settings()
        try:
            norm_ip = normalize_ip(ip_address)
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc

        clean_headers = sanitize_forensic_headers(
            headers,
            max_key_length=settings.header_max_key_length,
            max_value_length=settings.header_max_value_length,
            max_count=settings.header_max_count,
            max_total_bytes=settings.header_max_total_bytes,
        )

        clean_user_agent = user_agent[:1024] if user_agent and len(user_agent) > 1024 else user_agent

        try:
            token = self.token_repo.get_by_token(token_value)
            if not token:
                raise HoneyTokenNotFoundError(f"Token '{token_value}' not found")

            # A tenant-scoped caller may only touch its own tenant's tokens; others look like a 404.
            if self._scoped_tenant_id is not None:
                from app.core.auth_exceptions import ForbiddenError
                try:
                    self._authorize_tenant_access(token.project.tenant_id)
                except ForbiddenError:
                    raise HoneyTokenNotFoundError(f"Token '{token_value}' not found")

            if self.current_user is None:
                # Manual evidence must always be attributable to a person.
                from app.core.auth_exceptions import UnauthorizedError
                raise UnauthorizedError("Manually recorded events require an authenticated user")

            event = self._persist_event(
                token=token,
                ip_address=norm_ip,
                request_path=request_path,
                http_method=http_method,
                severity=severity,
                user_agent=clean_user_agent,
                headers=clean_headers,
                source=EventSource.MANUAL,
                created_by_user_id=self.current_user.id,
                commit=False,
            )
            if self.audit_service:
                self.audit_service.record_action(
                    event_type="DETECTION_EVENT_MANUALLY_RECORDED",
                    severity="WARNING",
                    message=f"Detection event {event.id} entered manually for honey token ID {token.id}",
                    actor_source="api",
                    actor_user_id=self.current_user.id,
                    target_entity="detection_event",
                    target_id=event.id,
                    tenant_id=token.project.tenant_id,
                    project_id=token.project_id,
                    event_metadata={"honey_token_id": token.id, "asserted_ip_address": norm_ip,
                                    "asserted_severity": severity.value,
                                    "reason": (reason or "")[:1000]},
                )
            # Event and its audit record commit atomically: no unaudited manual evidence.
            self.session.commit()
            self._publish_safely(event)
            return event
        except Exception:
            try:
                self.session.rollback()
            except Exception:
                pass
            raise

    # Public (unauthenticated) ingestion

    def find_token_for_ingest(self, token_value: str) -> HoneyToken | None:
        """Resolve a public trigger value to its token, or None if it is not a token.

        Values that cannot be a stored token are rejected without a database query.
        """
        if not token_value or len(token_value) > MAX_TOKEN_VALUE_LENGTH:
            return None
        return self.token_repo.get_by_token(token_value)

    def record_public_hit(
        self,
        token: HoneyToken,
        ip_address: str,
        request_path: str,
        http_method: str,
        user_agent: str | None = None,
        headers: dict[str, Any] | None = None,
        request_id: str | None = None,
        triggered_at: "datetime | None" = None,
        allowed_headers: frozenset[str] | None = None,
        source: EventSource = EventSource.PUBLIC_INGEST,
    ) -> DetectionEvent:
        """Persist a public trigger of an already-resolved token.

        Severity is derived from the token type, never from the caller. ``request_id`` is the edge's
        id for the request (stored as ``idempotency_key``; at most one public event per id), and
        ``triggered_at`` is the time the edge saw a hit that is recorded later (replay after an
        outage). A duplicate request id raises ``DuplicatePublicHitError``.

        DNS hits (``allowed_headers``: their own context keys) are PUBLIC_INGEST: HoneyShield's name
        server saw the query. Cloud canary uses are CLOUD_AUDIT: AWS CloudTrail recorded them and
        ``request_id`` is the CloudTrail event id, so polling the same window twice stores nothing new.
        """
        from app.core.config import get_settings
        from app.core.header_security import sanitize_forensic_headers
        from app.core.ip_trust import normalize_ip

        settings = get_settings()
        try:
            norm_ip = normalize_ip(ip_address)
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc

        clean_headers = sanitize_forensic_headers(
            headers,
            max_key_length=settings.header_max_key_length,
            max_value_length=settings.header_max_value_length,
            max_count=settings.header_max_count,
            max_total_bytes=settings.header_max_total_bytes,
            allowed=allowed_headers,
        )
        clean_user_agent = user_agent[:1024] if user_agent and len(user_agent) > 1024 else user_agent
        severity = DEFAULT_SEVERITY_BY_TOKEN_TYPE.get(token.token_type, EventSeverity.MEDIUM)

        try:
            return self._persist_event(
                token=token,
                ip_address=norm_ip,
                request_path=request_path[:2048],
                http_method=http_method[:10],
                severity=severity,
                user_agent=clean_user_agent,
                headers=clean_headers,
                source=source,
                idempotency_key=request_id,
                triggered_at=triggered_at,
            )
        except Exception as exc:
            try:
                self.session.rollback()
            except Exception:
                pass
            if request_id is not None and _is_duplicate_public_hit(exc):
                raise DuplicatePublicHitError(request_id) from None
            raise

    def record_hook_report(
        self,
        token: HoneyToken,
        integration_credential_id: int,
        idempotency_key: str,
        ip_address: str,
        observed_at: "datetime",
        request_path: str,
        http_method: str,
        user_agent: str | None,
        headers: dict[str, Any] | None,
        extra_commit: "Callable[[], None] | None" = None,
    ) -> DetectionEvent:
        """Persist a CUSTOMER_HOOK event reported by an authenticated integration.

        IP, path and time are asserted by the customer and stored as reported (after
        normalisation); the event is labelled CUSTOMER_HOOK so it is never mistaken for
        something HoneyShield observed itself. Severity comes from the token type.
        """
        from app.core.config import get_settings
        from app.core.header_security import sanitize_forensic_headers
        from app.core.ip_trust import normalize_ip

        settings = get_settings()
        try:
            norm_ip = normalize_ip(ip_address)
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc
        clean_headers = sanitize_forensic_headers(
            headers,
            max_key_length=settings.header_max_key_length,
            max_value_length=settings.header_max_value_length,
            max_count=settings.header_max_count,
            max_total_bytes=settings.header_max_total_bytes,
        )
        try:
            event = self._persist_event(
                token=token,
                ip_address=norm_ip,
                request_path=request_path[:2048],
                http_method=http_method[:10],
                severity=DEFAULT_SEVERITY_BY_TOKEN_TYPE.get(token.token_type, EventSeverity.MEDIUM),
                user_agent=(user_agent or None) and user_agent[:1024],
                headers=clean_headers,
                source=EventSource.CUSTOMER_HOOK,
                integration_credential_id=integration_credential_id,
                idempotency_key=idempotency_key,
                triggered_at=observed_at,
                commit=False,
            )
            if extra_commit is not None:
                extra_commit()
            self.session.commit()
        except Exception:
            try:
                self.session.rollback()
            except Exception:
                pass
            raise
        self._publish_safely(event)
        return event

    def record_suppressed_hits(self, token: HoneyToken, ip_address: str, cap: int) -> None:
        """Leave durable evidence that further hits from one source were not stored.

        Called once per window, on the first hit beyond the per-(IP, token) cap, so a
        flood against a token is visible even though its repeats are not each stored.
        Never raises: losing this marker must not affect the response.
        """
        if not self.audit_service:
            return
        try:
            self.audit_service.record_action(
                event_type="DETECTION_HITS_SUPPRESSED",
                severity="WARNING",
                message=(
                    f"More than {cap} hits per minute on honey token ID {token.id} from one source; "
                    "further hits in this window are not stored individually"
                ),
                actor_source="public_ingest",
                target_entity="honey_token",
                target_id=token.id,
                tenant_id=token.project.tenant_id,
                project_id=token.project_id,
                event_metadata={"ip_address": ip_address, "per_minute_cap": cap, "honey_token_id": token.id},
            )
            self.session.commit()
        except Exception:
            logging.getLogger(__name__).warning("Failed to record suppressed-hit marker", exc_info=True)
            try:
                self.session.rollback()
            except Exception:
                pass

    def _persist_event(
        self,
        token: HoneyToken,
        ip_address: str,
        request_path: str,
        http_method: str,
        severity: EventSeverity,
        user_agent: str | None,
        headers: dict[str, Any] | None,
        source: EventSource,
        created_by_user_id: int | None = None,
        commit: bool = True,
        integration_credential_id: int | None = None,
        idempotency_key: str | None = None,
        triggered_at: "datetime | None" = None,
    ) -> DetectionEvent:
        """Insert one event with explicit provenance.

        With ``commit=True`` (default) it commits and publishes. With ``commit=False``
        it only flushes, so the caller can commit related records atomically and then
        call ``_publish_safely``.
        """
        event = self.event_repo.create(
            honey_token_id=token.id,
            ip_address=ip_address,
            request_path=request_path,
            http_method=http_method,
            severity=severity,
            user_agent=user_agent,
            headers=headers,
            source=source,
            created_by_user_id=created_by_user_id,
            **({"integration_credential_id": integration_credential_id} if integration_credential_id is not None else {}),
            **({"idempotency_key": idempotency_key} if idempotency_key is not None else {}),
            **({"triggered_at": triggered_at} if triggered_at is not None else {}),
        )
        self.session.flush()
        # Tamper-evident chain: one append-only link per event, same transaction.
        from app.services import evidence
        evidence.append(self.session, event, token.project.tenant_id)
        # Durable alerting: deliveries are queued in the SAME transaction, so a
        # committed event always has its alerts queued and a rolled-back one never alerts.
        from app.services.alerting import enqueue_for_event
        enqueue_for_event(self.session, event, token)
        # Everything the live feed needs is loaded now; after commit the attributes are expired and
        # reading them again would cost three more queries per hit.
        event._hs_live = self._realtime_payload(event, token)
        if not commit:
            self.session.flush()
            return event
        self.session.commit()
        self._publish_safely(event)
        return event

    def _publish_safely(self, event: DetectionEvent) -> None:
        """Publish a committed event; a broadcast failure never affects the stored event."""
        try:
            self._publish_realtime_event(event)
        except Exception:
            logging.getLogger(__name__).warning(
                "Failed to broadcast detection event %s",
                event.id,
                exc_info=True,
            )

    @staticmethod
    def _realtime_payload(event: DetectionEvent, token: HoneyToken) -> tuple[dict[str, Any], int]:
        """Minimal live-feed payload (no raw headers, no token secrets) and the owning tenant."""
        triggered = event.triggered_at
        return {
            "event_type": "detection_event",
            "event_id": event.id,
            "honey_token_id": event.honey_token_id,
            "severity": event.severity.value,
            "source": event.source.value,
            "ip_address": event.ip_address,
            # Stream subscribers include TENANT_USER viewers: never broadcast the token value.
            "request_path": (event.request_path or "").replace(token.token_value, "{token}"),
            "decoy_id": token.decoy_id,
            "http_method": event.http_method,
            "user_agent": event.user_agent,
            "triggered_at": triggered.isoformat() if triggered else None,
        }, token.project.tenant_id

    def _publish_realtime_event(self, event: DetectionEvent) -> None:
        """Publish a committed detection event to real-time subscribers (tenant-matched)."""
        from app.services.event_broadcaster import get_broadcaster

        prepared = getattr(event, "_hs_live", None)
        if prepared is None:  # built before commit by _persist_event; rebuild only if missing
            prepared = self._realtime_payload(event, event.honey_token)
        event_data, tenant_id = prepared
        get_broadcaster().publish(event_data, tenant_id)

    def list_recent_events(
        self,
        token_value: str | None = None,
        limit: int = 100,
        offset: int = 0,
        cursor: int | None = None,
        severities: list[EventSeverity] | None = None,
        ip_address: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        decoy_id: str | None = None,
    ) -> list[DetectionEvent]:
        """List recent events globally or for a specific honey token.

        Args:
            token_value: Optional honey token value used to scope results.
            limit: Maximum number of recent events to return (capped at 1000).
            offset: Number of items to skip for offset-based pagination.
            cursor: Optional event ID cursor for keyset pagination.

        Returns:
            Detection events ordered from newest to oldest.

        Raises:
            ValidationError: If the limit or offset is invalid or token value is blank.
            HoneyTokenNotFoundError: If a supplied token does not exist.
        """
        if limit < 1:
            raise ValidationError("Limit must be at least 1")
        if limit > 1000:
            raise ValidationError("Limit cannot exceed 1000")
        if offset < 0:
            raise ValidationError("Offset cannot be negative")

        honey_token_id = None
        if token_value is not None:
            token = self.token_repo.get_by_token(token_value)
            if not token:
                raise HoneyTokenNotFoundError(f"Token '{token_value}' not found")
            if self._scoped_tenant_id is not None:
                from app.core.auth_exceptions import ForbiddenError
                try:
                    self._authorize_tenant_access(token.project.tenant_id)
                except ForbiddenError:
                    raise HoneyTokenNotFoundError(f"Token '{token_value}' not found")
            honey_token_id = token.id

        if decoy_id is not None:
            # The public decoy id (not the secret value): what the console and SIEM rules hold.
            # Another tenant's decoy is reported exactly like a missing one.
            from sqlalchemy import select
            token = self.session.scalar(select(HoneyToken).where(HoneyToken.decoy_id == decoy_id.strip()))
            scope = self._scoped_tenant_id
            if token is None or (scope is not None and token.project.tenant_id != scope) \
                    or (honey_token_id is not None and token.id != honey_token_id):
                raise HoneyTokenNotFoundError("Decoy not found")
            honey_token_id = token.id

        if ip_address is not None:
            from app.core.ip_trust import normalize_ip
            try:
                ip_address = normalize_ip(ip_address.strip())
            except ValueError:
                raise ValidationError("ip_address must be a valid IPv4 or IPv6 address") from None
        if since is not None and until is not None and since >= until:
            raise ValidationError("since must be earlier than until")

        scoped_tenant = self._scoped_tenant_id if honey_token_id is None else None
        return self.event_repo.list_recent(
            honey_token_id=honey_token_id,
            limit=limit,
            offset=offset,
            cursor=cursor,
            tenant_id=scoped_tenant,
            severities=[getattr(s, "value", s) for s in severities] if severities else None,
            ip_address=ip_address,
            since=since,
            until=until,
        )

    def get_event(self, event_id: int) -> DetectionEvent:
        """Return one event in the caller's scope.

        An event of another tenant is reported exactly like a missing one, so ids cannot be
        probed across tenants.
        """
        event = self.event_repo.get_by_id(event_id)
        scope = self._scoped_tenant_id
        if event is None or (scope is not None and event.tenant_id != scope):
            raise DetectionEventNotFoundError("Detection event not found")
        return event

    def count_today(self, token_value: str | None = None) -> int:
        """Count events recorded since the current UTC day began.

        Args:
            token_value: Optional honey token value used to scope the count.

        Returns:
            Number of matching detection events recorded today.

        Raises:
            ValidationError: If a supplied token value is blank.
            HoneyTokenNotFoundError: If a supplied token does not exist.
        """
        honey_token_id = None
        if token_value is not None:
            token = self.token_repo.get_by_token(token_value)
            if not token:
                raise HoneyTokenNotFoundError(f"Token '{token_value}' not found")
            if self._scoped_tenant_id is not None:
                from app.core.auth_exceptions import ForbiddenError
                try:
                    self._authorize_tenant_access(token.project.tenant_id)
                except ForbiddenError:
                    raise HoneyTokenNotFoundError(f"Token '{token_value}' not found")
            honey_token_id = token.id

        scoped_tenant = self._scoped_tenant_id if honey_token_id is None else None
        return self.event_repo.count_today(
            honey_token_id=honey_token_id,
            tenant_id=scoped_tenant,
        )

    def get_activity(self, days: int) -> list[dict[str, Any]]:
        """Events per UTC day and severity over the last ``days`` days (today included), oldest
        first, with empty days filled in. Same tenant scope and time budget as threat analytics."""
        from datetime import date, timedelta, timezone

        from app.core.config import get_settings
        from app.db.session import set_query_timeout
        from app.services.threat_intelligence import _analytics_budget

        today = datetime.now(timezone.utc).date()
        first = today - timedelta(days=days - 1)
        since = datetime(first.year, first.month, first.day, tzinfo=timezone.utc)
        with _analytics_budget(self.session), set_query_timeout(self.session, get_settings().db_analytics_timeout_ms):
            rows = self.event_repo.daily_activity(tenant_id=self._scoped_tenant_id, since=since)
        series = {(first + timedelta(days=i)).isoformat(): {s.value: 0 for s in EventSeverity} for i in range(days)}
        for day, severity, n in rows:
            key = date.fromisoformat(day[:10]).isoformat()
            if key in series and severity in series[key]:
                series[key][severity] += n
        return [{"date": d, "total": sum(c.values()), "by_severity": c} for d, c in series.items()]

    def get_statistics(self) -> dict[str, int]:
        """Return global or tenant-scoped detection-event totals in a single SQL pass.

        Args:
            None.

        Returns:
            A mapping containing total and current-day event counts.
        """
        tenant_id = self._scoped_tenant_id
        total_events, today_events = self.event_repo.count_summary(tenant_id=tenant_id)

        return {
            "total_events": total_events,
            "today_events": today_events,
        }
