from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app.core.auth_exceptions import ForbiddenError
from app.models.detection_event import DetectionEvent
from app.models.honey_token import HoneyToken
from app.repositories.base import BaseRepository


@dataclass(frozen=True)
class IPActivityAggregation:
    """SQL aggregate values describing one source IP's event activity."""

    ip_address: str
    total_events: int
    first_seen: datetime
    last_seen: datetime
    distinct_honey_tokens: int
    distinct_projects: int
    distinct_user_agents: int
    events_today: int


@dataclass(frozen=True)
class ThreatScoreWeights:
    """Weights of the deterministic 0-100 threat score, evaluated in SQL for ranking."""

    repeat_points: int
    max_repeat_events: int
    token_points: int
    max_tokens: int
    project_points: int
    max_projects: int
    current_day_points: int
    max_current_day_events: int


def _capped(expr, cap: int):
    """Portable LEAST(expr, cap) for SQLite and PostgreSQL."""
    return case((expr > cap, cap), else_=expr)


class DetectionEventRepository(BaseRepository[DetectionEvent]):
    def __init__(self, session: Session) -> None:
        super().__init__(session, DetectionEvent)

    def delete(self, id: int) -> None:
        """Prevent deletion of immutable detection events."""
        raise ForbiddenError(
            "DetectionEvent records are immutable forensic evidence and cannot be deleted"
        )

    def list_recent(
        self,
        honey_token_id: int | None = None,
        limit: int = 100,
        offset: int = 0,
        cursor: int | None = None,
        tenant_id: int | None = None,
        severities: list[str] | None = None,
        ip_address: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[DetectionEvent]:
        """Newest first. Filters map onto indexes: tenant/time on (tenant_id, triggered_at, id),
        time on (triggered_at, id), address on ip_address; severity filters the scanned range."""
        from app.models.honey_token import HoneyToken
        from app.models.project import Project

        from sqlalchemy import tuple_
        from sqlalchemy.orm import selectinload

        # The decoy and its project are read for every row (masking, export): load them in two
        # batched queries instead of per event.
        stmt = select(DetectionEvent).options(
            selectinload(DetectionEvent.honey_token).selectinload(HoneyToken.project))
        if honey_token_id is not None:
            stmt = stmt.where(DetectionEvent.honey_token_id == honey_token_id)
        if cursor is not None:
            # Keyset on the same key as the ORDER BY: (triggered_at, id). Trigger times are not in id
            # order (customer hooks assert their own time), so "id < cursor" skipped events.
            # Row comparison maps onto the (triggered_at, id) index on PostgreSQL.
            anchor = select(DetectionEvent.triggered_at).where(DetectionEvent.id == cursor).scalar_subquery()
            stmt = stmt.where(tuple_(DetectionEvent.triggered_at, DetectionEvent.id) < tuple_(anchor, cursor))
        if tenant_id is not None:
            # Range on (tenant_id, triggered_at, id); tenant_id is set by the database on insert.
            stmt = stmt.where(DetectionEvent.tenant_id == tenant_id)
        if severities:
            stmt = stmt.where(DetectionEvent.severity.in_(severities))
        if ip_address:
            stmt = stmt.where(DetectionEvent.ip_address == ip_address)
        if since is not None:
            stmt = stmt.where(DetectionEvent.triggered_at >= since)
        if until is not None:
            stmt = stmt.where(DetectionEvent.triggered_at < until)
        stmt = stmt.order_by(
            DetectionEvent.triggered_at.desc(),
            DetectionEvent.id.desc(),
        ).offset(offset).limit(limit)
        return list(self.session.scalars(stmt).all())

    def daily_activity(self, *, tenant_id: int | None, since: datetime) -> list[tuple[str, str, int]]:
        """(UTC day 'YYYY-MM-DD', severity, events) for UTC days from ``since``'s day onwards.

        PostgreSQL reads the trigger-maintained daily totals; other databases count directly.
        """
        if self.session.get_bind().dialect.name == "postgresql":
            # Trigger-maintained totals (migration 20261118_03): O(days), whatever the event volume.
            from app.models.tenant import TenantDailyEventCount as D
            q = (select(D.day, D.severity, func.sum(D.total))
                 .where(D.day >= since.astimezone(timezone.utc).date()))
            if tenant_id is not None:
                q = q.where(D.tenant_id == tenant_id)
            rows = self.session.execute(q.group_by(D.day, D.severity)).all()
            return [(d.isoformat(), sev, int(n)) for d, sev, n in rows if n]
        day = func.date(DetectionEvent.triggered_at)
        stmt = (select(day.label("day"), DetectionEvent.severity, func.count())
                .where(DetectionEvent.triggered_at >= since))
        if tenant_id is not None:
            stmt = stmt.where(DetectionEvent.tenant_id == tenant_id)
        rows = self.session.execute(stmt.group_by(day, DetectionEvent.severity)).all()
        return [(str(d), getattr(sev, "value", sev), int(n)) for d, sev, n in rows]

    def count_for_source_in_window(self, *, honey_token_id: int, ip_address: str, start: datetime,
                                   end: datetime) -> int:
        """Events of one decoy from one address in [start, end): the per-source cap for replays.
        Served by the (honey_token_id, triggered_at) index."""
        return int(self.session.scalar(
            select(func.count()).select_from(DetectionEvent).where(
                DetectionEvent.honey_token_id == honey_token_id,
                DetectionEvent.ip_address == ip_address,
                DetectionEvent.triggered_at >= start,
                DetectionEvent.triggered_at < end)) or 0)

    def count_summary(self, tenant_id: int | None = None) -> tuple[int, int]:
        """Total and current-day events.

        PostgreSQL: the total comes from ``tenant_event_counts`` (exact, maintained by triggers, so
        O(1) at any size) and today's count from an index range on the trigger time (today's slice
        is small). Other databases (SQLite in tests and development) count directly.
        """
        now = datetime.now(timezone.utc)
        start_of_day = now.replace(hour=0, minute=0, second=0, microsecond=0)
        from app.models.honey_token import HoneyToken
        from app.models.project import Project

        if self.session.get_bind().dialect.name == "postgresql":
            from app.models.tenant import TenantEventCount
            total_q = select(func.coalesce(func.sum(TenantEventCount.total), 0))
            today_q = select(func.count()).select_from(DetectionEvent).where(DetectionEvent.triggered_at >= start_of_day)
            if tenant_id is not None:
                total_q = total_q.where(TenantEventCount.tenant_id == tenant_id)
                today_q = today_q.where(DetectionEvent.tenant_id == tenant_id)
            return int(self.session.scalar(total_q) or 0), int(self.session.scalar(today_q) or 0)

        total_col = func.count(DetectionEvent.id).label("total_events")
        today_col = func.count(DetectionEvent.id).filter(
            DetectionEvent.triggered_at >= start_of_day
        ).label("today_events")

        stmt = select(total_col, today_col).select_from(DetectionEvent)
        if tenant_id is not None:
            stmt = stmt.where(DetectionEvent.tenant_id == tenant_id)
        row = self.session.execute(stmt).one()
        return (row[0] or 0, row[1] or 0)

    def count(self, tenant_id: int | None = None) -> int:
        from app.models.honey_token import HoneyToken
        from app.models.project import Project

        stmt = select(func.count()).select_from(DetectionEvent)
        if tenant_id is not None:
            stmt = stmt.where(DetectionEvent.tenant_id == tenant_id)
        return self.session.scalar(stmt) or 0

    def list_between(
        self, honey_token_id: int, start_time: datetime, end_time: datetime
    ) -> list[DetectionEvent]:
        stmt = (
            select(DetectionEvent)
            .where(DetectionEvent.honey_token_id == honey_token_id)
            .where(DetectionEvent.triggered_at >= start_time)
            .where(DetectionEvent.triggered_at <= end_time)
            .order_by(DetectionEvent.triggered_at.desc(), DetectionEvent.id.desc())
        )
        return list(self.session.scalars(stmt).all())

    def find_by_ip(
        self,
        ip_address: str,
        limit: int = 100,
        offset: int = 0,
        tenant_id: int | None = None,
    ) -> list[DetectionEvent]:
        from app.models.honey_token import HoneyToken
        from app.models.project import Project
        stmt = select(DetectionEvent).where(DetectionEvent.ip_address == ip_address)
        if tenant_id is not None:
            stmt = stmt.where(DetectionEvent.tenant_id == tenant_id)
        stmt = stmt.order_by(
            DetectionEvent.triggered_at.desc(),
            DetectionEvent.id.desc(),
        ).offset(offset).limit(limit)
        return list(self.session.scalars(stmt).all())

    def aggregate_by_ip(
        self,
        ip_address: str | None = None,
        tenant_id: int | None = None,
        since: datetime | None = None,
        limit: int | None = None,
        rank_by_threat: ThreatScoreWeights | None = None,
    ) -> list[IPActivityAggregation]:
        """Aggregate detection-event activity by source IP address.

        Args:
            ip_address: Optional source IP address used to scope the aggregation.
            tenant_id: Optional tenant identifier used to scope the aggregation.
            since: Optional cutoff timestamp to bound query window.
            limit: Optional maximum number of IP aggregates to return.
            rank_by_threat: When given, rows are ordered by the threat score computed
                in SQL (descending), then event count, then IP, *before* ``limit`` is
                applied, so the limit keeps the highest-scoring IPs rather than the
                first IPs in lexical order. Otherwise rows are ordered by IP.

        Returns:
            One aggregate result per matching source IP address.
        """
        now = datetime.now(timezone.utc)
        start_of_day = now.replace(hour=0, minute=0, second=0, microsecond=0)
        events_today = func.count(DetectionEvent.id).filter(
            DetectionEvent.triggered_at >= start_of_day
        )
        from app.models.project import Project
        stmt = (
            select(
                DetectionEvent.ip_address.label("ip_address"),
                func.count(DetectionEvent.id).label("total_events"),
                func.min(DetectionEvent.triggered_at).label("first_seen"),
                func.max(DetectionEvent.triggered_at).label("last_seen"),
                func.count(
                    func.distinct(DetectionEvent.honey_token_id)
                ).label("distinct_honey_tokens"),
                func.count(func.distinct(HoneyToken.project_id)).label(
                    "distinct_projects"
                ),
                func.count(func.distinct(DetectionEvent.user_agent)).label(
                    "distinct_user_agents"
                ),
                events_today.label("events_today"),
            )
            .join(HoneyToken, DetectionEvent.honey_token_id == HoneyToken.id)
        )
        if tenant_id is not None:
            stmt = stmt.where(DetectionEvent.tenant_id == tenant_id)
        if since is not None:
            stmt = stmt.where(DetectionEvent.triggered_at >= since)
        if ip_address is not None:
            stmt = stmt.where(DetectionEvent.ip_address == ip_address)

        stmt = stmt.group_by(DetectionEvent.ip_address)
        if rank_by_threat is not None:
            w = rank_by_threat
            total = func.count(DetectionEvent.id)
            repeats = case((total > 1, total - 1), else_=0)
            score = (
                _capped(repeats, w.max_repeat_events) * w.repeat_points
                + _capped(func.count(func.distinct(DetectionEvent.honey_token_id)), w.max_tokens) * w.token_points
                + _capped(func.count(func.distinct(HoneyToken.project_id)), w.max_projects) * w.project_points
                + _capped(
                    func.count(DetectionEvent.id).filter(DetectionEvent.triggered_at >= start_of_day),
                    w.max_current_day_events,
                ) * w.current_day_points
            )
            stmt = stmt.order_by(_capped(score, 100).desc(), total.desc(), DetectionEvent.ip_address)
        else:
            stmt = stmt.order_by(DetectionEvent.ip_address)
        if limit is not None:
            stmt = stmt.limit(limit)

        rows = self.session.execute(stmt)
        return [
            IPActivityAggregation(
                ip_address=row.ip_address,
                total_events=row.total_events,
                first_seen=row.first_seen,
                last_seen=row.last_seen,
                distinct_honey_tokens=row.distinct_honey_tokens,
                distinct_projects=row.distinct_projects,
                distinct_user_agents=row.distinct_user_agents,
                events_today=row.events_today,
            )
            for row in rows
        ]

    # ------------------------------------------------------------------ bounded analytics
    def _recent_window(self, tenant_id: int | None, since: datetime, sample: int):
        """The most recent ``sample`` events in the window (index range; bounded cost at any size)."""
        stmt = select(DetectionEvent.ip_address, DetectionEvent.honey_token_id, DetectionEvent.triggered_at) \
            .where(DetectionEvent.triggered_at >= since)
        if tenant_id is not None:
            stmt = stmt.where(DetectionEvent.tenant_id == tenant_id)
        return stmt.order_by(DetectionEvent.triggered_at.desc(), DetectionEvent.id.desc()).limit(sample).subquery()

    def _per_ip(self, recent):
        """Per-IP activity without COUNT(DISTINCT): three hash-aggregation stages.

        (ip, project, decoy) -> (ip, project): rows = distinct decoys in that project ->
        ip: rows = distinct projects, sum = distinct decoys.
        """
        from app.models.honey_token import HoneyToken
        now = datetime.now(timezone.utc)
        start_of_day = now.replace(hour=0, minute=0, second=0, microsecond=0)
        s1 = (select(recent.c.ip_address, HoneyToken.project_id, recent.c.honey_token_id,
                     func.count().label("n"),
                     func.count().filter(recent.c.triggered_at >= start_of_day).label("n_today"),
                     func.min(recent.c.triggered_at).label("first_seen"),
                     func.max(recent.c.triggered_at).label("last_seen"))
              .join(HoneyToken, HoneyToken.id == recent.c.honey_token_id)
              .group_by(recent.c.ip_address, HoneyToken.project_id, recent.c.honey_token_id)).subquery()
        s2 = (select(s1.c.ip_address, s1.c.project_id, func.count().label("tokens"), func.sum(s1.c.n).label("n"),
                     func.sum(s1.c.n_today).label("n_today"), func.min(s1.c.first_seen).label("first_seen"),
                     func.max(s1.c.last_seen).label("last_seen"))
              .group_by(s1.c.ip_address, s1.c.project_id)).subquery()
        return (select(s2.c.ip_address, func.sum(s2.c.n).label("total_events"),
                       func.sum(s2.c.tokens).label("distinct_honey_tokens"), func.count().label("distinct_projects"),
                       func.sum(s2.c.n_today).label("events_today"), func.min(s2.c.first_seen).label("first_seen"),
                       func.max(s2.c.last_seen).label("last_seen"))
                .group_by(s2.c.ip_address)).subquery()

    def rank_ip_activity(self, *, tenant_id: int | None, since: datetime, limit: int, weights: ThreatScoreWeights,
                         sample: int) -> tuple[list[IPActivityAggregation], bool]:
        """Top IPs by threat score over the most recent ``sample`` events in the window.

        Returns (rows, sampled): ``sampled`` is True when the window held more than ``sample``
        events, so the ranking covers only the most recent ones.
        """
        recent = self._recent_window(tenant_id, since, sample + 1)
        considered = self.session.scalar(select(func.count()).select_from(recent))
        sampled = considered > sample
        recent = self._recent_window(tenant_id, since, sample)
        per_ip = self._per_ip(recent)
        w = weights
        repeats = case((per_ip.c.total_events > 1, per_ip.c.total_events - 1), else_=0)
        score = (_capped(repeats, w.max_repeat_events) * w.repeat_points
                 + _capped(per_ip.c.distinct_honey_tokens, w.max_tokens) * w.token_points
                 + _capped(per_ip.c.distinct_projects, w.max_projects) * w.project_points
                 + _capped(per_ip.c.events_today, w.max_current_day_events) * w.current_day_points)
        rows = self.session.execute(
            select(per_ip).order_by(_capped(score, 100).desc(), per_ip.c.total_events.desc(), per_ip.c.ip_address)
            .limit(limit)).all()
        agents: dict[str, int] = {}
        if rows:
            ua = (select(DetectionEvent.ip_address, func.count(func.distinct(DetectionEvent.user_agent)))
                  .where(DetectionEvent.ip_address.in_([r.ip_address for r in rows]),
                         DetectionEvent.triggered_at >= since))
            if tenant_id is not None:
                ua = ua.where(DetectionEvent.tenant_id == tenant_id)
            agents = dict(self.session.execute(ua.group_by(DetectionEvent.ip_address)).all())
        return [IPActivityAggregation(
            ip_address=r.ip_address, total_events=int(r.total_events), first_seen=r.first_seen, last_seen=r.last_seen,
            distinct_honey_tokens=int(r.distinct_honey_tokens), distinct_projects=int(r.distinct_projects),
            distinct_user_agents=int(agents.get(r.ip_address, 0)), events_today=int(r.events_today or 0))
            for r in rows], sampled

    def summarize_ip_activity(self, *, tenant_id: int | None, since: datetime, sample: int) -> tuple[int, int, bool]:
        """(events considered, distinct IPs, sampled) over the most recent ``sample`` events."""
        recent = self._recent_window(tenant_id, since, sample + 1)
        considered = self.session.scalar(select(func.count()).select_from(recent))
        sampled = considered > sample
        recent = self._recent_window(tenant_id, since, sample)
        events, ips = self.session.execute(
            select(func.count(), func.count(func.distinct(recent.c.ip_address))).select_from(recent)).one()
        return int(events), int(ips), sampled

    def count_today(self, honey_token_id: int | None = None, tenant_id: int | None = None) -> int:
        from app.models.honey_token import HoneyToken
        from app.models.project import Project

        now = datetime.now(timezone.utc)
        start_of_day = now.replace(hour=0, minute=0, second=0, microsecond=0)
        stmt = (
            select(func.count())
            .select_from(DetectionEvent)
            .where(DetectionEvent.triggered_at >= start_of_day)
        )
        if honey_token_id is not None:
            stmt = stmt.where(DetectionEvent.honey_token_id == honey_token_id)
        if tenant_id is not None:
            stmt = stmt.where(DetectionEvent.tenant_id == tenant_id)
        return self.session.scalar(stmt) or 0
