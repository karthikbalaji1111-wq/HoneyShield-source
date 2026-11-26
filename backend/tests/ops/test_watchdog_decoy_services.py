"""The watchdog tells the operator when DNS or cloud decoys stop being watched."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.core.config import get_settings
from app.models.system_status import SystemStatus
from app.services.system_status import put_status
from app.workers import watchdog


def _age(db_session, key, minutes):
    row = db_session.get(SystemStatus, key)
    row.updated_at = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    db_session.commit()


def test_checks_are_skipped_when_the_features_are_off(db_session, monkeypatch):
    monkeypatch.setattr(get_settings(), "dns_token_zone", None)
    monkeypatch.setattr(get_settings(), "aws_canary_enabled", False)
    assert watchdog.check_dns_listener(db_session, get_settings()) is None
    assert watchdog.check_cloud_canary(db_session, get_settings()) is None


def test_dns_listener_heartbeat(db_session, monkeypatch):
    monkeypatch.setattr(get_settings(), "dns_token_zone", "dns.example.net")
    assert not watchdog.check_dns_listener(db_session, get_settings()).ok
    put_status(db_session, "dns_listener", {"zone": "dns.example.net"})
    assert watchdog.check_dns_listener(db_session, get_settings()).ok
    _age(db_session, "dns_listener", 10)
    result = watchdog.check_dns_listener(db_session, get_settings())
    assert not result.ok and result.severity == watchdog.CRITICAL and "10 min" in result.detail


def test_cloud_canary_worker_status(db_session, monkeypatch):
    monkeypatch.setattr(get_settings(), "aws_canary_enabled", True)
    assert not watchdog.check_cloud_canary(db_session, get_settings()).ok
    put_status(db_session, "cloud_canary_worker", {"ok": False, "error": "InvalidClientTokenId: bad key"})
    assert "InvalidClientTokenId" in watchdog.check_cloud_canary(db_session, get_settings()).detail
    put_status(db_session, "cloud_canary_worker", {"ok": True, "last_poll": {"region_errors": {"eu-south-1": "OptInRequired"}}})
    result = watchdog.check_cloud_canary(db_session, get_settings())
    assert not result.ok and result.severity == watchdog.WARNING and "eu-south-1" in result.detail
    put_status(db_session, "cloud_canary_worker", {"ok": True, "last_poll": {"region_errors": {}}})
    assert watchdog.check_cloud_canary(db_session, get_settings()).ok
