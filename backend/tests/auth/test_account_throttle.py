"""Per-account failed-login budget: stops credential stuffing spread across many source IPs."""
from __future__ import annotations

import pytest

from app.core import rate_limit
from app.core.config import get_settings
from app.models.audit_log import AuditLog


@pytest.fixture()
def budget(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "login_account_failures_allowed", 3)
    monkeypatch.setattr(s, "login_attempts_per_minute", 1000)   # isolate from the per-IP limit
    now = [1000.0]
    limiter = rate_limit.FixedWindowLimiter(clock=lambda: now[0])
    monkeypatch.setattr(rate_limit, "login_account_failure_limiter", limiter)
    return now


def _login(client, email, password):
    return client.post("/auth/login", json={"email": email, "password": password})


def test_account_is_throttled_after_the_budget_even_with_the_right_password(client, db_session, admin_a, budget):
    assert [_login(client, admin_a.email, "wrong").status_code for _ in range(3)] == [401, 401, 401]
    r = _login(client, admin_a.email, "password")
    assert r.status_code == 429 and int(r.headers["Retry-After"]) == 900
    rec = db_session.query(AuditLog).filter_by(event_type="AUTH_ACCOUNT_THROTTLED").one()
    assert rec.event_metadata["email_domain"] == "tenant-a.com" and "password" not in str(rec.event_metadata)


def test_unknown_addresses_behave_identically(client, budget):
    codes = [_login(client, "nobody@tenant-a.com", "wrong").status_code for _ in range(4)]
    assert codes == [401, 401, 401, 429]


def test_address_normalisation_cannot_dodge_the_budget(client, admin_a, budget):
    for variant in (admin_a.email, admin_a.email.upper(), admin_a.email.title()):
        assert _login(client, variant, "wrong").status_code == 401
    assert _login(client, f"  {admin_a.email} ", "password").status_code == 422   # not a way around it
    assert _login(client, admin_a.email, "password").status_code == 429


def test_other_accounts_are_unaffected(client, admin_a, admin_b, budget):
    for _ in range(3):
        _login(client, admin_a.email, "wrong")
    assert _login(client, admin_b.email, "password").status_code == 200


def test_budget_recovers_after_the_window(client, admin_a, budget):
    for _ in range(3):
        _login(client, admin_a.email, "wrong")
    assert _login(client, admin_a.email, "password").status_code == 429
    budget[0] += 2 * 900
    assert _login(client, admin_a.email, "password").status_code == 200


def test_successful_logins_do_not_consume_the_budget(client, admin_a, budget):
    for _ in range(5):
        assert _login(client, admin_a.email, "password").status_code == 200


def test_zero_disables_the_account_budget(client, admin_a, budget, monkeypatch):
    monkeypatch.setattr(get_settings(), "login_account_failures_allowed", 0)
    assert all(_login(client, admin_a.email, "wrong").status_code == 401 for _ in range(6))
    assert _login(client, admin_a.email, "password").status_code == 200
