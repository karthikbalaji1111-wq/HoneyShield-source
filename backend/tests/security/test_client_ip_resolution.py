"""Client IP is the rightmost *untrusted* X-Forwarded-For hop, never a client-chosen value."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from app.core.config import get_settings
from app.core.ip_trust import client_from_forwarded_for, resolve_client_ip
from app.models.detection_event import DetectionEvent

TRUSTED = ["127.0.0.1", "10.0.0.0/8"]


@pytest.mark.parametrize(
    "xff, expected",
    [
        ("198.51.100.7", "198.51.100.7"),                         # single hop written by our proxy
        ("1.2.3.4, 198.51.100.7", "198.51.100.7"),                # client-forged left entry ignored
        ("1.2.3.4, 198.51.100.7, 10.0.0.5", "198.51.100.7"),      # skip our own trusted proxy hop
        ("10.0.0.9, 10.0.0.5", "10.0.0.9"),                       # all hops trusted -> leftmost
        ("1.2.3.4, not-an-ip, 198.51.100.7", "198.51.100.7"),     # malformed only left of the answer
        ("1.2.3.4, 10.0.0.5, garbage", None),                     # malformed rightmost hop -> untrusted chain
        ("2001:db8::1, 10.0.0.5", "2001:db8::1"),
        ("", None),
    ],
)
def test_client_from_forwarded_for(xff, expected):
    assert client_from_forwarded_for(xff, TRUSTED) == expected


def test_untrusted_peer_ignores_all_forwarding_headers():
    assert resolve_client_ip("203.0.113.9", {"x-forwarded-for": "1.2.3.4", "x-real-ip": "5.6.7.8"}, TRUSTED) == "203.0.113.9"


def test_malformed_chain_falls_back_to_real_ip_then_peer():
    assert resolve_client_ip("10.0.0.5", {"x-forwarded-for": "junk", "x-real-ip": "198.51.100.1"}, TRUSTED) == "198.51.100.1"
    assert resolve_client_ip("10.0.0.5", {"x-forwarded-for": "junk"}, TRUSTED) == "10.0.0.5"


def test_forged_left_entry_cannot_choose_forensic_ip(client, token_a, db_session):
    """Regression for the audit probe: a client-supplied left-hand XFF entry used to be recorded."""
    with patch.object(get_settings(), "trusted_proxies", ["127.0.0.1"]):
        client.get(f"/t/{token_a.token_value}", headers={"X-Forwarded-For": "1.2.3.4, 198.51.100.7"})
    event = db_session.query(DetectionEvent).filter_by(honey_token_id=token_a.id).one()
    assert event.ip_address == "198.51.100.7"


def test_forged_left_entry_cannot_rotate_api_rate_limit_key():
    """The API rate limiter resolves IPs with the same function, so XFF rotation cannot mint new keys."""
    from app.middleware.rate_limit import ApiRateLimitMiddleware

    mw = ApiRateLimitMiddleware(app=None)
    settings = get_settings()
    with patch.object(settings, "trusted_proxies", ["127.0.0.1"]):
        a = mw._resolve_ip("127.0.0.1", {"x-forwarded-for": "9.9.9.1, 198.51.100.7"}, settings)
        b = mw._resolve_ip("127.0.0.1", {"x-forwarded-for": "9.9.9.2, 198.51.100.7"}, settings)
    assert a == b == "198.51.100.7"
