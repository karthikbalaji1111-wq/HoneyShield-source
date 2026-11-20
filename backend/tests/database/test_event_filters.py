"""Event list filters (severity, address, time range) and decoy identity on each event."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.models.detection_event import DetectionEvent
from app.models.enums import EventSeverity, EventSource
from tests.conftest import auth_headers

URL = "/api/v1/detection-events"


def _event(db, token, *, ip="198.51.100.1", severity=EventSeverity.HIGH, minutes_ago=0):
    db.add(DetectionEvent(honey_token_id=token.id, ip_address=ip, request_path=f"/t/{token.token_value}",
                          http_method="GET", severity=severity, source=EventSource.PUBLIC_INGEST,
                          triggered_at=datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)))


def _seed(db, token):
    _event(db, token, ip="198.51.100.1", severity=EventSeverity.CRITICAL, minutes_ago=5)
    _event(db, token, ip="198.51.100.1", severity=EventSeverity.LOW, minutes_ago=90)
    _event(db, token, ip="2001:db8::1", severity=EventSeverity.HIGH, minutes_ago=60 * 30)
    _event(db, token, ip="203.0.113.9", severity=EventSeverity.MEDIUM, minutes_ago=60 * 24 * 10)
    db.commit()


def test_filter_by_one_or_several_severities(client, db_session, admin_a, token_a):
    _seed(db_session, token_a)
    h = auth_headers(admin_a)
    r = client.get(f"{URL}?severity=CRITICAL", headers=h)
    assert r.status_code == 200 and [e["severity"] for e in r.json()] == ["CRITICAL"]
    r = client.get(f"{URL}?severity=CRITICAL&severity=MEDIUM", headers=h)
    assert sorted(e["severity"] for e in r.json()) == ["CRITICAL", "MEDIUM"]
    assert client.get(f"{URL}?severity=NOPE", headers=h).status_code == 422


def test_filter_by_address_normalises_ipv6_and_rejects_garbage(client, db_session, admin_a, token_a):
    _seed(db_session, token_a)
    h = auth_headers(admin_a)
    assert len(client.get(f"{URL}?ip_address=198.51.100.1", headers=h).json()) == 2
    r = client.get(f"{URL}?ip_address=2001:DB8:0:0:0:0:0:1", headers=h)       # same address, other spelling
    assert [e["ip_address"] for e in r.json()] == ["2001:db8::1"]
    assert client.get(f"{URL}?ip_address=not-an-ip", headers=h).status_code == 422


def test_filter_by_time_range(client, db_session, admin_a, token_a):
    _seed(db_session, token_a)
    h = auth_headers(admin_a)
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    r = client.get(URL, params={"since": since}, headers=h)
    assert sorted(e["severity"] for e in r.json()) == ["CRITICAL", "LOW"]
    until = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    r = client.get(URL, params={"since": since, "until": until}, headers=h)
    assert [e["severity"] for e in r.json()] == ["LOW"]
    naive_since = (datetime.now(timezone.utc) - timedelta(days=2)).replace(tzinfo=None).isoformat()  # read as UTC
    assert len(client.get(URL, params={"since": naive_since}, headers=h).json()) == 3
    r = client.get(URL, params={"since": until, "until": since}, headers=h)
    assert r.status_code == 422


def test_filters_combine_and_paginate_newest_first(client, db_session, admin_a, token_a):
    for i in range(7):
        _event(db_session, token_a, ip="198.51.100.77", severity=EventSeverity.HIGH, minutes_ago=i)
    _event(db_session, token_a, ip="198.51.100.77", severity=EventSeverity.LOW, minutes_ago=3)
    db_session.commit()
    h = auth_headers(admin_a)
    first = client.get(f"{URL}?ip_address=198.51.100.77&severity=HIGH&limit=4", headers=h).json()
    rest = client.get(f"{URL}?ip_address=198.51.100.77&severity=HIGH&limit=4&cursor={first[-1]['id']}", headers=h).json()
    assert len(first) == 4 and len(rest) == 3
    times = [e["triggered_at"] for e in first + rest]
    assert times == sorted(times, reverse=True)
    assert {e["severity"] for e in first + rest} == {"HIGH"}


def test_filters_never_cross_tenants(client, db_session, admin_a, admin_b, token_a, token_b):
    _event(db_session, token_a, ip="192.0.2.50")
    _event(db_session, token_b, ip="192.0.2.50")
    db_session.commit()
    a = client.get(f"{URL}?ip_address=192.0.2.50", headers=auth_headers(admin_a)).json()
    b = client.get(f"{URL}?ip_address=192.0.2.50", headers=auth_headers(admin_b)).json()
    assert len(a) == 1 and len(b) == 1 and a[0]["id"] != b[0]["id"]


def test_each_event_names_its_decoy_but_never_the_secret(client, db_session, admin_a, token_a):
    _event(db_session, token_a)
    db_session.commit()
    e = client.get(URL, headers=auth_headers(admin_a)).json()[0]
    assert e["decoy_id"] == token_a.decoy_id
    assert e["decoy_type"] == token_a.token_type.value
    assert e["project_domain"]
    assert "token_value" not in e


def test_viewers_still_get_masked_paths_with_decoy_identity(client, db_session, user_a, token_a):
    _event(db_session, token_a)
    db_session.commit()
    e = client.get(URL, headers=auth_headers(user_a)).json()[0]
    assert token_a.token_value not in e["request_path"]
    assert e["decoy_id"] == token_a.decoy_id


def test_export_honours_the_address_filter(client, db_session, admin_a, token_a):
    _seed(db_session, token_a)
    r = client.get(f"{URL}/export?ip_address=198.51.100.1", headers=auth_headers(admin_a))
    assert r.status_code == 200
    lines = [ln for ln in r.text.splitlines() if ln]
    assert len(lines) == 1 + 2 and all("198.51.100.1" in ln for ln in lines[1:])


def _ids(client, headers):
    return [e["id"] for e in client.get(URL, headers=headers).json()]


def test_get_one_event_in_scope(client, db_session, admin_a, token_a):
    _seed(db_session, token_a)
    h = auth_headers(admin_a)
    newest = client.get(URL, headers=h).json()[0]
    r = client.get(f"{URL}/{newest['id']}", headers=h)
    assert r.status_code == 200
    assert r.json() == newest                        # same view as the list, decoy identity included
    assert client.get(f"{URL}/999999999", headers=h).status_code == 404
    assert client.get(f"{URL}/0", headers=h).status_code == 422
    # the fixed sub-paths are not captured by the id route
    assert client.get(f"{URL}/activity?days=7", headers=h).status_code == 200


def test_get_one_event_never_crosses_tenants(client, db_session, admin_a, admin_b, system_admin, token_a, token_b):
    _event(db_session, token_b)
    db_session.commit()
    other = _ids(client, auth_headers(admin_b))[0]
    cross = client.get(f"{URL}/{other}", headers=auth_headers(admin_a))
    missing = client.get(f"{URL}/999999999", headers=auth_headers(admin_a))
    assert cross.status_code == missing.status_code == 404
    assert cross.json()["detail"] == missing.json()["detail"]      # indistinguishable from a missing id
    assert client.get(f"{URL}/{other}", headers=auth_headers(system_admin)).status_code == 200


def test_get_one_event_masks_the_secret_for_viewers(client, db_session, user_a, admin_a, token_a):
    _seed(db_session, token_a)
    newest = _ids(client, auth_headers(admin_a))[0]
    e = client.get(f"{URL}/{newest}", headers=auth_headers(user_a)).json()
    assert token_a.token_value not in e["request_path"] and e["decoy_id"] == token_a.decoy_id
    assert token_a.token_value in client.get(f"{URL}/{newest}", headers=auth_headers(admin_a)).json()["request_path"]


def test_decoy_list_shows_when_each_decoy_last_fired(client, db_session, admin_a, user_a, project_a, token_a):
    from app.models.enums import HoneyTokenType
    from app.models.honey_token import HoneyToken
    quiet = HoneyToken(project_id=project_a.id, token_type=HoneyTokenType.URL, token_value="quiet-decoy-value",
                       label="never touched", is_active=True)
    db_session.add(quiet)
    _seed(db_session, token_a)                    # newest hit: 5 minutes ago
    url = f"/api/v1/honey-tokens?project_domain={project_a.domain}&active_only=false"
    for who in (admin_a, user_a):                 # masked viewers get the same timestamps
        rows = {t["label"] or t["token_value"]: t for t in client.get(url, headers=auth_headers(who)).json()}
        fired = next(t for t in rows.values() if t["id"] == token_a.id)["last_triggered_at"]
        age = datetime.now(timezone.utc) - datetime.fromisoformat(fired.replace("Z", "+00:00")).replace(tzinfo=timezone.utc)
        assert timedelta(minutes=4) < age < timedelta(minutes=6)
        assert rows["never touched"]["last_triggered_at"] is None


def test_filter_by_public_decoy_id_in_list_and_export(client, db_session, admin_a, admin_b, user_a, project_a, token_a, token_b):
    from app.models.enums import HoneyTokenType
    from app.models.honey_token import HoneyToken
    other = HoneyToken(project_id=project_a.id, token_type=HoneyTokenType.LINK, token_value="other-decoy-value", is_active=True)
    db_session.add(other)
    db_session.commit()
    _seed(db_session, token_a)
    _event(db_session, other, ip="192.0.2.50")
    _event(db_session, token_b, ip="192.0.2.99")
    db_session.commit()
    for who in (admin_a, user_a):
        r = client.get(URL, params={"decoy_id": token_a.decoy_id}, headers=auth_headers(who))
        assert r.status_code == 200 and len(r.json()) == 4 and {e["decoy_id"] for e in r.json()} == {token_a.decoy_id}
    combined = client.get(URL, params={"decoy_id": token_a.decoy_id, "severity": "CRITICAL"}, headers=auth_headers(admin_a))
    assert [e["severity"] for e in combined.json()] == ["CRITICAL"]
    # another tenant's decoy id is indistinguishable from an unknown one
    cross = client.get(URL, params={"decoy_id": token_b.decoy_id}, headers=auth_headers(admin_a))
    unknown = client.get(URL, params={"decoy_id": "dcy_does_not_exist"}, headers=auth_headers(admin_a))
    assert cross.status_code == unknown.status_code == 404 and cross.json()["detail"] == unknown.json()["detail"]
    export = client.get(f"{URL}/export", params={"decoy_id": token_a.decoy_id}, headers=auth_headers(admin_a))
    assert export.status_code == 200 and export.headers["X-Export-Rows"] == "4"
    assert "192.0.2.50" not in export.text and "192.0.2.99" not in export.text
