"""Public triggers take their severity from the token type, not a fixed MEDIUM."""
from __future__ import annotations

import pytest

from app.models.detection_event import DetectionEvent
from app.models.enums import EventSeverity, HoneyTokenType
from app.models.honey_token import HoneyToken
from app.services.detection_event import DEFAULT_SEVERITY_BY_TOKEN_TYPE


def test_every_token_type_has_a_default_severity():
    assert set(DEFAULT_SEVERITY_BY_TOKEN_TYPE) == set(HoneyTokenType)


@pytest.mark.parametrize(
    "token_type, method, path_fmt, expected",
    [
        (HoneyTokenType.URL, "GET", "/t/{v}", EventSeverity.HIGH),
        (HoneyTokenType.LINK, "GET", "/t/{v}", EventSeverity.MEDIUM),
        (HoneyTokenType.PIXEL, "GET", "/px/{v}.gif", EventSeverity.HIGH),
        (HoneyTokenType.FORM_FIELD, "POST", "/collect/{v}", EventSeverity.MEDIUM),
        (HoneyTokenType.API_KEY, "POST", "/collect/{v}", EventSeverity.CRITICAL),
    ],
)
def test_public_hit_severity_follows_token_type(client, db_session, project_a, token_type, method, path_fmt, expected):
    token = HoneyToken(project_id=project_a.id, token_type=token_type,
                       token_value=f"sev-{token_type.value.lower()}-0123456789", is_active=True)
    db_session.add(token)
    db_session.flush()

    client.request(method, path_fmt.format(v=token.token_value))

    event = db_session.query(DetectionEvent).filter_by(honey_token_id=token.id).one()
    assert event.severity == expected
    assert event.request_path == path_fmt.format(v=token.token_value)
