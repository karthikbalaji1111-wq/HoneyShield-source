"""Every decoy hit is a database write under the tenant's chain lock: keep its query count small.

Before this guard a hit took 12 statements on PostgreSQL (3 of them re-reading committed rows only
to build the live-feed message); now 7: decoy lookup (+project), event insert, chain head
lock/update, link insert, destination lookup, outbox insert.
"""
from __future__ import annotations

from sqlalchemy import event as sa_event


def _statements_for_one_hit(client, engine, token):
    client.get(f"/t/{token.token_value}")            # first hit creates the tenant's chain head
    token_value = token.token_value                  # read before listening (fixture refresh)
    seen = []
    listener = lambda conn, cur, statement, params, ctx, many: seen.append(" ".join(statement.split()).upper())
    sa_event.listen(engine, "before_cursor_execute", listener)
    try:
        assert client.get(f"/t/{token_value}", headers={"User-Agent": "budget"}).status_code == 204
    finally:
        sa_event.remove(engine, "before_cursor_execute", listener)
    return [s for s in seen if s.split()[0] in ("SELECT", "INSERT", "UPDATE", "DELETE")]


def test_a_decoy_hit_costs_at_most_seven_statements(client, engine, token_a):
    stmts = _statements_for_one_hit(client, engine, token_a)
    assert len(stmts) <= 7, [s[:60] for s in stmts]


def test_live_feed_message_does_not_reload_committed_rows(client, engine, token_a):
    stmts = _statements_for_one_hit(client, engine, token_a)
    event_insert = next(i for i, s in enumerate(stmts) if s.startswith("INSERT INTO DETECTION_EVENTS"))
    rereads = [s[:60] for s in stmts[event_insert + 1:]
               if s.startswith("SELECT") and any(f"FROM {t} " in s + " " or f"FROM {t}\n" in s
                                                 for t in ("DETECTION_EVENTS", "HONEY_TOKENS", "PROJECTS"))]
    assert rereads == [], rereads
