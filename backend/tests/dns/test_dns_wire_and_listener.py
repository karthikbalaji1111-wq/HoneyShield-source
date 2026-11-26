"""DNS decoys at the name server: wire format, answers, what is recorded, and the spool.

The listener faces the internet, so the parser is fuzzed and the answer policy is pinned down:
the same answer for decoy and non-decoy names (no oracle), REFUSED outside the zone (never an
open resolver), and a spooled hit only for names that carry a token label.
"""
from __future__ import annotations

import asyncio
import json
import os
import socket
import struct
import threading
import time

import pytest
from hypothesis import given, settings as hsettings, strategies as st

from app.core import dns_wire as w
from app.core.dns_tokens import TOKEN_LABEL, new_token_label, normalise_zone, token_label
from app.workers import dns_listener as dl

ZONE = "dns.example.net"


def query(name: str, qtype: int = w.A, *, msg_id: int = 4242, rd: bool = True, edns: bytes | None = None) -> bytes:
    flags = 0x0100 if rd else 0
    ar = 1 if edns is not None else 0
    out = struct.pack("!HHHHHH", msg_id, flags, 1, 0, 0, ar) + w.encode_name(name) + struct.pack("!HH", qtype, 1)
    if edns is not None:
        out += b"\0" + struct.pack("!HHIH", w.OPT, 1232, 0, len(edns)) + edns
    return out


def ecs_option(prefix: str) -> bytes:
    import ipaddress
    net = ipaddress.ip_network(prefix)
    addr = net.network_address.packed[: (net.prefixlen + 7) // 8]
    data = struct.pack("!HBB", 1 if net.version == 4 else 2, net.prefixlen, 0) + addr
    return struct.pack("!HH", 8, len(data)) + data


def header(reply: bytes) -> tuple[int, int, int, int]:
    msg_id, flags, _qd, an, ns, _ar = struct.unpack("!HHHHHH", reply[:12])
    return msg_id, flags, an, ns


@pytest.fixture()
def cfg():
    return dl.ZoneConfig(ZONE, ipv4="198.51.100.53", nameservers=[f"ns1.{ZONE}"], ttl=30, serial=7)


@pytest.fixture()
def listener(tmp_path, cfg):
    return dl.Listener(cfg, dl.Spool(str(tmp_path / "hits.jsonl")), rate_per_second=1000)


def spooled(listener) -> list[dict]:
    entries, _ = listener.spool.read(0)
    return entries


# ----------------------------------------------------------------------------------- token names
def test_token_labels_are_dns_safe_and_found_under_the_zone():
    label = new_token_label()
    assert TOKEN_LABEL.match(label)
    assert token_label(f"{label}.{ZONE}", ZONE) == label
    assert token_label(f"laptop-7.{label}.{ZONE}", ZONE) == label
    assert token_label(f"{label}.other.example", ZONE) is None
    assert token_label(f"www.{ZONE}", ZONE) is None
    assert token_label(ZONE, ZONE) is None
    assert token_label(f"{label}.x{ZONE}", ZONE) is None


def test_zone_names_are_validated():
    assert normalise_zone(" DNS.Example.COM. ") == "dns.example.com"
    assert normalise_zone("") is None
    for bad in ("http://dns.example.com", "dns example.com", "-x.example.com", "localhost"):
        with pytest.raises(ValueError):
            normalise_zone(bad)


# ----------------------------------------------------------------------------------- parsing
def test_parse_keeps_the_question_as_sent_and_lower_cases_the_name():
    label = new_token_label()
    mixed = f"{label.upper()}.DnS.ExAmPle.NeT"
    q = w.parse_query(query(mixed, w.AAAA))
    assert q.qname == f"{label}.{ZONE}" and q.qtype_name == "AAAA" and q.rd
    assert mixed.encode()[:5] in q.question_wire      # reply echoes the resolver's 0x20 casing


def test_parse_reads_edns_client_subnet():
    q = w.parse_query(query(f"x.{ZONE}", edns=ecs_option("203.0.113.0/24")))
    assert q.edns and q.client_subnet == "203.0.113.0/24"


@pytest.mark.parametrize("packet", [
    b"", b"\0" * 11,
    struct.pack("!HHHHHH", 1, 0x8000, 1, 0, 0, 0) + w.encode_name(ZONE) + b"\0\1\0\1",  # a response
    struct.pack("!HHHHHH", 1, 0, 2, 0, 0, 0) + w.encode_name(ZONE) + b"\0\1\0\1",       # two questions
    struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0) + b"\xc0\x0c\0\1\0\1",                   # pointer in question
    struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0) + b"\x3fabc",                             # label past the end
    struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0) + w.encode_name(ZONE) + b"\0\1",          # truncated question
    query(ZONE) + b"junk",                                                               # trailing bytes
])
def test_malformed_messages_are_format_errors(packet):
    with pytest.raises(w.FormatError):
        w.parse_query(packet)


@hsettings(max_examples=400, deadline=None)
@given(st.binary(max_size=600))
def test_parser_never_fails_on_garbage(data):
    try:
        w.parse_query(data)
    except w.FormatError:
        pass


@hsettings(max_examples=300, deadline=None)
@given(st.binary(max_size=600))
def test_listener_never_fails_on_garbage(tmp_path_factory, data):
    lst = dl.Listener(dl.ZoneConfig(ZONE, ipv4="198.51.100.53", nameservers=[f"ns1.{ZONE}"]),
                      dl.Spool(str(tmp_path_factory.mktemp("s") / "h.jsonl")), rate_per_second=10_000)
    reply = lst.handle(data, "203.0.113.9", "udp")
    assert reply is None or len(reply) >= 12


# ----------------------------------------------------------------------------------- answers
def test_decoy_and_ordinary_names_get_the_same_answer(listener):
    decoy = listener.handle(query(f"{new_token_label()}.{ZONE}"), "203.0.113.9", "udp")
    other = listener.handle(query(f"{new_token_label()[:-1]}x.{ZONE}"), "203.0.113.9", "udp")
    plain = listener.handle(query(f"www.{ZONE}"), "203.0.113.9", "udp")
    for reply in (decoy, other, plain):
        msg_id, flags, an, ns = header(reply)
        assert msg_id == 4242 and flags & 0x8000 and flags & 0x0400 and flags & 0x0F == w.NOERROR
        assert an == 1 and reply.endswith(bytes([198, 51, 100, 53]))
    assert decoy[:2] + decoy[2:4] == other[:4] and len(decoy) == len(other)   # same flags, same size
    assert decoy[-16:] == other[-16:] == plain[-16:]                          # same answer record


def test_other_zones_are_refused_and_never_recursed(listener):
    reply = listener.handle(query("example.org"), "203.0.113.9", "udp")
    _, flags, an, _ = header(reply)
    assert flags & 0x0F == w.REFUSED and not flags & 0x0400 and an == 0
    assert not flags & 0x0080                                           # RA: no recursion offered
    assert spooled(listener) == []


def test_apex_answers_soa_and_ns_and_missing_types_get_nodata(listener):
    _, _, an, _ = header(listener.handle(query(ZONE, w.SOA), "203.0.113.9", "udp"))
    assert an == 1
    _, _, an, _ = header(listener.handle(query(ZONE, w.NS), "203.0.113.9", "udp"))
    assert an == 1
    _, flags, an, ns = header(listener.handle(query(f"{new_token_label()}.{ZONE}", w.AAAA), "203.0.113.9", "udp"))
    assert flags & 0x0F == w.NOERROR and an == 0 and ns == 1            # NODATA with the SOA


def test_other_opcodes_are_not_implemented(listener):
    packet = bytearray(query(ZONE))
    packet[2] |= 0x28                                                    # opcode 5 (UPDATE)
    assert header(listener.handle(bytes(packet), "203.0.113.9", "udp"))[1] & 0x0F == w.NOTIMP


# ----------------------------------------------------------------------------------- what is recorded
def test_a_decoy_lookup_is_spooled_with_what_the_server_saw(listener):
    label = new_token_label()
    listener.handle(query(f"build-07.{label}.{ZONE}", w.TXT if hasattr(w, "TXT") else 16,
                          edns=ecs_option("198.51.100.0/24")), "192.0.2.53", "udp")
    [hit] = spooled(listener)
    assert hit["qname"] == f"build-07.{label}.{ZONE}" and hit["qtype"] == "TXT"
    assert hit["resolver"] == "192.0.2.53" and hit["transport"] == "udp" and hit["ecs"] == "198.51.100.0/24"
    assert len(hit["request_id"]) == 32 and abs(hit["time"] - time.time()) < 5


def test_names_without_a_token_label_are_not_spooled(listener):
    for name in (ZONE, f"www.{ZONE}", f"ns1.{ZONE}", f"{'a' * 25}.{ZONE}"):
        listener.handle(query(name), "203.0.113.9", "udp")
    assert spooled(listener) == []


def test_resolver_retransmits_are_one_hit(listener):
    name = f"{new_token_label()}.{ZONE}"
    for _ in range(3):
        listener.handle(query(name), "203.0.113.9", "udp")
    listener.handle(query(name, w.AAAA), "203.0.113.9", "udp")
    assert len(spooled(listener)) == 2


def test_a_flooding_source_is_throttled_without_filling_the_spool(tmp_path, cfg):
    lst = dl.Listener(cfg, dl.Spool(str(tmp_path / "h.jsonl")), rate_per_second=5)
    replies = [lst.handle(query(f"{new_token_label()}.{ZONE}"), "203.0.113.66", "udp") for _ in range(50)]
    assert replies.count(None) >= 35 and len(spooled(lst)) <= 15
    assert lst.handle(query(f"{new_token_label()}.{ZONE}"), "203.0.113.67", "udp") is not None


def test_a_full_spool_drops_new_hits_but_keeps_answering(tmp_path, cfg):
    lst = dl.Listener(cfg, dl.Spool(str(tmp_path / "h.jsonl"), max_bytes=300), rate_per_second=1000)
    for _ in range(5):
        assert lst.handle(query(f"{new_token_label()}.{ZONE}"), "203.0.113.9", "udp") is not None
    assert lst.stats["spool_full"] >= 1 and os.path.getsize(tmp_path / "h.jsonl") <= 300


# ----------------------------------------------------------------------------------- spool
def test_spool_position_survives_restarts_and_empties_once_sent(tmp_path, monkeypatch):
    monkeypatch.setattr(dl, "COMPACT_AFTER_BYTES", 10)
    spool = dl.Spool(str(tmp_path / "h.jsonl"))
    for i in range(3):
        spool.append({"n": i})
    entries, consumed = spool.read(0, limit=2)
    assert [e["n"] for e in entries] == [0, 1]
    spool.accept(consumed)
    again = dl.Spool(str(tmp_path / "h.jsonl"))
    rest, more = again.read(again.position())
    assert [e["n"] for e in rest] == [2]
    assert again.accept(again.position() + more) == 0 and os.path.getsize(tmp_path / "h.jsonl") == 0


def test_shipper_sends_signed_batches_and_heartbeats(tmp_path, monkeypatch):
    from app.core.replay_signing import dns_hits_key, sign
    from app.workers import ingest_replay

    sent = []

    def fake_send(url, key, entries, timeout=30.0):
        assert key == dns_hits_key("k" * 32) and url == "http://backend:8000/internal/v1/dns-hits"
        sent.append(list(entries))
        return {"recorded": len(entries)}

    monkeypatch.setattr(ingest_replay, "send", fake_send)
    monkeypatch.setattr(dl, "ALIVE_FILE", str(tmp_path / "alive"))
    spool = dl.Spool(str(tmp_path / "h.jsonl"))
    spool.append({"request_id": "a" * 32})
    stop = threading.Event()
    t = threading.Thread(target=dl.ship, args=(spool, "http://backend:8000/internal/v1/dns-hits",
                                               dns_hits_key("k" * 32), stop))
    t.start()
    deadline = time.time() + 5
    while not sent and time.time() < deadline:
        time.sleep(0.05)
    stop.set()
    t.join(5)
    assert sent[0] == [{"request_id": "a" * 32}]
    assert spool.position() > 0 and os.path.exists(tmp_path / "alive")
    assert sign(b"k", "1", b"x").startswith("v1=")


# ----------------------------------------------------------------------------------- real sockets
def test_udp_and_tcp_on_a_real_socket(listener):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    stop_event = threading.Event()
    loop = asyncio.new_event_loop()

    def run():
        async def main():
            stop = asyncio.Event()
            async def watch():
                while not stop_event.is_set():
                    await asyncio.sleep(0.05)
                stop.set()
            asyncio.ensure_future(watch())
            await dl.serve(listener, "127.0.0.1", port, stop)
        loop.run_until_complete(main())

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    try:
        assert _wait_for(lambda: dl.check(port, ZONE) == 0)
        name = f"{new_token_label()}.{ZONE}"
        with socket.create_connection(("127.0.0.1", port), timeout=3) as tcp:
            packet = query(name, msg_id=77)
            tcp.sendall(struct.pack("!H", len(packet)) + packet)
            size = struct.unpack("!H", _recv(tcp, 2))[0]
            reply = _recv(tcp, size)
        assert header(reply)[0] == 77 and header(reply)[2] == 1
        assert [h["transport"] for h in spooled(listener)] == ["tcp"]
    finally:
        stop_event.set()
        thread.join(5)


def _recv(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        assert chunk
        data += chunk
    return data


def _wait_for(check, seconds=5.0):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if check():
            return True
        time.sleep(0.05)
    return False


def test_config_comes_from_the_environment():
    cfg = dl.ZoneConfig.from_env({"DNS_TOKEN_ZONE": "Canary.Example.ORG", "DNS_ANSWER_IPV4": "192.0.2.1",
                                  "DNS_NAMESERVERS": "ns1.canary.example.org,ns2.canary.example.org"})
    assert cfg.zone == "canary.example.org" and cfg.nameservers[1] == "ns2.canary.example.org"
    with pytest.raises(SystemExit):
        dl.ZoneConfig.from_env({"DNS_TOKEN_ZONE": "canary.example.org", "DNS_ANSWER_IPV4": "2001:db8::1"})
    with pytest.raises(SystemExit):
        dl.ZoneConfig.from_env({})
    assert json.dumps(dl.ZoneConfig.from_env({"DNS_TOKEN_ZONE": "a.example.com"}).nameservers) == '["ns1.a.example.com"]'
