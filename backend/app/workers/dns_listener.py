"""Authoritative name server for DNS decoys: ``python -m app.workers.dns_listener``.

Answers for one zone (DNS_TOKEN_ZONE) that the operator delegates to this server. Every name in
the zone gets the same answer whether or not it is a decoy, so the server cannot be used to test
names; it never recurses and refuses every other zone (it is not an open resolver).

A query for a decoy name (<token>.<zone>, or anything.<token>.<zone>) is a hit. Hits are appended
to a spool file first and then sent, in signed batches, to the backend's internal endpoint
(/internal/v1/dns-hits); the saved position only moves once the backend has accepted a batch, so a
hit survives a backend outage or a restart of this process. The listener holds no database
credentials and stores no query that is not a decoy.

What a DNS hit shows: the address of the resolver that asked (the visitor's own resolver, their
ISP's or a public one), sometimes the visitor's network through EDNS client subnet, and the time.
It does not show who typed the name.

Environment: DNS_TOKEN_ZONE, DNS_ANSWER_IPV4, DNS_ANSWER_IPV6, DNS_NAMESERVERS, DNS_TTL,
DNS_LISTEN_HOST, DNS_LISTEN_PORT, DNS_RATE_PER_SECOND, HS_DNS_SPOOL, HS_DNS_HITS_URL,
INTEGRATION_SIGNING_KEY. ``--check`` asks the running server for the zone's SOA (health check).
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import secrets
import signal
import socket
import struct
import sys
import threading
import time
import urllib.error
from dataclasses import dataclass, field

from app.core import dns_wire as w
from app.core.dns_tokens import in_zone, normalise_zone, token_label
from app.core.replay_signing import dns_hits_key

logger = logging.getLogger("honeyshield.dns")

UDP_LIMIT = 512
SPOOL_MAX_BYTES = 64 * 1024 * 1024
COMPACT_AFTER_BYTES = 1024 * 1024
BATCH = 500
HEARTBEAT_SECONDS = 60
RETRANSMIT_SECONDS = 5.0
TCP_IDLE_SECONDS = 10.0
TCP_MAX_CONNECTIONS = 100
# Liveness marker for the health check, on the container's private /tmp (a tmpfs).
ALIVE_FILE = "/tmp/dns-listener.alive"  # nosec B108


@dataclass
class ZoneConfig:
    zone: str
    ipv4: str | None = None
    ipv6: str | None = None
    nameservers: list[str] = field(default_factory=list)
    ttl: int = 30
    serial: int = 1

    @property
    def hostmaster(self) -> str:
        return f"hostmaster.{self.zone}"

    @classmethod
    def from_env(cls, env=os.environ) -> "ZoneConfig":
        zone = normalise_zone(env.get("DNS_TOKEN_ZONE"))
        if not zone:
            raise SystemExit("DNS_TOKEN_ZONE is required")
        ipv4 = env.get("DNS_ANSWER_IPV4") or None
        ipv6 = env.get("DNS_ANSWER_IPV6") or None
        if ipv4 and ipaddress.ip_address(ipv4).version != 4:
            raise SystemExit("DNS_ANSWER_IPV4 must be an IPv4 address")
        if ipv6 and ipaddress.ip_address(ipv6).version != 6:
            raise SystemExit("DNS_ANSWER_IPV6 must be an IPv6 address")
        servers = [s.strip().lower().rstrip(".") for s in (env.get("DNS_NAMESERVERS") or "").split(",") if s.strip()]
        for name in servers:
            w.encode_name(name)
        ttl = int(env.get("DNS_TTL") or 30)
        if not 0 <= ttl <= 86400:
            raise SystemExit("DNS_TTL must be between 0 and 86400")
        return cls(zone, ipv4, ipv6, servers or [f"ns1.{zone}"], ttl, int(time.time()) & 0xFFFFFFFF)


def answer(query: w.Query, cfg: ZoneConfig) -> tuple[bytes, dict | None]:
    """The reply to ``query`` and the hit to record (None when the name is not a decoy name)."""
    if query.opcode != 0:
        return w.build_response(query, w.NOTIMP, authoritative=False), None
    if query.qclass not in (w.CLASS_IN, w.ANY) or not in_zone(query.qname, cfg.zone):
        return w.build_response(query, w.REFUSED, authoritative=False), None
    apex = query.qname == cfg.zone
    soa = w.soa_record(w.encode_name(cfg.zone), cfg.ttl, cfg.nameservers[0], cfg.hostmaster, cfg.serial, cfg.ttl)
    qt, here = query.qtype, w.QUESTION_NAME
    answers: list[w.Record] = []
    if apex and qt in (w.SOA, w.ANY):
        answers.append(w.Record(here, w.SOA, soa.ttl, soa.rdata))
    if apex and qt in (w.NS, w.ANY):
        answers += [w.ns_record(here, cfg.ttl, ns) for ns in cfg.nameservers]
    if qt in (w.A, w.ANY) and cfg.ipv4:
        answers.append(w.a_record(here, cfg.ttl, cfg.ipv4))
    if qt in (w.AAAA, w.ANY) and cfg.ipv6:
        answers.append(w.a_record(here, cfg.ttl, cfg.ipv6))
    reply = w.build_response(query, w.NOERROR, answers, [] if answers else [soa])
    label = token_label(query.qname, cfg.zone)
    hit = {"qname": query.qname[:1024], "qtype": query.qtype_name, "ecs": query.client_subnet} if label else None
    return reply, hit


class RateLimiter:
    """Token bucket per source address, so the server is a poor reflector and a flood cannot fill the spool."""

    def __init__(self, per_second: float, burst: float | None = None, max_sources: int = 100_000) -> None:
        self.rate, self.burst, self.max_sources = per_second, burst or per_second * 2, max_sources
        self._buckets: dict[str, tuple[float, float]] = {}

    def allow(self, source: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        if len(self._buckets) >= self.max_sources:
            self._buckets.clear()
        tokens, last = self._buckets.get(source, (self.burst, now))
        tokens = min(self.burst, tokens + (now - last) * self.rate)
        if tokens < 1:
            self._buckets[source] = (tokens, now)
            return False
        self._buckets[source] = (tokens - 1, now)
        return True


class Spool:
    """Append-only JSON lines plus the position up to which the backend has accepted them."""

    def __init__(self, path: str, max_bytes: int = SPOOL_MAX_BYTES) -> None:
        self.path, self.state_path, self.max_bytes = path, f"{path}.position", max_bytes
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        if not os.path.exists(path):
            open(path, "ab").close()

    def append(self, entry: dict) -> bool:
        line = (json.dumps(entry, separators=(",", ":")) + "\n").encode()
        with self._lock:
            if os.path.getsize(self.path) + len(line) > self.max_bytes:
                return False
            with open(self.path, "ab") as fh:
                fh.write(line)
                fh.flush()
                os.fsync(fh.fileno())
        return True

    def position(self) -> int:
        try:
            with open(self.state_path) as fh:
                offset = int(json.load(fh)["offset"])
        except (OSError, ValueError, KeyError, TypeError):
            offset = 0
        return offset if 0 <= offset <= os.path.getsize(self.path) else 0

    def _save(self, offset: int) -> None:
        tmp = f"{self.state_path}.tmp"
        with open(tmp, "w") as fh:
            json.dump({"offset": offset}, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.state_path)

    def read(self, offset: int, limit: int = BATCH) -> tuple[list[dict], int]:
        """Complete lines after ``offset``: (entries, bytes consumed). Malformed lines are skipped."""
        entries, consumed = [], 0
        with open(self.path, "rb") as fh:
            fh.seek(offset)
            while len(entries) < limit:
                line = fh.readline()
                if not line or not line.endswith(b"\n"):
                    break
                consumed += len(line)
                try:
                    entries.append(json.loads(line))
                except ValueError:
                    logger.error("Skipping a malformed spool line")
        return entries, consumed

    def accept(self, offset: int) -> int:
        """Record that everything before ``offset`` was accepted; empty the file once fully sent."""
        with self._lock:
            if offset >= COMPACT_AFTER_BYTES and offset == os.path.getsize(self.path):
                with open(self.path, "r+b") as fh:
                    fh.truncate(0)
                offset = 0
            self._save(offset)
        return offset


class Listener:
    def __init__(self, cfg: ZoneConfig, spool: Spool, rate_per_second: float = 50.0) -> None:
        self.cfg, self.spool = cfg, spool
        self.limiter = RateLimiter(rate_per_second)
        self._recent: dict[tuple, float] = {}
        self.stats = {"queries": 0, "hits": 0, "refused": 0, "malformed": 0, "dropped": 0, "spool_full": 0}

    def handle(self, data: bytes, source: str, transport: str) -> bytes | None:
        self.stats["queries"] += 1
        if not self.limiter.allow(source):
            self.stats["dropped"] += 1
            return None
        try:
            query = w.parse_query(data)
        except w.FormatError:
            self.stats["malformed"] += 1
            return w.build_error(data, w.FORMERR)
        reply, hit = answer(query, self.cfg)
        if reply[3] & 0x0F == w.REFUSED:
            self.stats["refused"] += 1
        if transport == "udp" and len(reply) > UDP_LIMIT:
            reply = w.build_response(query, w.NOERROR, truncated=True)
        if hit is not None:
            self._record(hit, source, transport)
        return reply

    def _record(self, hit: dict, source: str, transport: str) -> None:
        now = time.time()
        key = (source, hit["qname"], hit["qtype"])
        if now - self._recent.get(key, 0.0) < RETRANSMIT_SECONDS:
            return  # the resolver retrying the same question: one event is enough
        if len(self._recent) > 50_000:
            self._recent = {k: t for k, t in self._recent.items() if now - t < RETRANSMIT_SECONDS}
        self._recent[key] = now
        try:
            source = str(ipaddress.ip_address(source).ipv4_mapped or ipaddress.ip_address(source))
        except (ValueError, AttributeError):
            pass
        entry = {"request_id": secrets.token_hex(16), "time": now, "resolver": source, "transport": transport, **hit}
        if self.spool.append(entry):
            self.stats["hits"] += 1
        else:
            self.stats["spool_full"] += 1
            logger.error("DNS spool is full (%d bytes): a decoy hit was not recorded", self.spool.max_bytes)


class _Udp(asyncio.DatagramProtocol):
    def __init__(self, listener: Listener) -> None:
        self.listener = listener
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        try:
            reply = self.listener.handle(data, addr[0], "udp")
        except Exception:
            logger.exception("Failed to handle a DNS query")
            return
        if reply and self.transport is not None:
            self.transport.sendto(reply, addr)


def _tcp_handler(listener: Listener, slots: asyncio.Semaphore):
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if slots.locked():
            writer.close()
            return
        async with slots:
            peer = (writer.get_extra_info("peername") or ("", 0))[0]
            try:
                for _ in range(20):
                    size = struct.unpack("!H", await asyncio.wait_for(reader.readexactly(2), TCP_IDLE_SECONDS))[0]
                    data = await asyncio.wait_for(reader.readexactly(size), TCP_IDLE_SECONDS)
                    reply = listener.handle(data, peer, "tcp")
                    if reply is None:
                        break
                    writer.write(struct.pack("!H", len(reply)) + reply)
                    await writer.drain()
            except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError):
                pass
            finally:
                writer.close()
    return handle


def ship(spool: Spool, url: str, key: bytes, stop: threading.Event) -> None:
    """Send spooled hits to the backend until ``stop`` is set (runs in its own thread)."""
    from app.workers.ingest_replay import send

    offset, last_sent, backoff = spool.position(), 0.0, 2.0
    while not stop.is_set():
        try:
            entries, consumed = spool.read(offset)
            if entries or time.monotonic() - last_sent >= HEARTBEAT_SECONDS:
                result = send(url, key, entries)  # an empty batch is the listener's heartbeat
                last_sent = time.monotonic()
                if entries:
                    logger.info("Delivered %d DNS hit(s): %s", len(entries), result)
            if consumed:
                offset = spool.accept(offset + consumed)
            with open(ALIVE_FILE, "w") as fh:
                fh.write(str(int(time.time())))
            backoff = 2.0
            if not consumed:
                stop.wait(1.0)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            logger.warning("Backend not accepting DNS hits yet (%s); retrying in %.0fs", exc, backoff)
            stop.wait(backoff)
            backoff = min(backoff * 2, 30.0)


async def serve(listener: Listener, host: str, port: int, stop: asyncio.Event) -> None:
    loop = asyncio.get_running_loop()
    udp, _ = await loop.create_datagram_endpoint(lambda: _Udp(listener), local_addr=(host, port))
    tcp = await asyncio.start_server(_tcp_handler(listener, asyncio.Semaphore(TCP_MAX_CONNECTIONS)), host, port)
    logger.info("DNS decoys for %s on %s:%d (udp+tcp)", listener.cfg.zone, host, port)
    last_stats = time.monotonic()
    try:
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), 60)
            except asyncio.TimeoutError:
                pass
            if time.monotonic() - last_stats >= 600:
                logger.info("DNS listener: %s", listener.stats)
                last_stats = time.monotonic()
    finally:
        udp.close()
        tcp.close()
        await tcp.wait_closed()


def check(port: int, zone: str) -> int:
    """Health check: the server answers an SOA query for its zone."""
    msg_id = secrets.randbelow(65536)
    query = struct.pack("!HHHHHH", msg_id, 0, 1, 0, 0, 0) + w.encode_name(zone) + struct.pack("!HH", w.SOA, w.CLASS_IN)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        try:
            sock.sendto(query, ("127.0.0.1", port))
            reply = sock.recv(UDP_LIMIT)
        except OSError:
            return 1
    ok = len(reply) >= 12 and struct.unpack("!H", reply[:2])[0] == msg_id and reply[3] & 0x0F == w.NOERROR
    return 0 if ok else 1


def main() -> int:  # pragma: no cover - process entry point, exercised end to end
    from app.core.logging import configure_logging

    configure_logging(os.environ.get("LOG_LEVEL", "INFO"))
    port = int(os.environ.get("DNS_LISTEN_PORT", "5353"))
    if "--check" in sys.argv:
        return check(port, normalise_zone(os.environ.get("DNS_TOKEN_ZONE")) or "")
    cfg = ZoneConfig.from_env()
    secret = os.environ.get("INTEGRATION_SIGNING_KEY")
    if not secret:
        raise SystemExit("INTEGRATION_SIGNING_KEY is required")
    spool = Spool(os.environ.get("HS_DNS_SPOOL", "/var/spool/honeyshield-dns/hits.jsonl"))
    listener = Listener(cfg, spool, float(os.environ.get("DNS_RATE_PER_SECOND", "50")))
    url = os.environ.get("HS_DNS_HITS_URL", "http://backend:8000/internal/v1/dns-hits")

    stop_thread = threading.Event()
    shipper = threading.Thread(target=ship, args=(spool, url, dns_hits_key(secret), stop_thread), daemon=True)
    shipper.start()

    async def run() -> None:
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, stop.set)
        # Binds all interfaces inside the container; the published port decides what is reachable.
        await serve(listener, os.environ.get("DNS_LISTEN_HOST", "0.0.0.0"), port, stop)  # nosec B104

    asyncio.run(run())
    stop_thread.set()
    shipper.join(timeout=10)
    logger.info("DNS listener stopped: %s", listener.stats)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
