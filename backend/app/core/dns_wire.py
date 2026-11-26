"""DNS wire format: the strict subset an authoritative decoy name server needs.

RFC 1035 messages, RFC 6891 EDNS(0) and RFC 7871 client subnet. Parsing is for untrusted input
from the internet: every length is checked against the packet, compression pointers are refused
in the question (where they can never be valid) and followed only forwards-safe elsewhere, and
anything unexpected raises FormatError. No I/O, no settings: the listener and the tests use it.
"""
from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass

MAX_PACKET = 4096
MAX_NAME = 255

QTYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA",
               33: "SRV", 35: "NAPTR", 43: "DS", 48: "DNSKEY", 64: "SVCB", 65: "HTTPS", 255: "ANY",
               257: "CAA"}
A, NS, SOA, AAAA, OPT, ANY = 1, 2, 6, 28, 41, 255
CLASS_IN = 1

NOERROR, FORMERR, SERVFAIL, NXDOMAIN, NOTIMP, REFUSED = 0, 1, 2, 3, 4, 5


class FormatError(ValueError):
    pass


@dataclass(frozen=True)
class Query:
    id: int
    opcode: int
    rd: bool
    qname: str            # presentation form, lower case, no trailing dot ("" is the root)
    qtype: int
    qclass: int
    question_wire: bytes  # the question exactly as received (case preserved, for the reply)
    edns: bool = False
    client_subnet: str | None = None

    @property
    def qtype_name(self) -> str:
        return QTYPE_NAMES.get(self.qtype, f"TYPE{self.qtype}")


def _presentation(label: bytes) -> str:
    out = []
    for b in label:
        c = chr(b)
        if c.isascii() and (c.isalnum() or c in "-_*"):
            out.append(c.lower())
        else:
            out.append(f"\\{b:03d}")
    return "".join(out)


def _read_question_name(data: bytes, pos: int) -> tuple[str, int]:
    labels, total = [], 0
    while True:
        if pos >= len(data):
            raise FormatError("name runs past the packet")
        length = data[pos]
        if length & 0xC0:
            raise FormatError("compression or extended label in the question")
        pos += 1
        if length == 0:
            break
        total += length + 1
        if total > MAX_NAME or pos + length > len(data):
            raise FormatError("name too long")
        labels.append(_presentation(data[pos:pos + length]))
        pos += length
    return ".".join(labels), pos


def _skip_name(data: bytes, pos: int) -> int:
    """Skip a possibly compressed name in a record; the pointer target is never followed."""
    total = 0
    while True:
        if pos >= len(data):
            raise FormatError("name runs past the packet")
        length = data[pos]
        if length & 0xC0 == 0xC0:
            if pos + 2 > len(data):
                raise FormatError("truncated pointer")
            return pos + 2
        if length & 0xC0:
            raise FormatError("extended label")
        pos += 1
        if length == 0:
            return pos
        total += length + 1
        if total > MAX_NAME or pos + length > len(data):
            raise FormatError("name too long")
        pos += length


def _client_subnet(option: bytes) -> str | None:
    if len(option) < 4:
        raise FormatError("short client-subnet option")
    family, source_prefix = struct.unpack("!HB", option[:3])
    address = option[4:]
    if family == 1:
        size, bits = 4, 32
    elif family == 2:
        size, bits = 16, 128
    else:
        return None
    if source_prefix > bits or len(address) != (source_prefix + 7) // 8:
        raise FormatError("malformed client-subnet option")
    ip = ipaddress.ip_address(address.ljust(size, b"\0"))
    return f"{ip}/{source_prefix}"


def parse_query(data: bytes) -> Query:
    """Parse a query. Raises FormatError for anything that is not a well-formed single question."""
    if len(data) < 12 or len(data) > MAX_PACKET:
        raise FormatError("bad message size")
    msg_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    if flags & 0x8000:
        raise FormatError("not a query")
    opcode = (flags >> 11) & 0xF
    rd = bool(flags & 0x0100)
    if opcode != 0:
        return Query(msg_id, opcode, rd, "", 0, 0, b"")
    if qdcount != 1 or ancount or nscount or arcount > 2:
        raise FormatError("expected exactly one question")
    qname, pos = _read_question_name(data, 12)
    if pos + 4 > len(data):
        raise FormatError("truncated question")
    qtype, qclass = struct.unpack("!HH", data[pos:pos + 4])
    question = data[12:pos + 4]
    pos += 4

    edns, subnet = False, None
    for _ in range(arcount):
        pos = _skip_name(data, pos)
        if pos + 10 > len(data):
            raise FormatError("truncated record")
        rtype, _rclass, _ttl, rdlength = struct.unpack("!HHIH", data[pos:pos + 10])
        pos += 10
        if pos + rdlength > len(data):
            raise FormatError("record data runs past the packet")
        rdata = data[pos:pos + rdlength]
        pos += rdlength
        if rtype != OPT:
            continue
        if edns:
            raise FormatError("more than one OPT record")
        edns = True
        opt_pos = 0
        while opt_pos < len(rdata):
            if opt_pos + 4 > len(rdata):
                raise FormatError("truncated EDNS option")
            code, length = struct.unpack("!HH", rdata[opt_pos:opt_pos + 4])
            opt_pos += 4
            if opt_pos + length > len(rdata):
                raise FormatError("EDNS option runs past the record")
            if code == 8:
                subnet = _client_subnet(rdata[opt_pos:opt_pos + length])
            opt_pos += length
    if pos != len(data):
        raise FormatError("trailing bytes")
    return Query(msg_id, 0, rd, qname, qtype, qclass, question, edns, subnet)


def encode_name(name: str) -> bytes:
    """Wire form of a host name in presentation form (letters, digits, hyphen, underscore)."""
    out = bytearray()
    for label in [p for p in name.strip(".").split(".") if p]:
        raw = label.encode("ascii")
        if not 1 <= len(raw) <= 63:
            raise ValueError(f"bad label in {name!r}")
        out += bytes([len(raw)]) + raw
    out += b"\0"
    if len(out) > MAX_NAME:
        raise ValueError(f"name too long: {name!r}")
    return bytes(out)


QUESTION_NAME = b"\xc0\x0c"  # compression pointer to the name in the question


@dataclass(frozen=True)
class Record:
    name: bytes       # wire form (QUESTION_NAME or encode_name(...))
    rtype: int
    ttl: int
    rdata: bytes

    def wire(self) -> bytes:
        return self.name + struct.pack("!HHIH", self.rtype, CLASS_IN, self.ttl, len(self.rdata)) + self.rdata


def a_record(name: bytes, ttl: int, address: str) -> Record:
    ip = ipaddress.ip_address(address)
    return Record(name, A if ip.version == 4 else AAAA, ttl, ip.packed)


def ns_record(name: bytes, ttl: int, target: str) -> Record:
    return Record(name, NS, ttl, encode_name(target))


def soa_record(name: bytes, ttl: int, mname: str, rname: str, serial: int, minimum: int) -> Record:
    rdata = encode_name(mname) + encode_name(rname) + struct.pack("!IIIII", serial, 3600, 600, 1209600, minimum)
    return Record(name, SOA, ttl, rdata)


def build_response(query: Query, rcode: int, answers: list[Record] = (), authority: list[Record] = (),
                   authoritative: bool = True, truncated: bool = False) -> bytes:
    flags = (0x8000 | (query.opcode << 11) | (0x0400 if authoritative else 0) | (0x0200 if truncated else 0)
             | (0x0100 if query.rd else 0) | rcode)
    qd = 1 if query.question_wire else 0
    header = struct.pack("!HHHHHH", query.id, flags, qd, len(answers), len(authority), 0)
    return header + query.question_wire + b"".join(r.wire() for r in answers) + b"".join(r.wire() for r in authority)


def build_error(data: bytes, rcode: int) -> bytes | None:
    """A header-only reply to a message that could not be parsed, or None when there is no id."""
    if len(data) < 12:
        return None
    msg_id, flags = struct.unpack("!HH", data[:4])
    if flags & 0x8000:
        return None  # never answer a response (reflection loops)
    out_flags = 0x8000 | (flags & 0x7900) | rcode  # keep opcode and RD
    return struct.pack("!HHHHHH", msg_id, out_flags, 0, 0, 0, 0)
