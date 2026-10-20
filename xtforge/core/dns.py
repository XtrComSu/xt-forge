"""A minimal DNS client using only the standard library.

This host has no `dig`, `host` or `nslookup`, and adding a dependency for six
record types would be a poor trade. The wire format is stable and small
enough to speak directly: header, question, then length-prefixed answers with
compression pointers.

    from xtforge.core import dns
    dns.resolve("example.com")      # A, AAAA, MX, NS, TXT, CNAME

Every function returns data, never raises. A resolver timeout is reported as
`{"error": ...}` — recon must survive an unreachable resolver.
"""
from __future__ import annotations

import os
import random
import socket
import struct
from typing import Any

TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16,
         "AAAA": 28, "DS": 43, "DNSKEY": 48, "CAA": 257}
DEFAULT_TIMEOUT = 4
PUBLIC_RESOLVERS = ("1.1.1.1", "8.8.8.8")


def _resolver() -> str:
    """First nameserver from /etc/resolv.conf, else a public one."""
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    candidate = parts[1]
                    if candidate.count(":") == 0:      # IPv4 only for UDP
                        return candidate
    except OSError:
        pass
    return PUBLIC_RESOLVERS[0]


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        if not label:
            continue
        raw = label.encode("idna")[:63]
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _decode_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a possibly-compressed name. Returns (name, next offset)."""
    labels: list[str] = []
    jumped = False
    original = offset
    guard = 0
    while offset < len(data):
        guard += 1
        if guard > 64:
            break
        length = data[offset]
        if length & 0xC0 == 0xC0:                 # compression pointer
            if offset + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                original = offset + 2
            jumped = True
            offset = pointer
            continue
        if length == 0:
            offset += 1
            break
        labels.append(data[offset + 1:offset + 1 + length].decode("latin-1"))
        offset += 1 + length
    name = ".".join(labels)
    return name, (original if jumped else offset)


def _parse_rdata(rtype: int, data: bytes, start: int, length: int,
                 packet: bytes) -> Any:
    block = data[start:start + length]
    if rtype == TYPES["A"] and length == 4:
        return ".".join(str(b) for b in block)
    if rtype == TYPES["AAAA"] and length == 16:
        try:
            return socket.inet_ntop(socket.AF_INET6, block)
        except (OSError, ValueError):
            return block.hex()
    if rtype in (TYPES["NS"], TYPES["CNAME"]):
        return _decode_name(packet, start)[0]
    if rtype == TYPES["MX"]:
        if length < 3:
            return block.hex()
        preference = struct.unpack("!H", block[:2])[0]
        # RFC 7505 null MX: "0 ." means the domain accepts no mail.
        host = _decode_name(packet, start + 2)[0] or "."
        return {"preference": preference, "host": host}
    if rtype == TYPES["TXT"]:
        strings, index = [], 0
        while index < len(block):
            size = block[index]
            index += 1
            strings.append(block[index:index + size].decode("utf-8", "replace"))
            index += size
        return " ".join(strings)
    if rtype == TYPES["CAA"] and length >= 2:
        flags = block[0]
        tag_len = block[1]
        tag = block[2:2 + tag_len].decode("latin-1")
        value = block[2 + tag_len:].decode("latin-1")
        return {"flags": flags, "tag": tag, "value": value}
    if rtype == TYPES["DS"] and length >= 4:
        keytag, algorithm, digesttype = struct.unpack("!HBB", block[:4])
        return {"keytag": keytag, "algorithm": algorithm,
                "digest_type": digesttype, "digest": block[4:].hex()}
    if rtype == TYPES["DNSKEY"] and length >= 4:
        flags, protocol, algorithm = struct.unpack("!HBB", block[:4])
        return {"flags": flags, "protocol": protocol, "algorithm": algorithm,
                "key_len": len(block) - 4}
    return block.hex()


def _tcp_exchange(packet: bytes, target: str, timeout: int) -> bytes | None:
    """Retry a truncated response over TCP (RFC 1035 §4.2.2)."""
    try:
        with socket.create_connection((target, 53), timeout=timeout) as conn:
            conn.sendall(struct.pack("!H", len(packet)) + packet)
            header = conn.recv(2)
            if len(header) < 2:
                return None
            size = struct.unpack("!H", header)[0]
            data = b""
            while len(data) < size:
                chunk = conn.recv(size - len(data))
                if not chunk:
                    break
                data += chunk
            return data or None
    except (socket.timeout, OSError):
        return None


def query(name: str, rtype: str = "A", server: str | None = None,
          timeout: int = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """One DNS question. Returns {"records": [...], "error": ""}."""
    qtype = TYPES.get(rtype.upper())
    if qtype is None:
        return {"ok": False, "error": f"unsupported type {rtype}"}
    if not name or len(name) > 253:
        return {"ok": False, "error": "invalid name"}

    identifier = random.randint(0, 0xFFFF)
    # EDNS0 (OPT, 1232-byte payload) keeps large TXT sets under the UDP limit;
    # without it a site with several verification records comes back empty.
    packet = struct.pack("!HHHHHH", identifier, 0x0100, 1, 0, 0, 1)
    packet += _encode_name(name) + struct.pack("!HH", qtype, 1)
    packet += b"\x00" + struct.pack("!HHIH", 41, 1232, 0, 0)

    target = server or _resolver()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (target, 53))
        data, _ = sock.recvfrom(65535)
    except (socket.timeout, OSError) as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    finally:
        sock.close()

    if len(data) < 12:
        return {"ok": False, "error": "short response"}
    flags = struct.unpack("!H", data[2:4])[0]
    if flags & 0x0200:                     # truncated: the answer needs TCP
        retried = None
        for attempt in (timeout, timeout * 2):
            retried = _tcp_exchange(packet, target, attempt)
            if retried:
                break
        if retried:
            data = retried
        else:
            return {"ok": False, "error": "truncated response and TCP retry failed"}

    header = struct.unpack("!HHHHHH", data[:12])
    if header[0] != identifier:
        return {"ok": False, "error": "response id mismatch"}
    flags, qdcount, ancount = header[1], header[2], header[3]
    if not flags & 0x8000:
        return {"ok": False, "error": "not a response"}
    rcode = flags & 0x000F
    if rcode == 3:
        return {"ok": True, "name": name, "type": rtype.upper(),
                "records": [], "nxdomain": True, "error": ""}
    if rcode != 0:
        return {"ok": False, "error": f"rcode {rcode}"}

    offset = 12
    for _ in range(qdcount):
        _, offset = _decode_name(data, offset)
        offset += 4
    records = []
    for _ in range(ancount):
        _, offset = _decode_name(data, offset)
        if offset + 10 > len(data):
            break
        atype, _aclass, ttl, rdlength = struct.unpack(
            "!HHIH", data[offset:offset + 10])
        offset += 10
        value = _parse_rdata(atype, data, offset, rdlength, data)
        offset += rdlength
        records.append({"type": next((k for k, v in TYPES.items() if v == atype),
                                     str(atype)),
                        "ttl": ttl, "value": value})
    return {"ok": True, "name": name, "type": rtype.upper(),
            "records": records, "error": ""}


def resolve(name: str, types: tuple[str, ...] = ("A", "AAAA", "MX", "NS",
                                                 "TXT", "CNAME"),
            server: str | None = None) -> dict[str, Any]:
    """All chosen record types for one name."""
    value = (name or "").strip().rstrip(".")
    if not value:
        return {"ok": False, "error": "resolve needs a name"}
    grouped: dict[str, list[Any]] = {}
    errors: list[str] = []
    nxdomain = False
    for rtype in types:
        answer = query(value, rtype, server=server)
        if answer.get("nxdomain"):
            nxdomain = True
        if answer.get("ok"):
            values = [r["value"] for r in answer.get("records") or []]
            if values:
                grouped[rtype] = values
        elif answer.get("error"):
            errors.append(f"{rtype}: {answer['error']}")
    return {"ok": True, "name": value, "records": grouped,
            "types_found": sorted(grouped), "nxdomain": nxdomain,
            "errors": errors, "resolver": server or _resolver()}
