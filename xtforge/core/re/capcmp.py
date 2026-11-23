"""Compare two network captures, and correlate what a binary says against what it did.

`re netcap` inspects one capture: flows, protocols, HTTP requests. That answers "what is in
this capture". The questions that matter are comparative and correlative:

  * what did the app start talking to that it was not talking to before — a new endpoint is
    the highest-signal finding in a release diff, and it is invisible in a single capture;
  * what hosts and ports does the binary reference statically, and which of them actually
    appear at runtime — a hardcoded C2 host that never fires is a dormant capability, and one
    that fires without appearing in strings is obfuscated;
  * what does the binary contain that the capture never shows, and vice versa.

Both directions matter. Static-only analysis over-reports (an embedded URL in a help string
is not a live endpoint) and runtime-only analysis under-reports (a host resolved at runtime
from an encrypted config leaves no string). Reporting the mismatches is the product.

The comparison is deliberately at the level of *endpoints* — host plus port — rather than
packets. Packet counts change with retransmits and MTU; an endpoint appearing or disappearing
is a behavioural fact.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .runtimes import inspect_netcap

# Endpoints worth extracting from a binary. `scheme://host[:port]` is the unambiguous form;
# a bare `host:port` is accepted only when the host has a dot and the port is numeric, since
# otherwise every `key: value` pair in a binary looks like an endpoint.
_URL_RE = re.compile(rb"(?:https?|wss?|ftp)://([A-Za-z0-9._\-]{3,253}?)(?::(\d{1,5}))?[/\s\"'<>]")
_HOSTPORT_RE = re.compile(rb"\b((?:[A-Za-z0-9\-]{1,63}\.){1,10}[A-Za-z]{2,24}):(\d{2,5})\b")
# A bare hostname with a real TLD, used only for the "host referenced at all" set.
_HOST_RE = re.compile(rb"\b((?:[A-Za-z0-9\-]{1,63}\.){1,10}(?:com|net|org|io|api|dev|cloud|"
                      rb"app|co|gov|edu|ru|cn|info|xyz|top|site|online))\b")

_DEFAULT_PORTS = {b"http": 80, b"https": 443, b"ws": 80, b"wss": 443, b"ftp": 21}

MAX_SCAN_BYTES = 96 * 1024 * 1024


def _static_endpoints(path: Path) -> dict[str, Any]:
    """Host:port pairs the binary references, plus bare hosts seen without a port."""
    try:
        data = path.read_bytes()[:MAX_SCAN_BYTES]
    except OSError:
        return {"endpoints": set(), "hosts": set(), "error": "unreadable"}

    endpoints: set[str] = set()
    hosts: set[str] = set()

    for match in _URL_RE.finditer(data):
        host = match.group(1).decode("ascii", "ignore").lower()
        scheme_match = re.search(rb"^(https?|wss?|ftp)://", match.group(0))
        scheme = scheme_match.group(1).lower() if scheme_match else b"https"
        port = match.group(2)
        endpoint = f"{host}:{int(port) if port else _DEFAULT_PORTS.get(scheme, 443)}"
        endpoints.add(endpoint)
        hosts.add(host)

    for match in _HOSTPORT_RE.finditer(data):
        host = match.group(1).decode("ascii", "ignore").lower()
        port = int(match.group(2))
        if 0 < port < 65536:
            endpoints.add(f"{host}:{port}")
            hosts.add(host)

    for match in _HOST_RE.finditer(data):
        hosts.add(match.group(1).decode("ascii", "ignore").lower())

    return {"endpoints": endpoints, "hosts": hosts, "error": None}


def _decode_dns_name(data: bytes, offset: int, depth: int = 0) -> tuple[str, int] | None:
    """Decode a DNS name with compression pointers. Returns (name, next_offset)."""
    if depth > 8 or offset >= len(data):
        return None
    labels: list[str] = []
    cursor = offset
    # `next_offset` must end up *past the terminator*, not past the first label. Recording it
    # after the first label made the caller resume inside the name, so the question's
    # qtype/qclass were read from the wrong place and every answer decode failed — the DNS map
    # came back empty on a capture that plainly contained valid answers.
    next_offset: int | None = None
    while cursor < len(data):
        length = data[cursor]
        if length == 0:
            return ".".join(labels).lower(), cursor + 1
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(data):
                return None
            pointer = ((length & 0x3F) << 8) | data[cursor + 1]
            if next_offset is None:
                next_offset = cursor + 2
            target = _decode_dns_name(data, pointer, depth + 1)
            if target is None:
                return None
            if target[0]:
                labels.append(target[0])
            return ".".join(labels).lower(), next_offset
        if length > 63 or cursor + 1 + length > len(data):
            return None
        labels.append(data[cursor + 1:cursor + 1 + length].decode("ascii", "ignore"))
        cursor += 1 + length
    return None


def _dns_map(path: Path) -> dict[str, str]:
    """Resolve IP -> hostname from DNS answers in the capture.

    This exists because the two sides of a static/runtime comparison are written in different
    alphabets: a capture records *IP addresses* in its flows, while a binary records
    *hostnames* in its strings. Comparing them directly produced a correlation of 0% on a
    fixture where the app and the capture agreed about everything — the hosts simply never
    lined up. Parsing the DNS answers in the same capture gives the mapping.

    A capture with no DNS traffic (common: resolution happens before capture starts) yields an
    empty map, and the correlation then honestly reports that it could not compare by name.
    """
    try:
        data = path.read_bytes()[:MAX_SCAN_BYTES]
    except OSError:
        return {}
    mapping: dict[str, str] = {}

    # pcap: 24-byte global header, then 16-byte records with a link-layer frame.
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        little = magic == b"\xd4\xc3\xb2\xa1"
        endian = "<" if little else ">"
        cursor = 24
        while cursor + 16 <= len(data):
            incl_len = int.from_bytes(data[cursor + 8:cursor + 12],
                                      "little" if little else "big")
            frame = data[cursor + 16:cursor + 16 + incl_len]
            cursor += 16 + incl_len
            _dns_from_frame(frame, mapping)
    return mapping


def _dns_from_frame(frame: bytes, mapping: dict[str, str]) -> None:
    """Pull A-record answers out of one Ethernet/IPv4/UDP frame."""
    if len(frame) < 42:
        return
    ethertype = frame[12:14]
    if ethertype != b"\x08\x00":
        return  # IPv4 only; VLAN-tagged frames are skipped rather than guessed at
    ip_start = 14
    if len(frame) < ip_start + 20:
        return
    ihl = (frame[ip_start] & 0x0F) * 4
    if frame[ip_start + 9] != 17:
        return  # not UDP
    udp_start = ip_start + ihl
    if len(frame) < udp_start + 8:
        return
    dns = frame[udp_start + 8:]
    if len(dns) < 12:
        return
    try:
        qdcount = int.from_bytes(dns[4:6], "big")
        ancount = int.from_bytes(dns[6:8], "big")
    except (ValueError, IndexError):
        return
    if not ancount or ancount > 200:
        return
    cursor = 12
    for _ in range(qdcount):
        decoded = _decode_dns_name(dns, cursor)
        if decoded is None:
            return
        _, cursor = decoded
        cursor += 4  # qtype + qclass
    for _ in range(ancount):
        decoded = _decode_dns_name(dns, cursor)
        if decoded is None:
            return
        name, cursor = decoded
        if cursor + 10 > len(dns):
            return
        rtype = int.from_bytes(dns[cursor:cursor + 2], "big")
        rdlength = int.from_bytes(dns[cursor + 8:cursor + 10], "big")
        cursor += 10
        if rtype == 1 and rdlength == 4 and cursor + 4 <= len(dns):  # A record
            address = ".".join(str(byte) for byte in dns[cursor:cursor + 4])
            mapping[address] = name
        cursor += rdlength


def _runtime_endpoints(path: Path) -> dict[str, Any]:
    """Endpoints observed in a capture, from its flows."""
    report = inspect_netcap(path, limit=100000)
    if not report.get("ok"):
        return {"endpoints": set(), "hosts": set(),
                "error": report.get("error") or "capture could not be read"}
    endpoints: set[str] = set()
    hosts: set[str] = set()
    for flow in report.get("flows") or []:
        host = (flow.get("dst") or "").lower()
        port = flow.get("dst_port")
        if not host:
            continue
        hosts.add(host)
        if isinstance(port, int):
            endpoints.add(f"{host}:{port}")
    # Flows carry IPs; binaries carry names. Resolve through the capture's own DNS answers so
    # the two sides can be compared, and keep the IP-based endpoints as well so an
    # unresolved flow is still reported rather than dropped.
    dns = _dns_map(path)
    for address, name in dns.items():
        hosts.add(name)
    for endpoint in list(endpoints):
        host, _, port = endpoint.rpartition(":")
        resolved = dns.get(host)
        if resolved:
            endpoints.add(f"{resolved}:{port}")
    return {
        "endpoints": endpoints,
        "hosts": hosts,
        "dns_map": dns,
        "error": None,
        "packet_count": report.get("packet_count"),
        "flow_count": report.get("flow_count"),
        "protocols": report.get("protocols"),
        "http_requests": report.get("http_requests") or [],
    }


def compare_captures(path_a: str | Path, path_b: str | Path) -> dict[str, Any]:
    """Diff two captures at endpoint level.

    Reports endpoints and hosts that appeared, disappeared, and are common — plus the HTTP
    request paths, because `/api/v1/` becoming `/api/v2/` is a contract change that endpoint
    comparison alone would miss when host and port are unchanged.
    """
    a, b = Path(path_a), Path(path_b)
    for candidate in (a, b):
        if not candidate.is_file():
            return {"ok": False, "error": f"not a file: {candidate}"}

    left = _runtime_endpoints(a)
    right = _runtime_endpoints(b)
    for label, side in (("a", left), ("b", right)):
        if side["error"]:
            return {"ok": False, "error": f"capture {label}: {side['error']}",
                    "capture_a": str(a), "capture_b": str(b)}

    def leaves(requests: list[dict[str, Any]]) -> set[str]:
        out: set[str] = set()
        for request in requests:
            target = request.get("target") or request.get("path") or request.get("url")
            if target:
                out.add(str(target).split("?")[0])
        return out

    paths_a, paths_b = leaves(left["http_requests"]), leaves(right["http_requests"])
    added = sorted(right["endpoints"] - left["endpoints"])
    removed = sorted(left["endpoints"] - right["endpoints"])
    return {
        "ok": True,
        "capture_a": str(a),
        "capture_b": str(b),
        "endpoints_a": len(left["endpoints"]),
        "endpoints_b": len(right["endpoints"]),
        "added_endpoints": added,
        "removed_endpoints": removed,
        "common_endpoints": sorted(left["endpoints"] & right["endpoints"]),
        "added_hosts": sorted(right["hosts"] - left["hosts"]),
        "removed_hosts": sorted(left["hosts"] - right["hosts"]),
        "added_paths": sorted(paths_b - paths_a),
        "removed_paths": sorted(paths_a - paths_b),
        "changed": bool(added or removed or (paths_b - paths_a) or (paths_a - paths_b)),
        "packets_a": left.get("packet_count"),
        "packets_b": right.get("packet_count"),
        "protocols_a": left.get("protocols"),
        "protocols_b": right.get("protocols"),
        "note": ("Comparison is at endpoint (host:port) level, not packet level: packet "
                 "counts move with retransmits and MTU, while an endpoint appearing or "
                 "disappearing is a behavioural change."),
    }


def correlate_static_runtime(binary: str | Path, capture: str | Path) -> dict[str, Any]:
    """Compare the endpoints a binary references against the ones it was observed using.

    Four outcomes, all reported because all four are findings:

      * `in_both` — referenced and used. The expected case.
      * `static_only` — referenced but never observed. A dormant endpoint, dead code, or a
        feature that did not run in this capture.
      * `runtime_only` — observed but not present as a string. Constructed at runtime, which
        is the signature of obfuscation, encrypted config, or DNS-based discovery.
      * `new_in_runtime` — the runtime host is not in the binary's host set at all.

    Correlation is by host first, port second. Requiring the port to match would put nearly
    everything in `static_only`, because a URL in a binary rarely spells out 443.
    """
    bin_path = Path(binary)
    cap_path = Path(capture)
    if not bin_path.is_file():
        return {"ok": False, "error": f"not a file: {bin_path}"}
    if not cap_path.is_file():
        return {"ok": False, "error": f"not a file: {cap_path}"}

    static = _static_endpoints(bin_path)
    if static["error"]:
        return {"ok": False, "error": f"binary: {static['error']}"}
    runtime = _runtime_endpoints(cap_path)
    if runtime["error"]:
        return {"ok": False, "error": f"capture: {runtime['error']}"}

    static_hosts = static["hosts"]
    # Drop IP literals that we successfully resolved to a name: reporting
    # `93.184.216.34` as "runtime-only" next to `api.example.com` in `in_both` counts the same
    # flow twice and makes the list look far more alarming than the evidence supports. An
    # unresolved IP is kept, because then we genuinely do not know what it was.
    dns_map = runtime.get("dns_map") or {}
    runtime_hosts = {host for host in runtime["hosts"] if host not in dns_map}
    resolved = set(dns_map.values())
    runtime_hosts |= resolved
    in_both = sorted(static_hosts & runtime_hosts)
    static_only = sorted(static_hosts - runtime_hosts)
    runtime_only = sorted(runtime_hosts - static_hosts)

    static_ports = {endpoint.rsplit(":", 1)[0]: int(endpoint.rsplit(":", 1)[1])
                    for endpoint in static["endpoints"]}
    port_mismatches = []
    for endpoint in sorted(runtime["endpoints"]):
        host, _, port = endpoint.rpartition(":")
        expected = static_ports.get(host)
        if expected is not None and str(expected) != port:
            port_mismatches.append({"host": host, "static_port": expected,
                                    "observed_port": int(port)})

    total = len(static_hosts | runtime_hosts)
    return {
        "ok": True,
        "binary": str(bin_path),
        "capture": str(cap_path),
        "static_endpoints": len(static["endpoints"]),
        "static_hosts": len(static_hosts),
        "runtime_endpoints": len(runtime["endpoints"]),
        "runtime_hosts": len(runtime_hosts),
        "in_both": in_both[:200],
        "static_only": static_only[:200],
        "runtime_only": runtime_only[:200],
        "static_only_count": len(static_only),
        "runtime_only_count": len(runtime_only),
        "port_mismatches": port_mismatches[:50],
        "correlation_pct": round(len(in_both) / total * 100.0, 1) if total else 0.0,
        "note": ("Correlation is by host, then port. A host present only in `static_only` is "
                 "a dormant or dead reference; a host present only in `runtime_only` was "
                 "constructed at runtime and is worth investigating. Neither list is a bug "
                 "report on its own — a capture is one sample, not exhaustive."),
    }


def inspect(path: str | Path, **kwargs: Any) -> dict[str, Any]:
    return compare_captures(path, **kwargs)
