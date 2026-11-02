"""VPNGate DAT container decoding and SoftEther Pack parsing."""

from __future__ import annotations

import hashlib
import ipaddress
import struct
import zlib
from dataclasses import dataclass
from typing import Any

MAGIC = b"[VPNGate Data File]"
HDR_LEN = 0xF0
SALT_LEN = 0x14
MIN_BLOB_LEN = HDR_LEN + SALT_LEN + 16
MAX_HOSTS = 100000

USED_COLUMNS = (
    "IP",
    "CountryShort",
    "Fqdn",
    "HostName",
    "SslPorts",
    "L2TP",
    "UdpPort",
    "Score",
    "NumClients",
)


class DATError(ValueError):
    """Raised when a DAT blob or Pack payload is malformed."""


@dataclass(slots=True)
class Node:
    ip: str = ""
    country: str = ""
    fqdn: str = ""
    hostname: str = ""
    ssl_ports: list[int] | None = None
    l2tp: bool = False
    udp_port: int = 0
    score: int = 0
    sessions: int = 0
    source: str = "plugin"
    first_seen: int = 0
    last_seen: int = 0

    def __post_init__(self) -> None:
        self.ssl_ports = normalize_ports(self.ssl_ports or [])

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "country": self.country,
            "fqdn": self.fqdn,
            "hostname": self.hostname,
            "ssl_ports": list(self.ssl_ports or []),
            "l2tp": bool(self.l2tp),
            "udp_port": int(self.udp_port),
            "score": int(self.score),
            "sessions": int(self.sessions),
            "source": self.source,
            "first_seen": int(self.first_seen),
            "last_seen": int(self.last_seen),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Node":
        return cls(
            ip=str(data.get("ip") or ""),
            country=str(data.get("country") or ""),
            fqdn=str(data.get("fqdn") or ""),
            hostname=str(data.get("hostname") or ""),
            ssl_ports=data.get("ssl_ports") or [],
            l2tp=bool(data.get("l2tp", False)),
            udp_port=_int(data.get("udp_port")),
            score=_int(data.get("score")),
            sessions=_int(data.get("sessions")),
            source=str(data.get("source") or ""),
            first_seen=_int(data.get("first_seen")),
            last_seen=_int(data.get("last_seen")),
        )


@dataclass(slots=True)
class Meta:
    salt_hex: str
    key_hex: str
    num_hosts: int
    columns: int
    plaintext_len: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "salt_hex": self.salt_hex,
            "key_hex": self.key_hex,
            "num_hosts": self.num_hosts,
            "columns": self.columns,
            "plaintext_len": self.plaintext_len,
        }


@dataclass(slots=True)
class PackItem:
    type: int
    count: int
    values: list[Any]


def _int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _u32(buf: bytes, off: int) -> int:
    return struct.unpack_from(">I", buf, off)[0]


def _u64(buf: bytes, off: int) -> int:
    return struct.unpack_from(">Q", buf, off)[0]


def _need(total: int, off: int, size: int, what: str) -> None:
    if off < 0 or size < 0 or off + size > total:
        raise DATError(f"truncated pack: {what} at offset {off}")


def rc4(key: bytes, data: bytes) -> bytes:
    """RC4 with a preallocated output buffer (no per-byte append)."""
    s = bytearray(range(256))
    klen = len(key)
    if klen == 0:
        raise ValueError("RC4 key must not be empty")
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % klen]) & 0xFF
        s[i], s[j] = s[j], s[i]

    out = bytearray(len(data))
    i = j = 0
    for k, byte in enumerate(data):
        i = (i + 1) & 0xFF
        si = s[i]
        j = (j + si) & 0xFF
        sj = s[j]
        s[i] = sj
        s[j] = si
        out[k] = byte ^ s[(si + sj) & 0xFF]
    return bytes(out)


def parse_pack(buf: bytes, base: int = 0) -> tuple[dict[str, PackItem], int]:
    """Parse a SoftEther Pack and return (items, end_offset)."""
    total = len(buf)
    _need(total, base, 4, "item count")
    item_count = _u32(buf, base)
    off = base + 4
    items: dict[str, PackItem] = {}

    for _ in range(item_count):
        _need(total, off, 4, "name length")
        name_len = _u32(buf, off)
        off += 4
        if name_len < 1:
            raise DATError(f"invalid item name length {name_len}")
        # name_len counts a trailing NUL that is not stored on the wire.
        _need(total, off, name_len - 1, "item name")
        name = buf[off : off + name_len - 1].decode("latin-1", "replace")
        off += name_len - 1

        _need(total, off, 8, f"item header for {name!r}")
        typ = _u32(buf, off)
        count = _u32(buf, off + 4)
        off += 8

        if typ == 0:
            _need(total, off, count * 4, f"u32 values for {name!r}")
            values = list(struct.unpack_from(f">{count}I", buf, off))
            off += count * 4
        elif typ in (1, 2, 3):
            values = []
            for _i in range(count):
                _need(total, off, 4, f"value length for {name!r}")
                size = _u32(buf, off)
                off += 4
                _need(total, off, size, f"value bytes for {name!r}")
                values.append(bytes(buf[off : off + size]))
                off += size
        elif typ == 4:
            _need(total, off, count * 8, f"u64 values for {name!r}")
            values = list(struct.unpack_from(f">{count}Q", buf, off))
            off += count * 8
        else:
            raise DATError(f"unknown pack type {typ} for {name!r}")

        items[name] = PackItem(type=typ, count=count, values=values)

    return items, off


def _looks_zlib(data: bytes) -> bool:
    if len(data) < 2 or data[0] != 0x78:
        return False
    return ((data[0] << 8) | data[1]) % 31 == 0


def _decode_outer_payload(outer: dict[str, PackItem]) -> bytes:
    item = outer.get("data")
    if item is None or not item.values:
        raise DATError("outer pack has no data payload")
    raw = item.values[0]
    if not isinstance(raw, (bytes, bytearray)):
        raise DATError("outer data payload is not binary")

    compressed = 0
    flag = outer.get("compressed")
    if flag is not None and flag.values:
        compressed = _int(flag.values[0])
    if compressed or _looks_zlib(raw):
        try:
            return zlib.decompress(raw)
        except zlib.error as exc:
            raise DATError(f"zlib decompression failed: {exc}") from exc
    return bytes(raw)


def _as_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, (bytes, bytearray)):
        try:
            return int(bytes(value).decode("ascii").strip() or "0")
        except (UnicodeDecodeError, ValueError):
            return 0
    return 0


def text(value: Any) -> str:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace").rstrip("\x00")
    if value is None:
        return ""
    return str(value)


def normalize_ports(ports: Any) -> list[int]:
    out: set[int] = set()
    if ports is None:
        return []
    if isinstance(ports, (str, bytes, bytearray)):
        ports = parse_ssl_ports(text(ports))
    for value in ports:
        try:
            port = int(value)
        except (TypeError, ValueError):
            continue
        if 1 <= port <= 65535:
            out.add(port)
    return sorted(out)


def parse_ssl_ports(value: str) -> list[int]:
    out: set[int] = set()
    for token in value.replace(",", " ").split():
        if token.isdigit():
            port = int(token)
            if 1 <= port <= 65535:
                out.add(port)
    return sorted(out)


def is_ipv4(value: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(value)
    except (ipaddress.AddressValueError, ValueError):
        return False
    return str(addr) == value


def decode_dat(blob: bytes) -> tuple[list[Node], Meta]:
    """Decrypt and parse a VPNGate DAT blob. Returns rows in original order."""
    if not isinstance(blob, (bytes, bytearray, memoryview)):
        raise TypeError("blob must be bytes-like")
    blob = bytes(blob)
    if len(blob) < MIN_BLOB_LEN:
        raise DATError(f"blob too short: {len(blob)} < {MIN_BLOB_LEN}")
    if not blob.startswith(MAGIC):
        raise DATError("not a VPNGate DAT: bad magic")

    salt = blob[HDR_LEN : HDR_LEN + SALT_LEN]
    ciphertext = blob[HDR_LEN + SALT_LEN :]
    key = hashlib.sha1(salt).digest()
    plaintext = rc4(key, ciphertext)

    outer, off = parse_pack(plaintext)
    if off != len(plaintext):
        raise DATError(f"outer pack trailing bytes: {len(plaintext) - off}")

    inner_raw = _decode_outer_payload(outer)
    inner, ioff = parse_pack(inner_raw)
    if ioff != len(inner_raw):
        raise DATError(f"inner pack trailing bytes: {len(inner_raw) - ioff}")

    hosts_item = inner.get("NumHosts")
    if hosts_item is None or not hosts_item.values:
        raise DATError("NumHosts missing")
    num_hosts = _as_int(hosts_item.values[0])
    if num_hosts < 0 or num_hosts > MAX_HOSTS:
        raise DATError(f"NumHosts out of range: {num_hosts}")

    for name, item in inner.items():
        if name == "NumHosts":
            continue
        if name in USED_COLUMNS:
            if item.count != num_hosts:
                raise DATError(
                    f"column {name!r} has {item.count} rows, expected {num_hosts}"
                )
        elif item.count not in (1, num_hosts):
            raise DATError(
                f"column {name!r} has {item.count} rows, expected {num_hosts}"
            )

    columns = sum(1 for item in inner.values() if item.count == num_hosts)

    def col(name: str) -> list[Any]:
        item = inner.get(name)
        if item is None or item.count != num_hosts:
            return []
        return item.values

    ip_col = col("IP")
    if not ip_col:
        raise DATError("IP column missing or empty")

    country_col = col("CountryShort")
    fqdn_col = col("Fqdn")
    host_col = col("HostName")
    ports_col = col("SslPorts")
    l2tp_col = col("L2TP")
    udp_col = col("UdpPort")
    score_col = col("Score")
    sessions_col = col("NumClients")

    nodes: list[Node] = []
    for i in range(num_hosts):
        ip = text(ip_col[i])
        if not is_ipv4(ip):
            continue
        ports_text = text(ports_col[i]) if ports_col else ""
        nodes.append(
            Node(
                ip=ip,
                country=text(country_col[i]) if country_col else "",
                fqdn=text(fqdn_col[i]) if fqdn_col else "",
                hostname=text(host_col[i]) if host_col else "",
                ssl_ports=parse_ssl_ports(ports_text),
                l2tp=bool(_int(l2tp_col[i])) if l2tp_col else False,
                udp_port=_int(udp_col[i]) if udp_col else 0,
                score=_int(score_col[i]) if score_col else 0,
                sessions=_int(sessions_col[i]) if sessions_col else 0,
                source="plugin",
                first_seen=0,
                last_seen=0,
            )
        )

    meta = Meta(
        salt_hex=salt.hex(),
        key_hex=key.hex(),
        num_hosts=num_hosts,
        columns=columns,
        plaintext_len=len(plaintext),
    )
    return nodes, meta


def sort_nodes(nodes: list[Node]) -> list[Node]:
    """Stable sort by IP string; duplicate rows keep their original order."""
    return sorted(nodes, key=lambda node: node.ip)
