"""Node sources: VPNGate plugin mirrors and the public CSV API."""

from __future__ import annotations

import base64
import csv
import io
import json
import os
import re
import time
import urllib.request
from pathlib import Path
from typing import Any, Callable, Protocol

from .dat import MAGIC, Node, decode_dat, is_ipv4, normalize_ports

PLUGIN_URL = "http://x{a}.x{a}.client.api.vpngate2.jp/api/"
PLUGIN_MIRRORS = tuple("0123456789abcdefxyz")
CSV_URL = "https://www.vpngate.net/api/iphone/"
UA = "Mozilla/5.0"
REMOTE_RE = re.compile(r"^remote\s+\S+\s+(\d+)", re.MULTILINE)
PEM_TAGS = ("ca", "cert", "key")

HttpGet = Callable[[str, float], bytes]


class SourceError(RuntimeError):
    pass


class CertError(RuntimeError):
    pass


class Source(Protocol):
    def name(self) -> str: ...

    def fetch(self, ctx: Any = None) -> list[Node]: ...


def http_get(url: str, timeout: float = 30.0) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


class PluginSource:
    """Fetch the plugin DAT payload from the first working mirror."""

    def __init__(
        self,
        timeout: float = 30.0,
        get: HttpGet | None = None,
        mirrors: tuple[str, ...] = PLUGIN_MIRRORS,
        now: Callable[[], float] = time.time,
    ) -> None:
        self.timeout = timeout
        self._get = get or http_get
        self.mirrors = mirrors
        self._now = now

    def name(self) -> str:
        return "plugin"

    def fetch(self, ctx: Any = None) -> list[Node]:
        errors: list[str] = []
        for mirror in self.mirrors:
            url = PLUGIN_URL.format(a=mirror)
            try:
                blob = self._get(url, self.timeout)
            except Exception as exc:
                errors.append(f"{url}: {exc}")
                continue
            if not blob.startswith(MAGIC):
                errors.append(f"{url}: bad magic")
                continue
            try:
                nodes, _meta = decode_dat(blob)
            except Exception as exc:
                errors.append(f"{url}: {exc}")
                continue
            seen = int(self._now())
            for node in nodes:
                node.first_seen = seen
                node.last_seen = seen
            return nodes
        raise SourceError("all plugin mirrors failed: " + "; ".join(errors[-3:]))


class CSVSource:
    """Fetch the public CSV API. Malformed rows are skipped, not fatal."""

    def __init__(
        self,
        timeout: float = 30.0,
        get: HttpGet | None = None,
        url: str = CSV_URL,
        now: Callable[[], float] = time.time,
    ) -> None:
        self.timeout = timeout
        self._get = get or http_get
        self.url = url
        self._now = now
        self.ca: list[str] = []
        self.cert: list[str] = []
        self.key: list[str] = []
        self.skipped = 0

    def name(self) -> str:
        return "csv"

    def fetch(self, ctx: Any = None) -> list[Node]:
        raw = self._get(self.url, self.timeout)
        return self.parse(raw.decode("utf-8-sig", "replace"))

    def certs(self) -> tuple[list[str], list[str], list[str]]:
        if not (self.ca and self.cert and self.key):
            raise CertError("CSV source did not yield a complete certificate set")
        return self.ca, self.cert, self.key

    def parse(self, data: str, seen: int | None = None) -> list[Node]:
        self.skipped = 0
        self.ca, self.cert, self.key = [], [], []
        if seen is None:
            seen = int(self._now())
        rows = csv.reader(io.StringIO(data))
        header: list[str] | None = None
        nodes: list[Node] = []

        for row in rows:
            if not row or not any(cell.strip() for cell in row):
                continue
            first = row[0].strip().lstrip("\ufeff")
            if first.startswith("*"):
                continue
            if first.startswith("#"):
                header = [cell.strip().lstrip("#").strip() for cell in row]
                continue
            if header is None:
                continue
            record = dict(zip(header, row))
            node = self._row_to_node(record, seen)
            if node is None:
                self.skipped += 1
                continue
            nodes.append(node)
            if not self.ca:
                ovpn = decode_ovpn_strict(record.get("OpenVPN_ConfigData_Base64", ""))
                extracted = extract_certs(ovpn or "")
                if extracted is not None:
                    self.ca, self.cert, self.key = extracted
        if header is None:
            raise SourceError("CSV response has no header row")
        return nodes

    @staticmethod
    def _row_to_node(record: dict[str, str], seen: int) -> Node | None:
        ip = (record.get("IP") or "").strip()
        if not is_ipv4(ip):
            return None
        ovpn = decode_ovpn_strict(record.get("OpenVPN_ConfigData_Base64", ""))
        if ovpn is None:
            return None
        return Node(
            ip=ip,
            country=(record.get("CountryShort") or "").strip(),
            fqdn=(record.get("Fqdn") or "").strip(),
            hostname=(record.get("HostName") or "").strip(),
            ssl_ports=parse_ovpn_ports(ovpn),
            l2tp=False,
            udp_port=0,
            score=_to_int(record.get("Score")),
            sessions=_to_int(record.get("NumVpnSessions")),
            source="csv",
            first_seen=seen,
            last_seen=seen,
        )


def _to_int(value: Any) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return 0


def decode_ovpn(value: str) -> str:
    decoded = decode_ovpn_strict(value)
    return decoded if decoded is not None else ""


def decode_ovpn_strict(value: str) -> str | None:
    value = (value or "").strip().replace(" ", "")
    if not value:
        return ""
    try:
        blob = base64.b64decode(value + "=" * (-len(value) % 4), validate=False)
    except (ValueError, TypeError):
        return None
    return blob.decode("utf-8", "replace")


def parse_ovpn_port(ovpn: str) -> int:
    ports = parse_ovpn_ports(ovpn)
    return ports[0] if ports else 0


def parse_ovpn_ports(ovpn: str) -> list[int]:
    ports = [int(match.group(1)) for match in REMOTE_RE.finditer(ovpn)]
    return normalize_ports(ports)


def extract_certs(ovpn: str) -> tuple[list[str], list[str], list[str]] | None:
    found: list[list[str]] = []
    for tag in PEM_TAGS:
        match = re.search(rf"<{tag}>(.*?)</{tag}>", ovpn, re.DOTALL | re.IGNORECASE)
        if not match:
            return None
        lines = [line.strip() for line in match.group(1).splitlines() if line.strip()]
        if not lines:
            return None
        found.append(lines)
    return found[0], found[1], found[2]


def normalize_certs(value: Any) -> tuple[list[str], list[str], list[str]]:
    if isinstance(value, dict):
        parts = [value.get(tag) for tag in PEM_TAGS]
    elif isinstance(value, (list, tuple)) and len(value) == 3:
        parts = list(value)
    else:
        raise CertError("certificates must be {ca,cert,key} or a 3-tuple")
    out: list[list[str]] = []
    for part in parts:
        if isinstance(part, str):
            lines = [line.strip() for line in part.splitlines() if line.strip()]
        elif isinstance(part, (list, tuple)):
            lines = [str(line).strip() for line in part if str(line).strip()]
        else:
            raise CertError("certificate entry must be a string or list of lines")
        if not lines:
            raise CertError("certificate entry is empty")
        out.append(lines)
    return out[0], out[1], out[2]


def read_cert_file(path: str | os.PathLike[str]) -> tuple[list[str], list[str], list[str]]:
    try:
        with open(path, "r", encoding="utf-8") as fp:
            value = json.load(fp)
    except OSError as exc:
        raise CertError(f"cannot read cert file {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise CertError(f"invalid cert JSON {path}: {exc}") from exc
    return normalize_certs(value)


def write_cert_file(
    path: str | os.PathLike[str],
    ca: list[str],
    cert: list[str],
    key: list[str],
) -> None:
    payload = {"ca": list(ca), "cert": list(cert), "key": list(key)}
    with open(path, "w", encoding="utf-8") as fp:
        json.dump(payload, fp, ensure_ascii=False, indent=2)
        fp.write("\n")


def load_certs(
    certs_file: str | os.PathLike[str] | None = None,
    node_file: str | os.PathLike[str] | None = None,
    timeout: float = 30.0,
    get: HttpGet | None = None,
) -> tuple[list[str], list[str], list[str]]:
    """Lookup order: --certs, <in>.certs.json, sibling certs.json, CSV API."""
    if certs_file:
        return read_cert_file(certs_file)
    if node_file:
        candidates = [
            str(node_file) + ".certs.json",
            str(Path(node_file).parent / "certs.json"),
        ]
    else:
        candidates = ["certs.json"]
    for candidate in candidates:
        if os.path.isfile(candidate):
            return read_cert_file(candidate)
    source = CSVSource(timeout=timeout, get=get)
    source.fetch()
    return source.certs()
