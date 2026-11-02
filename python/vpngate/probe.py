"""Batch probing through a single sing-box process per batch."""

from __future__ import annotations

import concurrent.futures
import glob
import json
import os
import random
import re
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Protocol
from urllib.parse import urlsplit

from .dat import Node, is_ipv4
from .singbox import DEFAULT_BASE_PORT, DEFAULT_BATCH_SIZE, build_config
from .source import normalize_certs

DEFAULT_PROBE_TIMEOUT = 12.0
DEFAULT_STARTUP_TIMEOUT = 15.0
DEFAULT_PROBE_URL = "https://api.ipify.org"
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


class ProbeError(RuntimeError):
    pass


class RetryableProbeError(ProbeError):
    """Tunnel endpoint is not ready yet; worth retrying within budget."""


@dataclass(slots=True)
class Result:
    ip: str
    port: int
    country: str = ""
    ok: bool = False
    egress: str = ""
    elapsed_ms: int = 0
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "port": int(self.port),
            "country": self.country,
            "ok": bool(self.ok),
            "egress": self.egress,
            "elapsed_ms": int(self.elapsed_ms),
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Result":
        return cls(
            ip=str(data.get("ip") or ""),
            port=int(data.get("port") or 0),
            country=str(data.get("country") or ""),
            ok=bool(data.get("ok", False)),
            egress=str(data.get("egress") or ""),
            elapsed_ms=int(data.get("elapsed_ms") or 0),
            error=str(data.get("error") or ""),
        )


class Prober(Protocol):
    def probe(self, nodes: list[Node], ctx: Any = None) -> list[Result]: ...


def find_singbox() -> str | None:
    for env_name in ("VPNGATE_SING_BOX", "SING_BOX"):
        value = os.environ.get(env_name)
        if value and os.path.isfile(value):
            return value
    for name in ("sing-box", "sing-box.exe"):
        found = shutil.which(name)
        if found:
            return found
    roots = [Path.cwd(), Path.cwd().parent, Path(__file__).resolve().parents[2]]
    patterns = (
        "sing-box",
        "sing-box.exe",
        "sing-box-*/sing-box",
        "sing-box-*/sing-box.exe",
        "*/sing-box",
        "*/sing-box.exe",
    )
    for root in roots:
        for pattern in patterns:
            for hit in sorted(glob.glob(str(root / pattern))):
                if os.path.isfile(hit):
                    return hit
    return None


def _free_range(count: int, base_port: int) -> int:
    for candidate in range(base_port, base_port + 1024):
        sockets: list[socket.socket] = []
        try:
            for port in range(candidate, candidate + count):
                if port > 65535:
                    raise OSError("port overflow")
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("127.0.0.1", port))
                sockets.append(sock)
        except OSError:
            continue
        finally:
            for sock in sockets:
                sock.close()
        return candidate
    raise ProbeError("no free local port range for batch")


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise RetryableProbeError("connection closed during SOCKS5 handshake")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _remaining(deadline: float) -> float:
    left = deadline - time.monotonic()
    if left <= 0:
        raise TimeoutError("probe timed out")
    return left


def _decode_http_body(raw: bytes) -> str:
    head, sep, body = raw.partition(b"\r\n\r\n")
    if not sep:
        raise RetryableProbeError("malformed HTTP response")
    header_lines = head.decode("latin-1", "replace").splitlines()
    if not header_lines or " 200 " not in header_lines[0] + " ":
        raise RetryableProbeError(
            f"bad HTTP status: {header_lines[0] if header_lines else '?'}"
        )
    headers: dict[str, str] = {}
    for line in header_lines[1:]:
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()
    if headers.get("transfer-encoding", "").lower() == "chunked":
        out = bytearray()
        pos = 0
        while pos < len(body):
            end = body.find(b"\r\n", pos)
            if end < 0:
                break
            size_line = body[pos:end].split(b";", 1)[0].strip()
            size = int(size_line or b"0", 16)
            pos = end + 2
            if size == 0:
                break
            out += body[pos : pos + size]
            pos += size + 2
        body = bytes(out)
    return body.decode("ascii", "replace").strip()


def socks5_http_get(
    proxy_port: int,
    host: str,
    port: int,
    path: str,
    timeout: float,
) -> str:
    try:
        return _socks5_http_get_once(proxy_port, host, port, path, timeout)
    except ssl.SSLCertVerificationError:
        raise
    except (OSError, EOFError) as exc:
        raise RetryableProbeError(f"{type(exc).__name__}: {exc}") from exc


def _socks5_http_get_once(
    proxy_port: int,
    host: str,
    port: int,
    path: str,
    timeout: float,
) -> str:
    deadline = time.monotonic() + timeout
    host_bytes = host.encode("idna")
    with socket.create_connection(
        ("127.0.0.1", proxy_port), timeout=_remaining(deadline)
    ) as sock:
        sock.settimeout(_remaining(deadline))
        sock.sendall(b"\x05\x01\x00")
        greeting = _recv_exact(sock, 2)
        if greeting[0] != 5:
            raise ProbeError(f"SOCKS5 bad version: {greeting.hex()}")
        if greeting[1] != 0:
            raise ProbeError(f"SOCKS5 method rejected: {greeting.hex()}")

        request = (
            b"\x05\x01\x00\x03"
            + bytes([len(host_bytes)])
            + host_bytes
            + struct.pack(">H", port)
        )
        sock.sendall(request)
        reply = _recv_exact(sock, 4)
        if reply[0] != 5:
            raise ProbeError(f"SOCKS5 bad reply version: {reply.hex()}")
        if reply[1] != 0:
            if reply[1] in (1, 4):
                raise RetryableProbeError(f"SOCKS5 connect failed: code {reply[1]}")
            raise ProbeError(f"SOCKS5 connect failed: code {reply[1]}")
        atyp = reply[3]
        if atyp == 1:
            _recv_exact(sock, 4 + 2)
        elif atyp == 3:
            length = _recv_exact(sock, 1)[0]
            _recv_exact(sock, length + 2)
        elif atyp == 4:
            _recv_exact(sock, 16 + 2)
        else:
            raise ProbeError(f"SOCKS5 bad address type: {atyp}")

        context = ssl.create_default_context()
        with context.wrap_socket(sock, server_hostname=host) as tls:
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "User-Agent: Mozilla/5.0\r\n"
                "Accept: text/plain\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
            tls.settimeout(_remaining(deadline))
            tls.sendall(request)
            chunks: list[bytes] = []
            total = 0
            while total < 65536:
                tls.settimeout(_remaining(deadline))
                chunk = tls.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            return _decode_http_body(b"".join(chunks))


class TCPPreFilter:
    """Cheap TCP reachability filter before spending a sing-box slot."""

    def __init__(self, timeout: float = 3.0, workers: int | None = None) -> None:
        self.timeout = timeout
        self.workers = workers

    @staticmethod
    def _check(ip: str, port: int, timeout: float) -> tuple[bool, str]:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True, ""
        except OSError as exc:
            return False, str(exc)

    @staticmethod
    def _reachable(ip: str, port: int, timeout: float) -> bool:
        return TCPPreFilter._check(ip, port, timeout)[0]

    def filter(self, nodes: list[Node]) -> list[Node]:
        candidates = [node for node in nodes if node.ssl_ports]
        if not candidates:
            return []
        workers = self.workers or min(len(candidates), 64)
        out: list[Node] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [
                pool.submit(self._reachable, node.ip, node.ssl_ports[0], self.timeout)
                for node in candidates
            ]
            for node, future in zip(candidates, futures):
                try:
                    if future.result():
                        out.append(node)
                except Exception:
                    continue
        return out


class SingBoxBatchProber:
    def __init__(
        self,
        batch_size: int = DEFAULT_BATCH_SIZE,
        base_port: int = DEFAULT_BASE_PORT,
        timeout: float = DEFAULT_PROBE_TIMEOUT,
        workers: int | None = None,
        singbox: str | None = None,
        certs: Any = None,
        cert_loader: Callable[[], Any] | None = None,
        startup_timeout: float = DEFAULT_STARTUP_TIMEOUT,
        probe_url: str = DEFAULT_PROBE_URL,
        workdir: str | None = None,
        keep_config: bool = False,
        prefilter: "TCPPreFilter | None" = None,
    ) -> None:
        self.batch_size = max(1, int(batch_size))
        self.base_port = int(base_port)
        self.timeout = float(timeout)
        self.workers = int(workers) if workers else min(self.batch_size, 32)
        self.singbox = singbox
        self._certs_raw = certs
        self._cert_loader = cert_loader
        self.startup_timeout = float(startup_timeout)
        self.probe_url = probe_url
        self.workdir = workdir
        self.keep_config = keep_config
        self.prefilter = prefilter

    def _certs(self) -> tuple[list[str], list[str], list[str]]:
        if self._certs_raw is not None:
            return normalize_certs(self._certs_raw)
        if self._cert_loader is not None:
            self._certs_raw = self._cert_loader()
            return normalize_certs(self._certs_raw)
        from .source import load_certs

        self._certs_raw = load_certs()
        return normalize_certs(self._certs_raw)

    def _binary(self) -> str:
        binary = self.singbox or find_singbox()
        if not binary:
            raise ProbeError(
                "sing-box binary not found (set VPNGATE_SING_BOX or add it to PATH)"
            )
        return binary

    @staticmethod
    def _log_tail(path: str) -> str:
        try:
            with open(path, "rb") as fp:
                fp.seek(0, os.SEEK_END)
                size = fp.tell()
                fp.seek(max(0, size - 4096))
                raw = fp.read()
        except OSError:
            return ""
        text = ANSI_RE.sub("", raw.decode("utf-8", "replace"))
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        errors = [line for line in lines if "ERROR" in line.upper()]
        if errors:
            return errors[-1][:300]
        return lines[-1][:300] if lines else ""

    def _wait_ready(
        self, ports: list[int], proc: subprocess.Popen[Any], deadline: float
    ) -> tuple[bool, str]:
        while time.monotonic() < deadline:
            code = proc.poll()
            if code is not None:
                return False, f"sing-box exited early (code {code})"
            ready = True
            for port in ports:
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.15):
                        pass
                except OSError:
                    ready = False
                    break
            if ready:
                return True, ""
            time.sleep(0.05)
        return False, "sing-box startup timeout"

    def _probe_one(self, node: Node, port: int) -> Result:
        start = time.monotonic()
        url = urlsplit(self.probe_url)
        host = url.hostname or "api.ipify.org"
        target_port = url.port or (443 if url.scheme == "https" else 80)
        path = url.path or "/"
        deadline = start + self.timeout
        last_error: Exception | None = None
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            attempt_timeout = min(3.0, remaining)
            try:
                egress = socks5_http_get(
                    port, host, target_port, path, attempt_timeout
                )
                if not is_ipv4(egress):
                    raise RetryableProbeError(
                        f"non-IPv4 egress: {egress[:64]!r}"
                    )
            except RetryableProbeError as exc:
                last_error = exc
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(0.25 + random.random() * 0.1, remaining))
                continue
            except Exception as exc:
                elapsed = int(round((time.monotonic() - start) * 1000))
                return Result(
                    ip=node.ip,
                    port=node.ssl_ports[0],
                    country=node.country,
                    ok=False,
                    elapsed_ms=elapsed,
                    error=f"{type(exc).__name__}: {exc}",
                )
            elapsed = int(round((time.monotonic() - start) * 1000))
            return Result(
                ip=node.ip,
                port=node.ssl_ports[0],
                country=node.country,
                ok=True,
                egress=egress,
                elapsed_ms=elapsed,
                error="",
            )

        elapsed = int(round((time.monotonic() - start) * 1000))
        message = "timeout"
        if last_error is not None:
            message += f": {type(last_error).__name__}: {last_error}"
        return Result(
            ip=node.ip,
            port=node.ssl_ports[0],
            country=node.country,
            ok=False,
            elapsed_ms=elapsed,
            error=message,
        )

    def _batch(self, nodes: list[Node]) -> list[Result]:
        ca, cert, key = self._certs()
        listen_base = _free_range(len(nodes), self.base_port)
        config = build_config(
            nodes, ca, cert, key, base_port=listen_base, port_offset=0
        )
        ports = [listen_base + i for i in range(len(nodes))]

        def all_failed(message: str) -> list[Result]:
            return [
                Result(
                    ip=node.ip,
                    port=node.ssl_ports[0],
                    country=node.country,
                    ok=False,
                    error=message,
                )
                for node in nodes
            ]

        binary = self._binary()
        workdir = self.workdir or tempfile.gettempdir()
        os.makedirs(workdir, exist_ok=True)
        config_path = os.path.join(workdir, f"vpngate-sb-{os.getpid()}-{id(config)}.json")
        log_path = config_path + ".log"

        with open(config_path, "w", encoding="utf-8") as fp:
            json.dump(config, fp, ensure_ascii=False, separators=(",", ":"))

        proc: subprocess.Popen[Any] | None = None
        log_fp = None
        try:
            log_fp = open(log_path, "wb")
            try:
                proc = subprocess.Popen(
                    [binary, "run", "-c", config_path],
                    stdout=log_fp,
                    stderr=subprocess.STDOUT,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            except OSError as exc:
                return all_failed(f"sing-box start failed: {exc}")

            deadline = time.monotonic() + self.startup_timeout
            ready, reason = self._wait_ready(ports, proc, deadline)
            if not ready:
                tail = ""
                if proc.poll() is not None and log_fp:
                    log_fp.flush()
                    tail = self._log_tail(log_path)
                message = reason + (f": {tail}" if tail else "")
                return all_failed(message)

            results: list[Result | None] = [None] * len(nodes)
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=min(self.workers, len(nodes))
            ) as pool:
                futures = {
                    pool.submit(self._probe_one, node, port): index
                    for index, (node, port) in enumerate(zip(nodes, ports))
                }
                for future in concurrent.futures.as_completed(futures):
                    index = futures[future]
                    try:
                        results[index] = future.result()
                    except Exception as exc:
                        node = nodes[index]
                        results[index] = Result(
                            ip=node.ip,
                            port=node.ssl_ports[0],
                            country=node.country,
                            error=f"{type(exc).__name__}: {exc}",
                        )
            return [result for result in results if result is not None]
        finally:
            if proc is not None:
                try:
                    proc.terminate()
                    proc.wait(timeout=4)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
            if log_fp is not None:
                try:
                    log_fp.close()
                except OSError:
                    pass
            if not self.keep_config:
                for path in (config_path, log_path):
                    try:
                        os.remove(path)
                    except OSError:
                        pass

    def _run_prefilter(
        self,
        pending: list[tuple[int, Node]],
        results: list[Result | None],
    ) -> list[tuple[int, Node]]:
        assert self.prefilter is not None
        survivors: list[tuple[int, Node]] = []
        workers = self.prefilter.workers or min(len(pending), 64)

        def timed(node: Node) -> tuple[bool, str, int]:
            start = time.monotonic()
            ok, error = self.prefilter._check(
                node.ip, node.ssl_ports[0], self.prefilter.timeout
            )
            return ok, error, int(round((time.monotonic() - start) * 1000))

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {}
            for index, node in pending:
                futures[pool.submit(timed, node)] = (index, node)
            checked: list[tuple[int, Node, bool, str, int]] = []
            for future in concurrent.futures.as_completed(futures):
                index, node = futures[future]
                checked.append((index, node, *future.result()))
        for index, node, ok, error, elapsed in checked:
            if ok:
                survivors.append((index, node))
            else:
                results[index] = Result(
                    ip=node.ip,
                    port=node.ssl_ports[0],
                    country=node.country,
                    ok=False,
                    elapsed_ms=elapsed,
                    error=f"prefilter: {error}",
                )
        survivors.sort(key=lambda item: item[0])
        return survivors

    def probe(self, nodes: list[Node], ctx: Any = None) -> list[Result]:
        results: list[Result | None] = [None] * len(nodes)
        pending: list[tuple[int, Node]] = []
        for index, node in enumerate(nodes):
            port = node.ssl_ports[0] if node.ssl_ports else 0
            if not is_ipv4(node.ip):
                results[index] = Result(
                    ip=node.ip,
                    port=port,
                    country=node.country,
                    ok=False,
                    error="invalid IPv4",
                )
            elif not node.ssl_ports:
                results[index] = Result(
                    ip=node.ip,
                    port=0,
                    country=node.country,
                    ok=False,
                    error="no ssl port",
                )
            else:
                pending.append((index, node))

        if self.prefilter is not None and pending:
            pending = self._run_prefilter(pending, results)

        for start in range(0, len(pending), self.batch_size):
            chunk = pending[start : start + self.batch_size]
            chunk_nodes = [node for _, node in chunk]
            try:
                batch_results = self._batch(chunk_nodes)
            except Exception as exc:
                batch_results = [
                    Result(
                        ip=node.ip,
                        port=node.ssl_ports[0],
                        country=node.country,
                        error=f"{type(exc).__name__}: {exc}",
                    )
                    for node in chunk_nodes
                ]
            if len(batch_results) != len(chunk_nodes):
                batch_results = [
                    Result(
                        ip=node.ip,
                        port=node.ssl_ports[0],
                        country=node.country,
                        error="batch returned incomplete results",
                    )
                    for node in chunk_nodes
                ]
            for (index, _node), result in zip(chunk, batch_results):
                results[index] = result

        return [result for result in results if result is not None]
