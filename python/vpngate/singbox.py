"""sing-box batch configuration generation."""

from __future__ import annotations

from typing import Any, Iterable

from .dat import Node, is_ipv4

DEFAULT_BASE_PORT = 20000
DEFAULT_BATCH_SIZE = 32
DATA_CIPHERS = ["AES-128-CBC"]
AUTH = "SHA1"
USERNAME = "vpn"
PASSWORD = "vpn"


class ConfigError(ValueError):
    pass


def pem_lines(value: str | Iterable[str]) -> list[str]:
    if isinstance(value, str):
        lines = value.splitlines()
    else:
        lines = list(value)
    return [line.strip() for line in lines if line and line.strip()]


def normalize_cert_triplet(
    ca: str | Iterable[str],
    cert: str | Iterable[str],
    key: str | Iterable[str],
) -> tuple[list[str], list[str], list[str]]:
    triplet = (pem_lines(ca), pem_lines(cert), pem_lines(key))
    if not all(triplet):
        raise ConfigError("ca/cert/key must all be non-empty")
    return triplet


def build_endpoint(
    node: Node,
    tag: str,
    ca: list[str],
    cert: list[str],
    key: list[str],
) -> dict[str, Any]:
    if not node.ssl_ports:
        raise ConfigError(f"node {node.ip} has no SSL port")
    if not is_ipv4(node.ip):
        raise ConfigError(f"node {node.ip} has an invalid IPv4 address")
    return {
        "type": "openvpn-client",
        "tag": tag,
        "server": node.ip,
        "server_port": int(node.ssl_ports[0]),
        "network": "tcp",
        "system": False,
        "username": USERNAME,
        "password": PASSWORD,
        "tls": {
            "certificate": ca,
            "client_certificate": cert,
            "client_key": key,
            "remote_certificate_tls": "none",
        },
        "data_ciphers": list(DATA_CIPHERS),
        "auth": AUTH,
        "route_no_pull": True,
        "ping_restart_disabled": True,
    }


def build_config(
    nodes: list[Node],
    ca: str | Iterable[str],
    cert: str | Iterable[str],
    key: str | Iterable[str],
    base_port: int = DEFAULT_BASE_PORT,
    port_offset: int = 0,
    tag_offset: int = 0,
) -> dict[str, Any]:
    """One sing-box process config carrying len(nodes) endpoints/inbounds."""
    ca_lines, cert_lines, key_lines = normalize_cert_triplet(ca, cert, key)
    inbounds: list[dict[str, Any]] = []
    endpoints: list[dict[str, Any]] = []
    rules: list[dict[str, Any]] = []

    for i, node in enumerate(nodes):
        ep_tag = f"ep{tag_offset + i}"
        in_tag = f"in{tag_offset + i}"
        listen_port = int(base_port) + int(port_offset) + i
        if not 1 <= listen_port <= 65535:
            raise ConfigError(f"listen port out of range: {listen_port}")
        inbounds.append(
            {
                "type": "mixed",
                "tag": in_tag,
                "listen": "127.0.0.1",
                "listen_port": listen_port,
            }
        )
        endpoints.append(build_endpoint(node, ep_tag, ca_lines, cert_lines, key_lines))
        rules.append({"inbound": in_tag, "outbound": ep_tag})

    return {
        "log": {"level": "error"},
        "inbounds": inbounds,
        "endpoints": endpoints,
        "route": {"rules": rules},
    }


def batch_configs(
    nodes: list[Node],
    ca: str | Iterable[str],
    cert: str | Iterable[str],
    key: str | Iterable[str],
    batch_size: int = DEFAULT_BATCH_SIZE,
    base_port: int = DEFAULT_BASE_PORT,
) -> list[dict[str, Any]]:
    """Generate one config per batch; ports stay unique across the whole run."""
    if batch_size < 1:
        raise ConfigError("batch_size must be >= 1")
    configs: list[dict[str, Any]] = []
    for start in range(0, len(nodes), batch_size):
        chunk = nodes[start : start + batch_size]
        configs.append(
            build_config(
                chunk,
                ca,
                cert,
                key,
                base_port=base_port,
                port_offset=start,
                tag_offset=0,
            )
        )
    return configs
