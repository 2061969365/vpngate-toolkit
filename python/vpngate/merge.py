"""Node merging rules."""

from __future__ import annotations

from .dat import Node, is_ipv4, normalize_ports


def merge(nodes: list[Node]) -> list[Node]:
    """Deduplicate by IP; same-source duplicates keep that source."""
    merged: dict[str, Node] = {}
    has_plugin: dict[str, bool] = {}
    has_csv: dict[str, bool] = {}
    fallback: dict[str, str] = {}

    for raw in nodes:
        if not is_ipv4(raw.ip):
            continue
        node = merged.get(raw.ip)
        if node is None:
            node = Node(
                ip=raw.ip,
                ssl_ports=[],
                first_seen=raw.first_seen,
                last_seen=raw.last_seen,
            )
            merged[raw.ip] = node

        if not node.country:
            node.country = raw.country
        if not node.fqdn:
            node.fqdn = raw.fqdn
        if not node.hostname:
            node.hostname = raw.hostname
        node.l2tp = node.l2tp or raw.l2tp
        if not node.udp_port and raw.udp_port:
            node.udp_port = raw.udp_port
        node.score = max(node.score, raw.score)
        node.sessions = max(node.sessions, raw.sessions)
        node.ssl_ports = normalize_ports((node.ssl_ports or []) + (raw.ssl_ports or []))
        node.first_seen = min(node.first_seen, raw.first_seen)
        node.last_seen = max(node.last_seen, raw.last_seen)

        source = raw.source
        if source == "plugin":
            has_plugin[raw.ip] = True
        elif source == "csv":
            has_csv[raw.ip] = True
        elif source == "both":
            has_plugin[raw.ip] = True
            has_csv[raw.ip] = True
        if raw.ip not in fallback and source:
            fallback[raw.ip] = source

    for ip, node in merged.items():
        if has_plugin.get(ip) and has_csv.get(ip):
            node.source = "both"
        elif has_plugin.get(ip):
            node.source = "plugin"
        elif has_csv.get(ip):
            node.source = "csv"
        else:
            node.source = fallback.get(ip, "")

    return sorted(merged.values(), key=lambda item: item.ip)
