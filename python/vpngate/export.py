"""Exporters for Node / Result arrays."""

from __future__ import annotations

import csv
import io
import json
from typing import Any, Iterable, Protocol

from .dat import Node, sort_nodes
from .singbox import build_config

RESULT_KEYS = ("ip", "port", "country", "ok", "egress", "elapsed_ms", "error")
CSV_HEADER = ("ip", "port", "country", "egress", "elapsed_ms", "ok")


class Exporter(Protocol):
    format: str

    def export(self, data: list[Any], **kwargs: Any) -> str: ...


class ExportError(ValueError):
    pass


def is_result_array(data: Iterable[Any]) -> bool:
    for item in data:
        if isinstance(item, dict) and "ok" in item:
            return True
        if hasattr(item, "ok") and not isinstance(item, Node):
            return True
    return False


def _node(item: Any) -> Node:
    return item if isinstance(item, Node) else Node.from_dict(item)


def _result(item: Any) -> dict[str, Any]:
    if isinstance(item, dict):
        return {
            "ip": str(item.get("ip") or ""),
            "port": int(item.get("port") or 0),
            "country": str(item.get("country") or ""),
            "ok": bool(item.get("ok", False)),
            "egress": str(item.get("egress") or ""),
            "elapsed_ms": int(item.get("elapsed_ms") or 0),
            "error": str(item.get("error") or ""),
        }
    return {
        "ip": str(getattr(item, "ip", "")),
        "port": int(getattr(item, "port", 0)),
        "country": str(getattr(item, "country", "")),
        "ok": bool(getattr(item, "ok", False)),
        "egress": str(getattr(item, "egress", "")),
        "elapsed_ms": int(getattr(item, "elapsed_ms", 0)),
        "error": str(getattr(item, "error", "")),
    }


def _results_to_nodes(data: Iterable[Any]) -> list[Node]:
    nodes: list[Node] = []
    for item in data:
        result = _result(item)
        if not result["ok"]:
            continue
        nodes.append(
            Node(
                ip=result["ip"],
                country=result["country"],
                ssl_ports=[result["port"]] if result["port"] else [],
                source="plugin",
            )
        )
    return nodes


def _dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def export_json(data: list[Any]) -> str:
    if is_result_array(data):
        nodes = _results_to_nodes(data)
    else:
        nodes = [_node(item) for item in data]
    payload = [node.to_dict() for node in sort_nodes(nodes)]
    return _dumps(payload) + "\n"


def export_csv(data: list[Any]) -> str:
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(CSV_HEADER)
    if is_result_array(data):
        for item in data:
            result = _result(item)
            writer.writerow(
                [
                    result["ip"],
                    result["port"],
                    result["country"],
                    result["egress"],
                    result["elapsed_ms"],
                    "true" if result["ok"] else "false",
                ]
            )
    else:
        for item in data:
            node = _node(item)
            port = node.ssl_ports[0] if node.ssl_ports else 0
            writer.writerow([node.ip, port, node.country, "", 0, "false"])
    return buffer.getvalue()


def export_plain(data: list[Any]) -> str:
    lines: list[str] = []
    if is_result_array(data):
        for item in data:
            result = _result(item)
            if result["port"]:
                lines.append(f"{result['ip']}:{result['port']}")
    else:
        for item in data:
            node = _node(item)
            if node.ssl_ports:
                lines.append(f"{node.ip}:{node.ssl_ports[0]}")
    return "".join(line + "\n" for line in lines)


def select_singbox(data: list[Any]) -> Node:
    if is_result_array(data):
        usable = [(_result(item), item) for item in data]
        usable = [(r, item) for r, item in usable if r["ok"] and r["port"]]
        if not usable:
            raise ExportError("no successful result to export")
        best = min(usable, key=lambda pair: pair[0]["elapsed_ms"])[1]
        result = _result(best)
        return Node(
            ip=result["ip"],
            country=result["country"],
            ssl_ports=[result["port"]],
            source="plugin",
        )
    nodes = [_node(item) for item in data if _node(item).ssl_ports]
    if not nodes:
        raise ExportError("no node with an SSL port to export")
    return max(nodes, key=lambda node: node.score)


def export_singbox(
    data: list[Any],
    ca: str | Iterable[str],
    cert: str | Iterable[str],
    key: str | Iterable[str],
) -> str:
    node = select_singbox(data)
    config = build_config([node], ca, cert, key, base_port=20000)
    return _dumps(config) + "\n"


class JsonExporter:
    format = "json"

    def export(self, data: list[Any], **kwargs: Any) -> str:
        return export_json(data)


class CsvExporter:
    format = "csv"

    def export(self, data: list[Any], **kwargs: Any) -> str:
        return export_csv(data)


class PlainExporter:
    format = "plain"

    def export(self, data: list[Any], **kwargs: Any) -> str:
        return export_plain(data)


class SingBoxExporter:
    format = "singbox"

    def __init__(
        self,
        ca: str | Iterable[str],
        cert: str | Iterable[str],
        key: str | Iterable[str],
    ) -> None:
        self.ca = ca
        self.cert = cert
        self.key = key

    def export(self, data: list[Any], **kwargs: Any) -> str:
        return export_singbox(data, self.ca, self.cert, self.key)


EXPORTERS: dict[str, type[Exporter]] = {
    "json": JsonExporter,
    "csv": CsvExporter,
    "plain": PlainExporter,
}
