"""Command line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

from .dat import Node, decode_dat, sort_nodes
from .export import (
    ExportError,
    export_csv,
    export_json,
    export_plain,
    export_singbox,
)
from .merge import merge
from .probe import SingBoxBatchProber, TCPPreFilter
from .singbox import batch_configs
from .source import (
    CSVSource,
    PluginSource,
    load_certs,
    write_cert_file,
)

VERSION = "1.0.0"


def _non_empty_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid integer: {value}") from exc
    if number < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return number


def _positive_float(value: str) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid number: {value}") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError("must be > 0")
    return number


def _non_negative_float(value: str) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid number: {value}") from exc
    if number < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return number


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vpngate")
    sub = parser.add_subparsers(dest="command", required=True)

    harvest = sub.add_parser("harvest", help="fetch nodes")
    harvest.add_argument("--source", choices=("plugin", "csv", "both"), default="both")
    harvest.add_argument("--polls", type=_non_empty_int, default=1)
    harvest.add_argument("--interval", type=_non_negative_float, default=60.0)
    harvest.add_argument("--timeout", type=_positive_float, default=30.0)
    harvest.add_argument("--out")
    harvest.add_argument("--state")
    harvest.set_defaults(func=cmd_harvest)

    generate = sub.add_parser("generate", help="write batched sing-box configs")
    generate.add_argument("--in", dest="infile")
    generate.add_argument("--certs")
    generate.add_argument("--batch", type=_non_empty_int, default=32)
    generate.add_argument("--base-port", type=_non_empty_int, default=20000)
    generate.add_argument("--out", default="singbox")
    generate.set_defaults(func=cmd_generate)

    probe = sub.add_parser("probe", help="batch probe nodes")
    probe.add_argument("--in", dest="infile")
    probe.add_argument("--certs")
    probe.add_argument("--batch", type=_non_empty_int, default=32)
    probe.add_argument("--timeout", type=_positive_float, default=12.0)
    probe.add_argument("--workers", type=_non_empty_int)
    probe.add_argument("--prefilter", action="store_true")
    probe.add_argument("--out")
    probe.add_argument("--usable")
    probe.set_defaults(func=cmd_probe)

    export = sub.add_parser("export", help="convert node/result JSON")
    export.add_argument("--in", dest="infile")
    export.add_argument("--format", choices=("json", "csv", "plain", "singbox"), default="json")
    export.add_argument("--certs")
    export.add_argument("--out")
    export.set_defaults(func=cmd_export)

    decode = sub.add_parser("decode", help="decode a local VPNGate DAT")
    decode.add_argument("--in", dest="infile", required=True)
    decode.add_argument("--out")
    decode.set_defaults(func=cmd_decode)

    version = sub.add_parser("version", help="print version")
    version.set_defaults(func=cmd_version)
    return parser


def _read_bytes(path: str) -> bytes:
    try:
        with open(path, "rb") as fp:
            return fp.read()
    except OSError as exc:
        raise RuntimeError(f"cannot read {path}: {exc}") from exc


def _read_json(path: str | None) -> Any:
    try:
        if path:
            with open(path, "r", encoding="utf-8") as fp:
                return json.load(fp)
        return json.load(sys.stdin)
    except OSError as exc:
        raise RuntimeError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"invalid JSON in {path or 'stdin'}: {exc}") from exc


def _read_nodes(path: str | None) -> list[Node]:
    data = _read_json(path)
    if not isinstance(data, list):
        raise RuntimeError("expected a JSON array of nodes")
    return [Node.from_dict(item) for item in data if isinstance(item, dict)]


def _write_text(text: str, path: str | None) -> None:
    if path:
        with open(path, "wb") as fp:
            fp.write(text.encode("utf-8"))
    else:
        sys.stdout.write(text)


def _write_json(value: Any, path: str | None, pretty: bool = False) -> None:
    if pretty:
        text = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    else:
        text = json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n"
    _write_text(text, path)


def _stamp(nodes: list[Node], now: int) -> None:
    for node in nodes:
        if not node.first_seen:
            node.first_seen = now
        node.last_seen = now


def _write_state(path: str | None, nodes: list[Node]) -> None:
    if path:
        _write_text(export_json(sort_nodes(nodes)), path)


def cmd_version(args: argparse.Namespace) -> int:
    print(f"vpngate {VERSION}")
    return 0


def cmd_decode(args: argparse.Namespace) -> int:
    nodes, meta = decode_dat(_read_bytes(args.infile))
    order = sort_nodes(nodes)
    _write_text(export_json(order), args.out)
    print(
        f"salt={meta.salt_hex} key={meta.key_hex} hosts={meta.num_hosts} "
        f"columns={meta.columns} plaintext={meta.plaintext_len}",
        file=sys.stderr,
    )
    return 0


def cmd_harvest(args: argparse.Namespace) -> int:
    sources: list[Any] = []
    if args.source in ("plugin", "both"):
        sources.append(PluginSource(timeout=args.timeout))
    if args.source in ("csv", "both"):
        sources.append(CSVSource(timeout=args.timeout))

    accumulated: list[Node] = []
    if args.state and os.path.isfile(args.state):
        accumulated = _read_nodes(args.state)

    certs: tuple[list[str], list[str], list[str]] | None = None
    last_error = ""
    fetched = 0

    for poll in range(args.polls):
        poll_nodes: list[Node] = []
        for source in sources:
            try:
                nodes = source.fetch()
            except Exception as exc:
                last_error = f"{source.name()}: {exc}"
                continue
            fetched += len(nodes)
            if isinstance(source, CSVSource) and source.ca and source.cert and source.key:
                certs = (source.ca, source.cert, source.key)
            _stamp(nodes, int(time.time()))
            poll_nodes.extend(nodes)
        if poll_nodes:
            accumulated = merge(accumulated + poll_nodes)
            _write_state(args.state, accumulated)
            print(
                f"poll {poll + 1}/{args.polls}: +{len(poll_nodes)} nodes, "
                f"total {len(accumulated)}",
                file=sys.stderr,
            )
        elif not accumulated:
            print(f"poll {poll + 1}/{args.polls}: no nodes ({last_error})", file=sys.stderr)
        if poll + 1 < args.polls:
            time.sleep(args.interval)

    if not accumulated:
        raise RuntimeError(f"no nodes harvested: {last_error or 'empty result'}")

    if args.out:
        if certs is None:
            extra = CSVSource(timeout=args.timeout)
            try:
                extra.fetch()
                certs = extra.certs()
            except Exception as exc:
                print(
                    f"warning: harvest could not obtain certificates: {exc}",
                    file=sys.stderr,
                )
        _write_text(export_json(accumulated), args.out)
    else:
        _write_text(export_json(accumulated), None)

    target = args.out or args.state
    if target and certs is not None:
        write_cert_file(target + ".certs.json", *certs)

    print(f"harvested {len(accumulated)} nodes from {fetched} records", file=sys.stderr)
    return 0


def cmd_generate(args: argparse.Namespace) -> int:
    nodes = [node for node in _read_nodes(args.infile) if node.ssl_ports]
    if not nodes:
        raise RuntimeError("no nodes with SSL ports")
    ca, cert, key = load_certs(args.certs, args.infile, timeout=30.0)
    configs = batch_configs(
        nodes, ca, cert, key, batch_size=args.batch, base_port=args.base_port
    )
    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    for index, config in enumerate(configs):
        path = outdir / f"singbox-batch-{index}.json"
        _write_json(config, str(path))
    print(
        f"wrote {len(configs)} config(s) with {len(nodes)} nodes -> {outdir}",
        file=sys.stderr,
    )
    return 0


def cmd_probe(args: argparse.Namespace) -> int:
    data = _read_json(args.infile)
    if not isinstance(data, list):
        raise RuntimeError("expected a JSON array of nodes")
    if any(isinstance(item, dict) and "ok" in item for item in data):
        raise RuntimeError("probe: input must be a Node array")
    nodes = [Node.from_dict(item) for item in data if isinstance(item, dict)]
    ca, cert, key = load_certs(args.certs, args.infile, timeout=args.timeout)
    prober = SingBoxBatchProber(
        batch_size=args.batch,
        timeout=args.timeout,
        workers=args.workers,
        certs=(ca, cert, key),
        prefilter=(
            TCPPreFilter(timeout=min(args.timeout, 5.0)) if args.prefilter else None
        ),
    )
    results = prober.probe(nodes)
    payload = [result.to_dict() for result in results]
    _write_json(payload, args.out)

    usable = [result for result in results if result.ok]
    if args.usable:
        usable_nodes = []
        for node, result in zip(nodes, results):
            if result.ok:
                promoted = Node.from_dict(node.to_dict())
                promoted.ssl_ports = [result.port]
                usable_nodes.append(promoted)
        _write_text(export_json(usable_nodes), args.usable)
    print(
        f"probed {len(results)} nodes, {len(usable)} usable",
        file=sys.stderr,
    )
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    data = _read_json(args.infile)
    if not isinstance(data, list):
        raise RuntimeError("expected a JSON array")
    if args.format == "json":
        text = export_json(data)
    elif args.format == "csv":
        text = export_csv(data)
    elif args.format == "plain":
        text = export_plain(data)
    elif args.format == "singbox":
        ca, cert, key = load_certs(args.certs, args.infile, timeout=30.0)
        text = export_singbox(data, ca, cert, key)
    else:
        raise ExportError(f"unknown format: {args.format}")
    _write_text(text, args.out)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"vpngate: error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
