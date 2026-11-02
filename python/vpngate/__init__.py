"""VPNGate toolkit: DAT decoding, harvesting, sing-box config and probing."""

from __future__ import annotations

from .dat import (
    DATError,
    Meta,
    Node,
    PackItem,
    decode_dat,
    is_ipv4,
    normalize_ports,
    parse_pack,
    parse_ssl_ports,
    rc4,
    sort_nodes,
)
from .export import (
    CsvExporter,
    Exporter,
    JsonExporter,
    PlainExporter,
    SingBoxExporter,
    export_csv,
    export_json,
    export_plain,
    export_singbox,
)
from .merge import merge
from .probe import Prober, Result, SingBoxBatchProber, TCPPreFilter, find_singbox
from .singbox import batch_configs, build_config
from .source import (
    CertError,
    CSVSource,
    PluginSource,
    Source,
    load_certs,
    normalize_certs,
)

__version__ = "1.0.0"

__all__ = [
    "CsvExporter",
    "CSVSource",
    "CertError",
    "DATError",
    "Exporter",
    "JsonExporter",
    "Meta",
    "Node",
    "PackItem",
    "PlainExporter",
    "PluginSource",
    "Prober",
    "Result",
    "SingBoxBatchProber",
    "SingBoxExporter",
    "Source",
    "TCPPreFilter",
    "__version__",
    "batch_configs",
    "build_config",
    "decode_dat",
    "export_csv",
    "export_json",
    "export_plain",
    "export_singbox",
    "find_singbox",
    "is_ipv4",
    "load_certs",
    "merge",
    "normalize_certs",
    "normalize_ports",
    "parse_pack",
    "parse_ssl_ports",
    "rc4",
    "sort_nodes",
]
