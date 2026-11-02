from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path

from vpngate.source import (
    CertError,
    CSVSource,
    decode_ovpn,
    extract_certs,
    load_certs,
    normalize_certs,
    parse_ovpn_port,
    read_cert_file,
    write_cert_file,
)

OVPN = """client
remote 1.2.3.4 443 tcp
<ca>
-----BEGIN CERTIFICATE-----
CA-LINE
-----END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----
CERT-LINE
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
KEY-LINE
-----END PRIVATE KEY-----
</key>
"""


def csv_text() -> str:
    payload = base64.b64encode(OVPN.encode()).decode()
    return (
        "*\n"
        "#HostName,IP,Score,CountryShort,NumVpnSessions,OpenVPN_ConfigData_Base64\n"
        f"host1,1.2.3.4,100,JP,3,{payload}\n"
        "host2,999.1.1.1,10,US,1,\n"
        "host3,5.6.7.8,20,DE,2,\n"
    )


class CSVSourceTest(unittest.TestCase):
    def test_parse_rows_and_certs(self) -> None:
        source = CSVSource(get=lambda url, timeout: csv_text().encode())
        nodes = source.fetch()
        self.assertEqual([node.ip for node in nodes], ["1.2.3.4", "5.6.7.8"])
        self.assertEqual(nodes[0].country, "JP")
        self.assertEqual(nodes[0].hostname, "host1")
        self.assertEqual(nodes[0].ssl_ports, [443])
        self.assertEqual(nodes[0].score, 100)
        self.assertEqual(nodes[0].sessions, 3)
        self.assertEqual(nodes[0].source, "csv")
        self.assertEqual(source.skipped, 1)
        self.assertEqual(source.ca[1], "CA-LINE")
        self.assertEqual(source.cert[1], "CERT-LINE")
        self.assertEqual(source.key[1], "KEY-LINE")

    def test_ovpn_helpers(self) -> None:
        self.assertEqual(parse_ovpn_port(OVPN), 443)
        self.assertEqual(parse_ovpn_port("remote-random\n"), 0)
        self.assertEqual(decode_ovpn(base64.b64encode(OVPN.encode()).decode()), OVPN)
        self.assertEqual(
            extract_certs(OVPN),
            (
                [
                    "-----BEGIN CERTIFICATE-----",
                    "CA-LINE",
                    "-----END CERTIFICATE-----",
                ],
                [
                    "-----BEGIN CERTIFICATE-----",
                    "CERT-LINE",
                    "-----END CERTIFICATE-----",
                ],
                [
                    "-----BEGIN PRIVATE KEY-----",
                    "KEY-LINE",
                    "-----END PRIVATE KEY-----",
                ],
            ),
        )
        self.assertIsNone(extract_certs("no certs here"))


class CertLookupTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.certs = (["ca1"], ["cert1"], ["key1"])

    def test_write_and_read(self) -> None:
        path = self.dir / "x.certs.json"
        write_cert_file(path, *self.certs)
        self.assertEqual(read_cert_file(path), self.certs)

    def test_explicit_file_wins(self) -> None:
        path = self.dir / "explicit.json"
        write_cert_file(path, *self.certs)
        self.assertEqual(load_certs(path, self.dir / "missing.json"), self.certs)

    def test_sidecar_then_sibling(self) -> None:
        node_file = self.dir / "nodes.json"
        node_file.write_text("[]", encoding="utf-8")
        write_cert_file(str(node_file) + ".certs.json", *self.certs)
        self.assertEqual(load_certs(None, node_file), self.certs)

        (self.dir / "nodes.json.certs.json").unlink()
        write_cert_file(self.dir / "certs.json", *self.certs)
        self.assertEqual(load_certs(None, node_file), self.certs)

    def test_network_fallback(self) -> None:
        get = lambda url, timeout: csv_text().encode()
        ca, cert, key = load_certs(None, None, get=get)
        self.assertEqual(ca[1], "CA-LINE")
        self.assertEqual(cert[1], "CERT-LINE")
        self.assertEqual(key[1], "KEY-LINE")

    def test_invalid_certs_rejected(self) -> None:
        with self.assertRaises(CertError):
            normalize_certs({"ca": [], "cert": ["x"], "key": ["y"]})
        path = self.dir / "bad.json"
        path.write_text(json.dumps({"ca": [], "cert": [], "key": []}), encoding="utf-8")
        with self.assertRaises(CertError):
            read_cert_file(path)


if __name__ == "__main__":
    unittest.main()
