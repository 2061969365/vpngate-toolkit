from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from vpngate.cli import main
from vpngate.dat import decode_dat, sort_nodes
from vpngate.export import export_json

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"
API_RAW = FIXTURES / "api_raw.bin"


class DecodeCommandTest(unittest.TestCase):
    def test_decode_fixture(self) -> None:
        blob = API_RAW.read_bytes()
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "nodes.json"
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                code = main(["decode", "--in", str(API_RAW), "--out", str(out)])
            self.assertEqual(code, 0)
            expected = export_json(sort_nodes(decode_dat(blob)[0]))
            self.assertEqual(out.read_bytes(), expected.encode("utf-8"))
            self.assertEqual(
                stderr.getvalue().strip(),
                "salt=6c251f5c40d5e1739b0ef4395da111872639f2bd "
                "key=74ffac3bd2b906484c3cfc012db20ee0ed651a77 "
                "hosts=200 columns=34 plaintext=74773",
            )
            self.assertEqual(len(json.loads(out.read_text(encoding="utf-8"))), 200)

    def test_decode_to_stdout(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            code = main(["decode", "--in", str(API_RAW)])
        self.assertEqual(code, 0)
        self.assertEqual(len(json.loads(stdout.getvalue())), 200)


class ExportCommandTest(unittest.TestCase):
    def test_csv_from_nodes(self) -> None:
        node = {
            "ip": "1.2.3.4",
            "country": "JP",
            "fqdn": "",
            "hostname": "",
            "ssl_ports": [443],
            "l2tp": False,
            "udp_port": 0,
            "score": 0,
            "sessions": 0,
            "source": "plugin",
            "first_seen": 0,
            "last_seen": 0,
        }
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "nodes.json"
            out = Path(tmp) / "nodes.csv"
            source.write_text(json.dumps([node]), encoding="utf-8")
            code = main(
                ["export", "--in", str(source), "--format", "csv", "--out", str(out)]
            )
            self.assertEqual(code, 0)
            self.assertEqual(
                out.read_text(encoding="utf-8"),
                "ip,port,country,egress,elapsed_ms,ok\n1.2.3.4,443,JP,,0,false\n",
            )


class VersionCommandTest(unittest.TestCase):
    def test_version(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(main(["version"]), 0)
        self.assertEqual(stdout.getvalue(), "vpngate 1.0.0\n")


if __name__ == "__main__":
    unittest.main()
