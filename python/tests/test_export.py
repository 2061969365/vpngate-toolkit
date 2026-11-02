from __future__ import annotations

import json
import unittest

from vpngate.dat import Node
from vpngate.export import (
    export_csv,
    export_json,
    export_plain,
    export_singbox,
    is_result_array,
    select_singbox,
)

CA = ["ca"]
CERT = ["cert"]
KEY = ["key"]


def sample_node(**kwargs) -> Node:
    values = dict(
        ip="1.2.3.4",
        country="JP",
        fqdn="f.example",
        hostname="h.example",
        ssl_ports=[443],
        l2tp=False,
        udp_port=0,
        score=7,
        sessions=2,
        source="plugin",
        first_seen=0,
        last_seen=0,
    )
    values.update(kwargs)
    return Node(**values)


class JsonExportTest(unittest.TestCase):
    def test_exact_key_order_and_compact(self) -> None:
        text = export_json([sample_node()])
        self.assertEqual(
            text,
            '[{"ip":"1.2.3.4","country":"JP","fqdn":"f.example",'
            '"hostname":"h.example","ssl_ports":[443],"l2tp":false,'
            '"udp_port":0,"score":7,"sessions":2,"source":"plugin",'
            '"first_seen":0,"last_seen":0}]\n',
        )

    def test_sorted_by_ip(self) -> None:
        text = export_json([sample_node(ip="9.9.9.9"), sample_node(ip="1.1.1.1")])
        self.assertEqual(
            [item["ip"] for item in json.loads(text)], ["1.1.1.1", "9.9.9.9"]
        )
        self.assertTrue(text.endswith("\n"))
        self.assertFalse(text.endswith("\n\n"))


class CsvExportTest(unittest.TestCase):
    def test_result_input(self) -> None:
        results = [
            {
                "ip": "1.2.3.4",
                "port": 443,
                "country": "JP",
                "ok": True,
                "egress": "5.6.7.8",
                "elapsed_ms": 123,
                "error": "",
            }
        ]
        self.assertTrue(is_result_array(results))
        self.assertEqual(
            export_csv(results),
            "ip,port,country,egress,elapsed_ms,ok\n"
            "1.2.3.4,443,JP,5.6.7.8,123,true\n",
        )

    def test_node_input(self) -> None:
        text = export_csv([sample_node()])
        self.assertEqual(
            text,
            "ip,port,country,egress,elapsed_ms,ok\n1.2.3.4,443,JP,,0,false\n",
        )


class PlainExportTest(unittest.TestCase):
    def test_nodes(self) -> None:
        text = export_plain(
            [sample_node(), sample_node(ip="2.2.2.2", ssl_ports=[])]
        )
        self.assertEqual(text, "1.2.3.4:443\n")

    def test_results(self) -> None:
        results = [
            {"ip": "1.2.3.4", "port": 443, "ok": False},
            {"ip": "2.2.2.2", "port": 0, "ok": True},
        ]
        self.assertEqual(export_plain(results), "1.2.3.4:443\n")


class SingBoxExportTest(unittest.TestCase):
    def test_result_selection(self) -> None:
        results = [
            {"ip": "1.1.1.1", "port": 443, "ok": True, "elapsed_ms": 500},
            {"ip": "2.2.2.2", "port": 443, "ok": True, "elapsed_ms": 200},
            {"ip": "3.3.3.3", "port": 443, "ok": False, "elapsed_ms": 10},
        ]
        self.assertEqual(select_singbox(results).ip, "2.2.2.2")

    def test_node_selection(self) -> None:
        nodes = [
            sample_node(ip="1.1.1.1", score=10),
            sample_node(ip="2.2.2.2", score=100, ssl_ports=[]),
            sample_node(ip="3.3.3.3", score=50),
        ]
        self.assertEqual(select_singbox(nodes).ip, "3.3.3.3")

    def test_config_output(self) -> None:
        text = export_singbox([sample_node()], CA, CERT, KEY)
        config = json.loads(text)
        self.assertEqual(config["endpoints"][0]["server"], "1.2.3.4")
        self.assertEqual(config["endpoints"][0]["server_port"], 443)
        self.assertEqual(len(config["inbounds"]), 1)
        self.assertTrue(text.endswith("\n"))


if __name__ == "__main__":
    unittest.main()
