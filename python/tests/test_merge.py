from __future__ import annotations

import unittest

from vpngate.dat import Node
from vpngate.merge import merge


def node(ip: str, **kwargs) -> Node:
    return Node(ip=ip, **kwargs)


class MergeTest(unittest.TestCase):
    def test_overlap(self) -> None:
        left = node(
            "1.2.3.4",
            country="JP",
            fqdn="a.example",
            hostname="",
            ssl_ports=[443, 80],
            score=10,
            sessions=2,
            source="plugin",
            first_seen=100,
            last_seen=200,
        )
        right = node(
            "1.2.3.4",
            country="US",
            fqdn="",
            hostname="b.example",
            ssl_ports=[443, 8443],
            score=20,
            sessions=1,
            source="csv",
            first_seen=50,
            last_seen=300,
        )
        merged = merge([left, right])
        self.assertEqual(len(merged), 1)
        result = merged[0]
        self.assertEqual(result.source, "both")
        self.assertEqual(result.ssl_ports, [80, 443, 8443])
        self.assertEqual(result.score, 20)
        self.assertEqual(result.sessions, 2)
        self.assertEqual(result.fqdn, "a.example")
        self.assertEqual(result.hostname, "b.example")
        self.assertEqual(result.country, "JP")
        self.assertEqual(result.first_seen, 50)
        self.assertEqual(result.last_seen, 300)

    def test_only_left_and_only_right(self) -> None:
        merged = merge(
            [
                node("2.2.2.2", source="csv"),
                node("1.1.1.1", source="plugin"),
            ]
        )
        self.assertEqual([item.ip for item in merged], ["1.1.1.1", "2.2.2.2"])
        self.assertEqual(merged[0].source, "plugin")
        self.assertEqual(merged[1].source, "csv")

    def test_inputs_are_not_mutated(self) -> None:
        left = node("1.1.1.1", ssl_ports=[443])
        right = node("1.1.1.1", ssl_ports=[8443])
        merge([left, right])
        self.assertEqual(left.source, "plugin")
        self.assertEqual(left.ssl_ports, [443])
        self.assertEqual(right.ssl_ports, [8443])


if __name__ == "__main__":
    unittest.main()
