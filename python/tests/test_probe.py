from __future__ import annotations

import unittest
from unittest.mock import patch

from vpngate.dat import Node
from vpngate.probe import (
    ProbeError,
    RetryableProbeError,
    SingBoxBatchProber,
)


class RetryLoopTest(unittest.TestCase):
    def setUp(self) -> None:
        self.prober = SingBoxBatchProber(
            timeout=3.0, certs=(["ca"], ["cert"], ["key"])
        )
        self.node = Node(ip="1.2.3.4", country="JP", ssl_ports=[443])

    def test_retries_until_success(self) -> None:
        calls: list[int] = []

        def fake(*args, **kwargs):
            calls.append(1)
            if len(calls) < 3:
                raise RetryableProbeError("SOCKS5 connect failed: code 1")
            return "5.6.7.8"

        with patch("vpngate.probe.socks5_http_get", side_effect=fake):
            result = self.prober._probe_one(self.node, 20000)

        self.assertTrue(result.ok)
        self.assertEqual(result.egress, "5.6.7.8")
        self.assertEqual(len(calls), 3)
        self.assertGreaterEqual(result.elapsed_ms, 400)

    def test_non_retryable_stops_immediately(self) -> None:
        calls: list[int] = []

        def fake(*args, **kwargs):
            calls.append(1)
            raise ProbeError("SOCKS5 bad version")

        with patch("vpngate.probe.socks5_http_get", side_effect=fake):
            result = self.prober._probe_one(self.node, 20000)

        self.assertFalse(result.ok)
        self.assertEqual(len(calls), 1)
        self.assertIn("bad version", result.error)

    def test_budget_exhausted(self) -> None:
        calls: list[int] = []
        prober = SingBoxBatchProber(
            timeout=0.6, certs=(["ca"], ["cert"], ["key"])
        )

        def fake(*args, **kwargs):
            calls.append(1)
            raise RetryableProbeError("code 1")

        with patch("vpngate.probe.socks5_http_get", side_effect=fake):
            result = prober._probe_one(self.node, 20000)

        self.assertFalse(result.ok)
        self.assertTrue(result.error.startswith("timeout"))
        self.assertGreaterEqual(len(calls), 2)
        self.assertGreaterEqual(result.elapsed_ms, 500)


if __name__ == "__main__":
    unittest.main()
