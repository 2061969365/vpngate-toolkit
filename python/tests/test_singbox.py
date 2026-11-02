from __future__ import annotations

import unittest

from vpngate.dat import Node
from vpngate.singbox import ConfigError, batch_configs, build_config

CA = ["-----BEGIN CERTIFICATE-----", "CA", "-----END CERTIFICATE-----"]
CERT = ["-----BEGIN CERTIFICATE-----", "CERT", "-----END CERTIFICATE-----"]
KEY = ["-----BEGIN PRIVATE KEY-----", "KEY", "-----END PRIVATE KEY-----"]


class SingBoxConfigTest(unittest.TestCase):
    def test_batch_structure(self) -> None:
        nodes = [
            Node(ip="1.1.1.1", ssl_ports=[443]),
            Node(ip="2.2.2.2", ssl_ports=[8443, 443]),
        ]
        config = build_config(nodes, CA, CERT, KEY, base_port=20000)
        self.assertEqual(config["log"], {"level": "error"})
        self.assertEqual(len(config["inbounds"]), 2)
        self.assertEqual(len(config["endpoints"]), 2)
        self.assertEqual(
            config["route"]["rules"],
            [
                {"inbound": "in0", "outbound": "ep0"},
                {"inbound": "in1", "outbound": "ep1"},
            ],
        )
        self.assertEqual(config["inbounds"][0]["listen"], "127.0.0.1")
        self.assertEqual(config["inbounds"][0]["listen_port"], 20000)
        self.assertEqual(config["inbounds"][1]["listen_port"], 20001)

        endpoint = config["endpoints"][0]
        self.assertEqual(endpoint["type"], "openvpn-client")
        self.assertEqual(endpoint["tag"], "ep0")
        self.assertEqual(endpoint["server"], "1.1.1.1")
        self.assertEqual(endpoint["server_port"], 443)
        self.assertEqual(endpoint["network"], "tcp")
        self.assertFalse(endpoint["system"])
        self.assertEqual(endpoint["username"], "vpn")
        self.assertEqual(endpoint["password"], "vpn")
        self.assertEqual(endpoint["data_ciphers"], ["AES-128-CBC"])
        self.assertEqual(endpoint["auth"], "SHA1")
        self.assertTrue(endpoint["route_no_pull"])
        self.assertTrue(endpoint["ping_restart_disabled"])
        self.assertEqual(endpoint["tls"]["remote_certificate_tls"], "none")
        self.assertEqual(endpoint["tls"]["certificate"], CA)
        self.assertEqual(config["endpoints"][1]["server_port"], 443)

    def test_cert_arrays_shared(self) -> None:
        nodes = [Node(ip="1.1.1.1", ssl_ports=[443]), Node(ip="2.2.2.2", ssl_ports=[443])]
        config = build_config(nodes, "\n".join(CA), "\n".join(CERT), "\n".join(KEY))
        first = config["endpoints"][0]["tls"]
        second = config["endpoints"][1]["tls"]
        self.assertIs(first["certificate"], second["certificate"])
        self.assertIs(first["client_certificate"], second["client_certificate"])

    def test_missing_port(self) -> None:
        with self.assertRaises(ConfigError):
            build_config([Node(ip="1.1.1.1")], CA, CERT, KEY)

    def test_missing_cert(self) -> None:
        with self.assertRaises(ConfigError):
            build_config([Node(ip="1.1.1.1", ssl_ports=[443])], [], CERT, KEY)

    def test_batch_ports_are_unique(self) -> None:
        nodes = [Node(ip=f"1.1.1.{i}", ssl_ports=[443]) for i in range(1, 4)]
        configs = batch_configs(nodes, CA, CERT, KEY, batch_size=2, base_port=20000)
        self.assertEqual(len(configs), 2)
        ports = [cfg["inbounds"][0]["listen_port"] for cfg in configs]
        self.assertEqual(ports, [20000, 20002])


if __name__ == "__main__":
    unittest.main()
