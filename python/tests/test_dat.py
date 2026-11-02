from __future__ import annotations

import hashlib
import struct
import unittest
from pathlib import Path

from vpngate.dat import (
    MAGIC,
    DATError,
    rc4,
    decode_dat,
    parse_pack,
    parse_ssl_ports,
    sort_nodes,
)

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"
API_RAW = FIXTURES / "api_raw.bin"
VPNGATE_DAT = FIXTURES / "VPNGate.dat"


def build_pack(items: list[tuple[str, int, list]]) -> bytes:
    out = bytearray(struct.pack(">I", len(items)))
    for name, typ, values in items:
        encoded = name.encode("latin-1")
        out += struct.pack(">I", len(encoded) + 1) + encoded
        out += struct.pack(">II", typ, len(values))
        if typ == 0:
            out += struct.pack(f">{len(values)}I", *values)
        elif typ in (1, 2, 3):
            for value in values:
                out += struct.pack(">I", len(value)) + value
        elif typ == 4:
            out += struct.pack(f">{len(values)}Q", *values)
        else:
            raise AssertionError("bad test type")
    return bytes(out)


def wrap_container(inner: bytes, salt: bytes = b"0123456789abcdefghij") -> bytes:
    outer = build_pack(
        [
            ("data", 1, [inner]),
            ("data_size", 0, [len(inner)]),
            ("compressed", 0, [0]),
        ]
    )
    header = MAGIC + b"\x00" * (0xF0 - len(MAGIC))
    return header + salt + rc4(hashlib.sha1(salt).digest(), outer)


class FixtureDecodeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.blob = API_RAW.read_bytes()
        cls.nodes, cls.meta = decode_dat(cls.blob)

    def test_meta_vectors(self) -> None:
        self.assertEqual(
            self.meta.salt_hex, "6c251f5c40d5e1739b0ef4395da111872639f2bd"
        )
        self.assertEqual(
            self.meta.key_hex, "74ffac3bd2b906484c3cfc012db20ee0ed651a77"
        )
        self.assertEqual(self.meta.num_hosts, 200)
        self.assertEqual(self.meta.columns, 34)
        self.assertEqual(self.meta.plaintext_len, len(self.blob) - 0x104)

    def test_row_and_unique_counts(self) -> None:
        self.assertEqual(len(self.nodes), 200)
        unique = {node.ip for node in self.nodes}
        self.assertEqual(len(unique), 198)
        self.assertEqual(
            sum(1 for node in self.nodes if node.ip == "123.48.124.169"), 2
        )
        self.assertEqual(sum(1 for node in self.nodes if node.ip == "87.103.202.90"), 2)

    def test_deterministic_fields(self) -> None:
        self.assertTrue(all(node.source == "plugin" for node in self.nodes))
        self.assertTrue(all(node.first_seen == 0 for node in self.nodes))
        self.assertTrue(all(node.last_seen == 0 for node in self.nodes))

    def test_stable_sort_keeps_duplicate_row_order(self) -> None:
        sorted_nodes = sort_nodes(self.nodes)
        self.assertEqual(sorted_nodes, sorted(self.nodes, key=lambda n: n.ip))
        self.assertEqual(
            [n.ip for n in sorted_nodes], sorted(n.ip for n in self.nodes)
        )
        original_index = {id(n): i for i, n in enumerate(self.nodes)}
        for left, right in zip(sorted_nodes, sorted_nodes[1:]):
            if left.ip == right.ip:
                self.assertLess(original_index[id(left)], original_index[id(right)])

    def test_inner_blob_anchors(self) -> None:
        salt = self.blob[0xF0:0x104]
        plaintext = rc4(hashlib.sha1(salt).digest(), self.blob[0x104:])
        outer, off = parse_pack(plaintext)
        self.assertEqual(off, 74773)
        self.assertEqual(off, len(plaintext))
        inner_raw = outer["data"].values[0]
        self.assertEqual(len(inner_raw), 74422)
        self.assertEqual(outer["data_size"].values[0], 74422)
        _inner, inner_off = parse_pack(inner_raw)
        self.assertEqual(inner_off, 74422)
        self.assertEqual(inner_off, len(inner_raw))

    def test_compressed_fixture(self) -> None:
        nodes, meta = decode_dat(VPNGATE_DAT.read_bytes())
        self.assertEqual(
            meta.salt_hex, "99c6aac62cf7e3e29f0e43c596217764ef43e51b"
        )
        self.assertEqual(
            meta.key_hex, "4f8fb1176b765039b4be7c5eddd3bdd0abe83703"
        )
        self.assertEqual(meta.num_hosts, 200)
        self.assertEqual(len(nodes), 200)


class ContainerErrorTest(unittest.TestCase):
    def test_too_short(self) -> None:
        with self.assertRaises(DATError):
            decode_dat(b"x" * 275)

    def test_bad_magic(self) -> None:
        with self.assertRaises(DATError):
            decode_dat(b"X" + b"x" * 400)

    def test_trailing_outer_bytes(self) -> None:
        with self.assertRaises(DATError):
            decode_dat(API_RAW.read_bytes() + b"\x00")

    def test_num_hosts_missing(self) -> None:
        inner = build_pack(
            [("IP", 2, [b"1.2.3.4"]), ("SslPorts", 2, [b"443"])]
        )
        with self.assertRaises(DATError):
            decode_dat(wrap_container(inner))

    def test_num_hosts_too_large(self) -> None:
        inner = build_pack([("NumHosts", 0, [100001])])
        with self.assertRaises(DATError):
            decode_dat(wrap_container(inner))

    def test_column_length_mismatch(self) -> None:
        inner = build_pack(
            [
                ("NumHosts", 0, [2]),
                ("IP", 2, [b"1.2.3.4"]),
                ("SslPorts", 2, [b"443", b"443"]),
            ]
        )
        with self.assertRaises(DATError):
            decode_dat(wrap_container(inner))

    def test_invalid_ip_is_dropped(self) -> None:
        inner = build_pack(
            [
                ("NumHosts", 0, [2]),
                ("IP", 2, [b"1.2.3.4", b"not-an-ip"]),
                ("CountryShort", 2, [b"JP", b"US"]),
                ("SslPorts", 2, [b"443", b"443"]),
            ]
        )
        nodes, meta = decode_dat(wrap_container(inner))
        self.assertEqual(meta.num_hosts, 2)
        self.assertEqual([node.ip for node in nodes], ["1.2.3.4"])


class PackTypeTest(unittest.TestCase):
    def test_type0_u32(self) -> None:
        buf = build_pack([("u32", 0, [1, 2, 4294967295])])
        items, off = parse_pack(buf)
        self.assertEqual(items["u32"].type, 0)
        self.assertEqual(items["u32"].values, [1, 2, 4294967295])
        self.assertEqual(off, len(buf))

    def test_type1_binary(self) -> None:
        buf = build_pack([("bin", 1, [b"\x00\xff", b""])])
        items, off = parse_pack(buf)
        self.assertEqual(items["bin"].type, 1)
        self.assertEqual(items["bin"].values, [b"\x00\xff", b""])
        self.assertEqual(off, len(buf))

    def test_type2_string(self) -> None:
        buf = build_pack([("str", 2, [b"hello", "世界".encode()])])
        items, off = parse_pack(buf)
        self.assertEqual(items["str"].type, 2)
        self.assertEqual(items["str"].values[0], b"hello")
        self.assertEqual(off, len(buf))

    def test_type3_string(self) -> None:
        buf = build_pack([("msg", 3, [b"hello"])])
        items, off = parse_pack(buf)
        self.assertEqual(items["msg"].type, 3)
        self.assertEqual(items["msg"].values, [b"hello"])
        self.assertEqual(off, len(buf))

    def test_type4_u64(self) -> None:
        buf = build_pack([("u64", 4, [1, 18446744073709551615])])
        items, off = parse_pack(buf)
        self.assertEqual(items["u64"].type, 4)
        self.assertEqual(items["u64"].values, [1, 18446744073709551615])
        self.assertEqual(off, len(buf))

    def test_unknown_type(self) -> None:
        buf = bytearray(build_pack([]))
        name = b"x"
        buf += (
            struct.pack(">I", len(name) + 1) + name + struct.pack(">II", 9, 0)
        )
        buf[0:4] = struct.pack(">I", 1)
        with self.assertRaises(DATError):
            parse_pack(bytes(buf))

    def test_truncated(self) -> None:
        with self.assertRaises(DATError):
            parse_pack(b"\x00\x00\x00\x01\x00\x00\x00\x10")


class PortParseTest(unittest.TestCase):
    def test_comma_and_space(self) -> None:
        self.assertEqual(parse_ssl_ports("443, 8443 443"), [443, 8443])

    def test_empty_and_junk(self) -> None:
        self.assertEqual(parse_ssl_ports(""), [])
        self.assertEqual(parse_ssl_ports("abc, 0, 70000, -1"), [])

    def test_out_of_range_filtered(self) -> None:
        self.assertEqual(parse_ssl_ports("65535,65536,1"), [1, 65535])


if __name__ == "__main__":
    unittest.main()
