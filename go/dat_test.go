package vpngate

import (
	"bytes"
	"crypto/sha1"
	"strings"
	"testing"
)

func TestDecodeAPIRaw(t *testing.T) {
	blob := fixtureBytes(t, "api_raw.bin")
	records, meta, err := DecodeDAT(blob)
	if err != nil {
		t.Fatalf("DecodeDAT: %v", err)
	}
	if meta.SaltHex != "6c251f5c40d5e1739b0ef4395da111872639f2bd" {
		t.Errorf("salt = %s", meta.SaltHex)
	}
	if meta.KeyHex != "74ffac3bd2b906484c3cfc012db20ee0ed651a77" {
		t.Errorf("key = %s", meta.KeyHex)
	}
	if meta.NumHosts != 200 {
		t.Errorf("NumHosts = %d", meta.NumHosts)
	}
	if meta.PlaintextLen != 74773 {
		t.Errorf("PlaintextLen = %d", meta.PlaintextLen)
	}
	if meta.Columns != 34 {
		t.Errorf("Columns = %d", meta.Columns)
	}
	if len(records) != 200 {
		t.Fatalf("records = %d", len(records))
	}
	unique := make(map[string]struct{}, len(records))
	for _, r := range records {
		unique[r.IP] = struct{}{}
	}
	if len(unique) != 198 {
		t.Errorf("unique IPs = %d", len(unique))
	}
	for i, r := range records {
		if !validIPv4(r.IP) {
			t.Errorf("record %d invalid ip %q", i, r.IP)
		}
	}
}

func TestDecodeVPNGateDAT(t *testing.T) {
	blob := fixtureBytes(t, "VPNGate.dat")
	records, meta, err := DecodeDAT(blob)
	if err != nil {
		t.Fatalf("DecodeDAT: %v", err)
	}
	if meta.SaltHex != "99c6aac62cf7e3e29f0e43c596217764ef43e51b" {
		t.Errorf("salt = %s", meta.SaltHex)
	}
	if meta.KeyHex != "4f8fb1176b765039b4be7c5eddd3bdd0abe83703" {
		t.Errorf("key = %s", meta.KeyHex)
	}
	if meta.NumHosts != 200 {
		t.Errorf("NumHosts = %d", meta.NumHosts)
	}
	if len(records) != 200 {
		t.Errorf("records = %d", len(records))
	}
}

func TestDecodeDATRejectsShortInput(t *testing.T) {
	if _, _, err := DecodeDAT(bytes.Repeat([]byte{0}, datMinLen-1)); err == nil {
		t.Fatal("expected length error")
	}
}

func TestDecodeDATRejectsBadMagic(t *testing.T) {
	blob := bytes.Repeat([]byte{0}, datMinLen)
	if _, _, err := DecodeDAT(blob); err == nil || !strings.Contains(err.Error(), "magic") {
		t.Fatalf("expected magic error, got %v", err)
	}
}

func TestDecodeDATRejectsTrailingOuterBytes(t *testing.T) {
	plain := buildPackBytes(t, []packFixture{{
		name: "x",
		typ:  packTypeU32,
		u32:  []uint32{1},
	}})
	plain = append(plain, 0xFF)
	blob := encryptFixture(t, plain)
	if _, _, err := DecodeDAT(blob); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("expected trailing error, got %v", err)
	}
}

func encryptFixture(t *testing.T, plain []byte) []byte {
	t.Helper()
	salt := bytes.Repeat([]byte{0x42}, datSaltLen)
	key := sha1.Sum(salt)
	blob := make([]byte, datHeaderLen+datSaltLen, datHeaderLen+datSaltLen+len(plain))
	copy(blob, datMagic)
	copy(blob[datHeaderLen:], salt)
	return append(blob, rc4Crypt(key[:], plain)...)
}

func BenchmarkDecodeDAT(b *testing.B) {
	blob := fixtureBytes(b, "api_raw.bin")
	b.SetBytes(int64(len(blob)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := DecodeDAT(blob); err != nil {
			b.Fatal(err)
		}
	}
}
