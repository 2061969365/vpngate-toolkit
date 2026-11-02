package vpngate

import (
	"bytes"
	"encoding/binary"
	"testing"
)

type packFixture struct {
	name string
	typ  uint32
	u32  []uint32
	u64  []uint64
	data [][]byte
}

func buildPackBytes(t testing.TB, items []packFixture) []byte {
	t.Helper()
	var buf bytes.Buffer
	writeU32 := func(v uint32) {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], v)
		buf.Write(b[:])
	}
	writeU32(uint32(len(items)))
	for _, item := range items {
		writeU32(uint32(len(item.name) + 1))
		buf.WriteString(item.name)
		writeU32(item.typ)
		switch item.typ {
		case packTypeU32:
			writeU32(uint32(len(item.u32)))
			for _, v := range item.u32 {
				writeU32(v)
			}
		case packTypeU64:
			writeU32(uint32(len(item.u64)))
			for _, v := range item.u64 {
				var b [8]byte
				binary.BigEndian.PutUint64(b[:], v)
				buf.Write(b[:])
			}
		default:
			writeU32(uint32(len(item.data)))
			for _, v := range item.data {
				writeU32(uint32(len(v)))
				buf.Write(v)
			}
		}
	}
	return buf.Bytes()
}

func TestParsePackAllTypes(t *testing.T) {
	blob := buildPackBytes(t, []packFixture{
		{name: "ints", typ: packTypeU32, u32: []uint32{7, 9}},
		{name: "blob", typ: packTypeBinary, data: [][]byte{{0, 1, 2}}},
		{name: "str", typ: packTypeString, data: [][]byte{[]byte("hello")}},
		{name: "text", typ: packTypeText, data: [][]byte{[]byte("world")}},
		{name: "big", typ: packTypeU64, u64: []uint64{1 << 40}},
	})
	pack, off, err := ParsePack(blob)
	if err != nil {
		t.Fatalf("ParsePack: %v", err)
	}
	if off != len(blob) {
		t.Errorf("off = %d, len = %d", off, len(blob))
	}
	if got := pack["ints"].U32; len(got) != 2 || got[0] != 7 || got[1] != 9 {
		t.Errorf("ints = %v", got)
	}
	if got := pack["blob"].Data[0]; !bytes.Equal(got, []byte{0, 1, 2}) {
		t.Errorf("blob = %v", got)
	}
	if got := string(pack["str"].Data[0]); got != "hello" {
		t.Errorf("str = %q", got)
	}
	if got := string(pack["text"].Data[0]); got != "world" {
		t.Errorf("text = %q", got)
	}
	if got := pack["big"].U64[0]; got != 1<<40 {
		t.Errorf("big = %d", got)
	}
}

func TestParsePackRejectsUnknownType(t *testing.T) {
	blob := buildPackBytes(t, []packFixture{{name: "bad", typ: 9}})
	if _, _, err := ParsePack(blob); err == nil {
		t.Fatal("expected unknown type error")
	}
}

func TestParsePackRejectsTruncatedValue(t *testing.T) {
	blob := buildPackBytes(t, []packFixture{{name: "ints", typ: packTypeU32, u32: []uint32{1}}})
	if _, _, err := ParsePack(blob[:len(blob)-1]); err == nil {
		t.Fatal("expected truncation error")
	}
}

func TestParsePackRejectsZeroName(t *testing.T) {
	blob := []byte{}
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], 1)
	blob = append(blob, b[:]...)
	binary.BigEndian.PutUint32(b[:], 0)
	blob = append(blob, b[:]...)
	if _, _, err := ParsePack(blob); err == nil {
		t.Fatal("expected zero name error")
	}
}
