package vpngate

import (
	"encoding/binary"
	"fmt"
)

const (
	packTypeU32    uint32 = 0
	packTypeBinary uint32 = 1
	packTypeString uint32 = 2
	packTypeText   uint32 = 3
	packTypeU64    uint32 = 4
)

type PackItem struct {
	Name  string
	Type  uint32
	Count uint32
	U32   []uint32
	U64   []uint64
	Data  [][]byte
}

type Pack map[string]*PackItem

func (p Pack) FirstU32(name string) (uint32, bool) {
	item, ok := p[name]
	if !ok || item.Count == 0 || len(item.U32) == 0 {
		return 0, false
	}
	return item.U32[0], true
}

func (p Pack) FirstU64(name string) (uint64, bool) {
	item, ok := p[name]
	if !ok || item.Count == 0 || len(item.U64) == 0 {
		return 0, false
	}
	return item.U64[0], true
}

func (p Pack) FirstBytes(name string) ([]byte, bool) {
	item, ok := p[name]
	if !ok || item.Count == 0 || len(item.Data) == 0 {
		return nil, false
	}
	return item.Data[0], true
}

func ParsePack(buf []byte) (Pack, int, error) {
	if len(buf) < 4 {
		return nil, 0, fmt.Errorf("pack: truncated item count")
	}
	count := binary.BigEndian.Uint32(buf[:4])
	off := 4
	if uint64(count)*12 > uint64(len(buf)-off) {
		return nil, 0, fmt.Errorf("pack: item count %d exceeds buffer", count)
	}
	items := make(Pack, count)
	for i := uint32(0); i < count; i++ {
		nameLen, err := readU32At(buf, off)
		if err != nil {
			return nil, 0, fmt.Errorf("pack item %d: %w", i, err)
		}
		off += 4
		if nameLen == 0 {
			return nil, 0, fmt.Errorf("pack item %d: zero name length", i)
		}
		nameBytes := uint64(nameLen - 1)
		if nameBytes > uint64(len(buf)-off) {
			return nil, 0, fmt.Errorf("pack item %d: truncated name", i)
		}
		name := string(buf[off : off+int(nameBytes)])
		off += int(nameBytes)

		typ, err := readU32At(buf, off)
		if err != nil {
			return nil, 0, fmt.Errorf("pack item %d (%s): %w", i, name, err)
		}
		valueCount, err := readU32At(buf, off+4)
		if err != nil {
			return nil, 0, fmt.Errorf("pack item %d (%s): %w", i, name, err)
		}
		off += 8
		item := &PackItem{Name: name, Type: typ, Count: valueCount}

		switch typ {
		case packTypeU32:
			if uint64(valueCount)*4 > uint64(len(buf)-off) {
				return nil, 0, fmt.Errorf("pack item %s: truncated u32 values", name)
			}
			item.U32 = make([]uint32, valueCount)
			for j := range item.U32 {
				item.U32[j] = binary.BigEndian.Uint32(buf[off : off+4])
				off += 4
			}
		case packTypeBinary, packTypeString, packTypeText:
			if uint64(valueCount)*4 > uint64(len(buf)-off) {
				return nil, 0, fmt.Errorf("pack item %s: truncated data values", name)
			}
			item.Data = make([][]byte, 0, valueCount)
			for j := uint32(0); j < valueCount; j++ {
				size, err := readU32At(buf, off)
				if err != nil {
					return nil, 0, fmt.Errorf("pack item %s value %d: %w", name, j, err)
				}
				off += 4
				if uint64(size) > uint64(len(buf)-off) {
					return nil, 0, fmt.Errorf("pack item %s value %d: truncated data", name, j)
				}
				item.Data = append(item.Data, buf[off:off+int(size)])
				off += int(size)
			}
		case packTypeU64:
			if uint64(valueCount)*8 > uint64(len(buf)-off) {
				return nil, 0, fmt.Errorf("pack item %s: truncated u64 values", name)
			}
			item.U64 = make([]uint64, valueCount)
			for j := range item.U64 {
				item.U64[j] = binary.BigEndian.Uint64(buf[off : off+8])
				off += 8
			}
		default:
			return nil, 0, fmt.Errorf("pack item %s: unknown type %d", name, typ)
		}
		items[name] = item
	}
	return items, off, nil
}

func readU32At(buf []byte, off int) (uint32, error) {
	if off < 0 || off+4 > len(buf) {
		return 0, fmt.Errorf("truncated at offset %d", off)
	}
	return binary.BigEndian.Uint32(buf[off : off+4]), nil
}
