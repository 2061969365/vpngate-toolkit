package vpngate

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	datHeaderLen = 0xF0
	datSaltLen   = 0x14
	datMinLen    = datHeaderLen + datSaltLen + 16
	datMagic     = "[VPNGate Data File]"
	maxHosts     = 100000
)

type Meta struct {
	SaltHex      string `json:"salt_hex"`
	KeyHex       string `json:"key_hex"`
	NumHosts     int    `json:"num_hosts"`
	Columns      int    `json:"columns"`
	PlaintextLen int    `json:"plaintext_len"`
}

type Record struct {
	IP       string
	Country  string
	Fqdn     string
	HostName string
	SSLPorts []int
	L2TP     bool
	UDPPort  uint32
	Score    uint32
	Sessions uint32
}

type RecordSet []Record

func (rs RecordSet) Nodes(source string, firstSeen, lastSeen int64) []Node {
	nodes := make([]Node, 0, len(rs))
	for _, r := range rs {
		nodes = append(nodes, Node{
			IP:        r.IP,
			Country:   r.Country,
			FQDN:      r.Fqdn,
			Hostname:  r.HostName,
			SSLPorts:  normalizeSSLPorts(r.SSLPorts),
			L2TP:      r.L2TP,
			UDPPort:   r.UDPPort,
			Score:     r.Score,
			Sessions:  r.Sessions,
			Source:    source,
			FirstSeen: firstSeen,
			LastSeen:  lastSeen,
		})
	}
	return nodes
}

func DecodeDAT(blob []byte) (RecordSet, Meta, error) {
	var meta Meta
	if len(blob) < datMinLen {
		return nil, meta, fmt.Errorf("dat: blob too short: %d bytes (need >= %d)", len(blob), datMinLen)
	}
	if !bytes.HasPrefix(blob, []byte(datMagic)) {
		return nil, meta, fmt.Errorf("dat: bad magic")
	}

	salt := blob[datHeaderLen : datHeaderLen+datSaltLen]
	key := sha1.Sum(salt)
	plain := rc4Crypt(key[:], blob[datHeaderLen+datSaltLen:])

	outer, off, err := ParsePack(plain)
	if err != nil {
		return nil, meta, fmt.Errorf("dat: outer pack: %w", err)
	}
	if off != len(plain) {
		return nil, meta, fmt.Errorf("dat: outer pack trailing bytes: %d", len(plain)-off)
	}

	data, ok := outer.FirstBytes("data")
	if !ok {
		return nil, meta, fmt.Errorf("dat: outer pack missing data")
	}
	compressed := false
	if item, ok := outer["compressed"]; ok && item.Count > 0 {
		if item.Type == packTypeU32 && len(item.U32) > 0 {
			compressed = item.U32[0] != 0
		} else if item.Type == packTypeU64 && len(item.U64) > 0 {
			compressed = item.U64[0] != 0
		}
	}
	if compressed || isZlib(data) {
		zr, err := zlib.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, meta, fmt.Errorf("dat: zlib: %w", err)
		}
		data, err = io.ReadAll(zr)
		closeErr := zr.Close()
		if err != nil {
			return nil, meta, fmt.Errorf("dat: zlib: %w", err)
		}
		if closeErr != nil {
			return nil, meta, fmt.Errorf("dat: zlib: %w", closeErr)
		}
	}

	inner, innerOff, err := ParsePack(data)
	if err != nil {
		return nil, meta, fmt.Errorf("dat: inner pack: %w", err)
	}
	if innerOff != len(data) {
		return nil, meta, fmt.Errorf("dat: inner pack trailing bytes: %d", len(data)-innerOff)
	}

	hostsItem, ok := inner["NumHosts"]
	if !ok || hostsItem.Count == 0 {
		return nil, meta, fmt.Errorf("dat: NumHosts missing")
	}
	hosts64, ok := packUint(hostsItem, 0)
	if !ok {
		return nil, meta, fmt.Errorf("dat: NumHosts is not numeric")
	}
	if hosts64 > maxHosts {
		return nil, meta, fmt.Errorf("dat: NumHosts %d exceeds %d", hosts64, maxHosts)
	}
	numHosts := int(hosts64)

	names := make([]string, 0, len(inner))
	for name := range inner {
		names = append(names, name)
	}
	sort.Strings(names)
	columns := 0
	for _, name := range names {
		item := inner[name]
		if name == "NumHosts" {
			continue
		}
		if int(item.Count) != numHosts && item.Count != 1 {
			return nil, meta, fmt.Errorf("dat: column %s has %d rows, NumHosts is %d", name, item.Count, numHosts)
		}
		if int(item.Count) == numHosts {
			columns++
		}
	}

	records := make(RecordSet, 0, numHosts)
	for row := 0; row < numHosts; row++ {
		ip := recordText(inner, "IP", row)
		if !validIPv4(ip) {
			continue
		}
		records = append(records, Record{
			IP:       ip,
			Country:  recordText(inner, "CountryShort", row),
			Fqdn:     recordText(inner, "Fqdn", row),
			HostName: recordText(inner, "HostName", row),
			SSLPorts: recordPorts(inner, row),
			L2TP:     recordUint(inner, "L2TP", row) != 0,
			UDPPort:  uint32(recordUint(inner, "UdpPort", row)),
			Score:    uint32(recordUint(inner, "Score", row)),
			Sessions: uint32(recordUint(inner, "NumClients", row)),
		})
	}

	meta = Meta{
		SaltHex:      hex.EncodeToString(salt),
		KeyHex:       hex.EncodeToString(key[:]),
		NumHosts:     numHosts,
		Columns:      columns,
		PlaintextLen: len(plain),
	}
	return records, meta, nil
}

func DecodeDATFile(path string) (RecordSet, Meta, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, Meta{}, err
	}
	return DecodeDAT(blob)
}

func rc4Crypt(key, data []byte) []byte {
	var s [256]byte
	for i := 0; i < 256; i++ {
		s[i] = byte(i)
	}
	if len(key) == 0 {
		return append([]byte(nil), data...)
	}
	j := 0
	for i := 0; i < 256; i++ {
		j = (j + int(s[i]) + int(key[i%len(key)])) & 0xFF
		s[i], s[j] = s[j], s[i]
	}
	out := make([]byte, len(data))
	i, j := 0, 0
	for k, b := range data {
		i = (i + 1) & 0xFF
		j = (j + int(s[i])) & 0xFF
		s[i], s[j] = s[j], s[i]
		out[k] = b ^ s[(int(s[i])+int(s[j]))&0xFF]
	}
	return out
}

func isZlib(data []byte) bool {
	return len(data) >= 2 && data[0] == 0x78 && (uint16(data[0])<<8|uint16(data[1]))%31 == 0
}

func packUint(item *PackItem, index int) (uint64, bool) {
	switch item.Type {
	case packTypeU32:
		if index >= 0 && index < len(item.U32) {
			return uint64(item.U32[index]), true
		}
	case packTypeU64:
		if index >= 0 && index < len(item.U64) {
			return item.U64[index], true
		}
	case packTypeBinary, packTypeString, packTypeText:
		if index >= 0 && index < len(item.Data) {
			v, err := strconv.ParseUint(strings.TrimSpace(decodeText(item.Data[index])), 10, 64)
			if err == nil {
				return v, true
			}
		}
	}
	return 0, false
}

func recordText(pack Pack, name string, row int) string {
	item, ok := pack[name]
	if !ok || row < 0 {
		return ""
	}
	switch item.Type {
	case packTypeBinary, packTypeString, packTypeText:
		if row < len(item.Data) {
			return decodeText(item.Data[row])
		}
	case packTypeU32:
		if row < len(item.U32) {
			return strconv.FormatUint(uint64(item.U32[row]), 10)
		}
	case packTypeU64:
		if row < len(item.U64) {
			return strconv.FormatUint(item.U64[row], 10)
		}
	}
	return ""
}

func recordUint(pack Pack, name string, row int) uint64 {
	item, ok := pack[name]
	if !ok {
		return 0
	}
	v, _ := packUint(item, row)
	return v
}

func recordPorts(pack Pack, row int) []int {
	item, ok := pack["SslPorts"]
	if !ok || row < 0 {
		return []int{}
	}
	switch item.Type {
	case packTypeU32:
		if row < len(item.U32) {
			return normalizeSSLPorts([]int{int(item.U32[row])})
		}
	case packTypeU64:
		if row < len(item.U64) {
			return normalizeSSLPorts([]int{int(item.U64[row])})
		}
	default:
		return ParseSSLPorts(recordText(pack, "SslPorts", row))
	}
	return []int{}
}

func decodeText(b []byte) string {
	b = bytes.TrimRight(b, "\x00")
	if utf8.Valid(b) {
		return string(b)
	}
	runes := make([]rune, len(b))
	for i, c := range b {
		runes[i] = rune(c)
	}
	return string(runes)
}

var remotePortRE = regexp.MustCompile(`(?m)^[ \t]*remote[ \t]+[^ \t\r\n]+[ \t]+([0-9]+)`)

func ParseSSLPorts(s string) []int {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\r' || r == '\n'
	})
	ports := make([]int, 0, len(fields))
	for _, f := range fields {
		v, err := strconv.Atoi(strings.TrimSpace(f))
		if err == nil {
			ports = append(ports, v)
		}
	}
	return normalizeSSLPorts(ports)
}

func ParseOVPNPorts(cfg string) []int {
	matches := remotePortRE.FindAllStringSubmatch(cfg, -1)
	ports := make([]int, 0, len(matches))
	for _, m := range matches {
		v, err := strconv.Atoi(m[1])
		if err == nil {
			ports = append(ports, v)
		}
	}
	return normalizeSSLPorts(ports)
}
