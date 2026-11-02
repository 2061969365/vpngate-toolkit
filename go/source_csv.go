package vpngate

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	csvURL     = "https://www.vpngate.net/api/iphone/"
	maxCSVSize = 64 << 20
)

type CSVSource struct {
	Client       *http.Client
	URL          string
	Timeout      time.Duration
	UserAgent    string
	Now          func() time.Time
	Certificates CertBundle
	ParseErrors  int
}

func (s *CSVSource) Name() string { return "csv" }

func (s *CSVSource) Fetch(ctx context.Context) ([]Node, error) {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ua := s.UserAgent
	if ua == "" {
		ua = defaultUA
	}
	client := s.Client
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	url := s.URL
	if url == "" {
		url = csvURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", ua)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("csv: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("csv: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCSVSize))
	if err != nil {
		return nil, fmt.Errorf("csv: %w", err)
	}

	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	seen := now().Unix()
	nodes, certs, skipped, err := parseCSVNodes(body, seen)
	if err != nil {
		return nil, err
	}
	s.Certificates = certs
	s.ParseErrors = skipped
	return nodes, nil
}

func parseCSVNodes(data []byte, seen int64) ([]Node, CertBundle, int, error) {
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	r := csv.NewReader(bytes.NewReader(data))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true

	header := map[string]int{}
	headerSeen := false
	var nodes []Node
	var certs CertBundle
	skipped := 0

	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			skipped++
			continue
		}
		if len(rec) == 0 {
			continue
		}
		first := strings.TrimSpace(rec[0])
		if first == "" || strings.HasPrefix(first, "*") {
			continue
		}
		if strings.HasPrefix(first, "#") {
			head := strings.TrimSpace(strings.TrimPrefix(first, "#"))
			if head == "HostName" {
				header = make(map[string]int, len(rec))
				for i, name := range rec {
					name = strings.TrimSpace(name)
					name = strings.TrimPrefix(name, "#")
					header[name] = i
				}
				headerSeen = true
			}
			continue
		}
		if !headerSeen {
			continue
		}

		ip := csvField(rec, header, "IP")
		if !validIPv4(ip) {
			skipped++
			continue
		}
		cfgText := ""
		if raw := csvField(rec, header, "OpenVPN_ConfigData_Base64"); raw != "" {
			cfg, err := decodeBase64Loose(raw)
			if err != nil {
				skipped++
				continue
			}
			cfgText = string(cfg)
		}
		ports := ParseOVPNPorts(cfgText)
		if !certs.Complete() {
			if got := ExtractOVPNCerts(cfgText); got.Complete() {
				certs = got
			}
		}
		nodes = append(nodes, Node{
			IP:        ip,
			Country:   csvField(rec, header, "CountryShort"),
			FQDN:      csvField(rec, header, "Fqdn"),
			Hostname:  csvField(rec, header, "HostName"),
			SSLPorts:  ports,
			Score:     parseUint32(csvField(rec, header, "Score")),
			Sessions:  parseUint32(csvField(rec, header, "NumVpnSessions")),
			Source:    "csv",
			FirstSeen: seen,
			LastSeen:  seen,
		})
	}
	if !headerSeen {
		return nil, CertBundle{}, skipped, fmt.Errorf("csv: header not found")
	}
	return nodes, certs.Normalized(), skipped, nil
}

func csvField(rec []string, header map[string]int, name string) string {
	i, ok := header[name]
	if !ok || i < 0 || i >= len(rec) {
		return ""
	}
	return strings.TrimSpace(rec[i])
}

func parseUint32(s string) uint32 {
	v, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
	if err != nil {
		return 0
	}
	return uint32(v)
}

func decodeBase64Loose(s string) ([]byte, error) {
	s = strings.Join(strings.Fields(s), "")
	if s == "" {
		return nil, nil
	}
	if rem := len(s) % 4; rem != 0 {
		s += strings.Repeat("=", 4-rem)
	}
	encs := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	var lastErr error
	for _, enc := range encs {
		b, err := enc.DecodeString(s)
		if err == nil {
			return b, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

var ovpnCertRE = regexp.MustCompile(`(?is)<ca>\s*(.*?)\s*</ca>`)
var ovpnClientCertRE = regexp.MustCompile(`(?is)<cert>\s*(.*?)\s*</cert>`)
var ovpnClientKeyRE = regexp.MustCompile(`(?is)<key>\s*(.*?)\s*</key>`)

func ExtractOVPNCerts(cfg string) CertBundle {
	return CertBundle{
		CA:   regexLines(ovpnCertRE, cfg),
		Cert: regexLines(ovpnClientCertRE, cfg),
		Key:  regexLines(ovpnClientKeyRE, cfg),
	}.Normalized()
}

func regexLines(re *regexp.Regexp, s string) []string {
	m := re.FindStringSubmatch(s)
	if len(m) < 2 {
		return nil
	}
	lines := strings.Split(strings.ReplaceAll(m[1], "\r\n", "\n"), "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}
