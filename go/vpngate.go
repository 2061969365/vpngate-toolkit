package vpngate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const Version = "1.0.0"

type Node struct {
	IP        string `json:"ip"`
	Country   string `json:"country"`
	FQDN      string `json:"fqdn"`
	Hostname  string `json:"hostname"`
	SSLPorts  []int  `json:"ssl_ports"`
	L2TP      bool   `json:"l2tp"`
	UDPPort   uint32 `json:"udp_port"`
	Score     uint32 `json:"score"`
	Sessions  uint32 `json:"sessions"`
	Source    string `json:"source"`
	FirstSeen int64  `json:"first_seen"`
	LastSeen  int64  `json:"last_seen"`
}

type Source interface {
	Name() string
	Fetch(ctx context.Context) ([]Node, error)
}

type Prober interface {
	Probe(ctx context.Context, nodes []Node) ([]Result, error)
}

type Exporter interface {
	Format() string
	Export(w io.Writer, nodes []Node) error
}

type CertBundle struct {
	CA   []string `json:"ca"`
	Cert []string `json:"cert"`
	Key  []string `json:"key"`
}

func (c CertBundle) Complete() bool {
	return len(c.CA) > 0 && len(c.Cert) > 0 && len(c.Key) > 0
}

func (c CertBundle) Normalized() CertBundle {
	return CertBundle{
		CA:   cleanLines(c.CA),
		Cert: cleanLines(c.Cert),
		Key:  cleanLines(c.Key),
	}
}

func cleanLines(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func validIPv4(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil && strings.Count(s, ".") == 3 && !strings.Contains(s, ":")
}

func normalizeSSLPorts(ports []int) []int {
	out := make([]int, 0, len(ports))
	for _, p := range ports {
		if p > 0 && p <= 65535 {
			out = append(out, p)
		}
	}
	sort.Ints(out)
	n := 0
	for _, p := range out {
		if n == 0 || out[n-1] != p {
			out[n] = p
			n++
		}
	}
	return out[:n]
}

func normalizeNode(n Node) Node {
	n.SSLPorts = normalizeSSLPorts(n.SSLPorts)
	return n
}

func WriteNodesJSON(w io.Writer, nodes []Node) error {
	sorted := make([]Node, len(nodes))
	for i, n := range nodes {
		sorted[i] = normalizeNode(n)
	}
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].IP < sorted[j].IP })
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "")
	return enc.Encode(sorted)
}

func ReadNodes(r io.Reader) ([]Node, error) {
	dec := json.NewDecoder(r)
	var nodes []Node
	if err := dec.Decode(&nodes); err != nil {
		return nil, err
	}
	for i := range nodes {
		nodes[i] = normalizeNode(nodes[i])
	}
	return nodes, nil
}

func LoadNodesFile(path string) ([]Node, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ReadNodes(f)
}

func SaveNodesFile(path string, nodes []Node) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := WriteNodesJSON(f, nodes); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func LoadCertsFile(path string) (CertBundle, error) {
	f, err := os.Open(path)
	if err != nil {
		return CertBundle{}, err
	}
	defer f.Close()
	var c CertBundle
	if err := json.NewDecoder(f).Decode(&c); err != nil {
		return CertBundle{}, err
	}
	return c.Normalized(), nil
}

func SaveCertsFile(path string, c CertBundle) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(c.Normalized()); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func WriteResultsJSON(w io.Writer, results []Result) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "")
	return enc.Encode(results)
}

func ReadResults(r io.Reader) ([]Result, error) {
	var results []Result
	err := json.NewDecoder(r).Decode(&results)
	return results, err
}

func ValidateNodes(nodes []Node) error {
	for i, n := range nodes {
		if !validIPv4(n.IP) {
			return fmt.Errorf("node %d: invalid IPv4 %q", i, n.IP)
		}
	}
	return nil
}
