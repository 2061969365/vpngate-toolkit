package vpngate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type singBoxConfig struct {
	Log       singBoxLog        `json:"log"`
	Inbounds  []singBoxInbound  `json:"inbounds"`
	Endpoints []singBoxEndpoint `json:"endpoints"`
	Route     singBoxRoute      `json:"route"`
}

type singBoxLog struct {
	Level string `json:"level"`
}

type singBoxInbound struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Listen     string `json:"listen"`
	ListenPort int    `json:"listen_port"`
}

type singBoxEndpoint struct {
	Type                string     `json:"type"`
	Tag                 string     `json:"tag"`
	Server              string     `json:"server"`
	ServerPort          int        `json:"server_port"`
	Network             string     `json:"network"`
	System              bool       `json:"system"`
	Username            string     `json:"username"`
	Password            string     `json:"password"`
	TLS                 singBoxTLS `json:"tls"`
	DataCiphers         []string   `json:"data_ciphers"`
	Auth                string     `json:"auth"`
	RouteNoPull         bool       `json:"route_no_pull"`
	PingRestartDisabled bool       `json:"ping_restart_disabled"`
}

type singBoxTLS struct {
	Certificate          []string `json:"certificate"`
	ClientCertificate    []string `json:"client_certificate"`
	ClientKey            []string `json:"client_key"`
	RemoteCertificateTLS string   `json:"remote_certificate_tls"`
}

type singBoxRoute struct {
	Rules []singBoxRule `json:"rules"`
}

type singBoxRule struct {
	Inbound  string `json:"inbound"`
	Outbound string `json:"outbound"`
}

func GenerateConfig(nodes []Node, certs CertBundle, basePort int) ([]byte, error) {
	return GenerateBatchConfig(nodes, certs, basePort)
}

func GenerateBatchConfig(nodes []Node, certs CertBundle, basePort int) ([]byte, error) {
	if basePort <= 0 || basePort > 65535 {
		return nil, fmt.Errorf("sing-box: invalid base port %d", basePort)
	}
	if len(nodes) > 0 && basePort+len(nodes)-1 > 65535 {
		return nil, fmt.Errorf("sing-box: port range %d..%d exceeds 65535", basePort, basePort+len(nodes)-1)
	}
	if len(nodes) > 0 {
		certs = certs.Normalized()
		if !certs.Complete() {
			return nil, fmt.Errorf("sing-box: ca/cert/key are required")
		}
	}

	cfg := singBoxConfig{
		Log:       singBoxLog{Level: "error"},
		Inbounds:  make([]singBoxInbound, 0, len(nodes)),
		Endpoints: make([]singBoxEndpoint, 0, len(nodes)),
		Route:     singBoxRoute{Rules: make([]singBoxRule, 0, len(nodes))},
	}
	for i, node := range nodes {
		if !validIPv4(node.IP) {
			return nil, fmt.Errorf("sing-box: node %d has invalid IPv4 %q", i, node.IP)
		}
		if len(node.SSLPorts) == 0 {
			return nil, fmt.Errorf("sing-box: node %s has no ssl port", node.IP)
		}
		ports := normalizeSSLPorts(node.SSLPorts)
		if len(ports) == 0 {
			return nil, fmt.Errorf("sing-box: node %s has no valid ssl port", node.IP)
		}
		port := basePort + i
		inTag := fmt.Sprintf("in%d", i)
		epTag := fmt.Sprintf("ep%d", i)
		cfg.Inbounds = append(cfg.Inbounds, singBoxInbound{
			Type:       "mixed",
			Tag:        inTag,
			Listen:     "127.0.0.1",
			ListenPort: port,
		})
		cfg.Endpoints = append(cfg.Endpoints, singBoxEndpoint{
			Type:       "openvpn-client",
			Tag:        epTag,
			Server:     node.IP,
			ServerPort: ports[0],
			Network:    "tcp",
			System:     false,
			Username:   "vpn",
			Password:   "vpn",
			TLS: singBoxTLS{
				Certificate:          certs.CA,
				ClientCertificate:    certs.Cert,
				ClientKey:            certs.Key,
				RemoteCertificateTLS: "none",
			},
			DataCiphers:         []string{"AES-128-CBC"},
			Auth:                "SHA1",
			RouteNoPull:         true,
			PingRestartDisabled: true,
		})
		cfg.Route.Rules = append(cfg.Route.Rules, singBoxRule{Inbound: inTag, Outbound: epTag})
	}
	return json.Marshal(cfg)
}

func WriteBatchConfigs(nodes []Node, certs CertBundle, basePort, batchSize int, outDir string) ([]string, error) {
	if batchSize <= 0 {
		return nil, fmt.Errorf("sing-box: invalid batch size %d", batchSize)
	}
	if outDir == "" {
		return nil, fmt.Errorf("sing-box: output directory is required")
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, err
	}
	var paths []string
	for start := 0; start < len(nodes); start += batchSize {
		end := start + batchSize
		if end > len(nodes) {
			end = len(nodes)
		}
		base := basePort + len(paths)*batchSize
		data, err := GenerateBatchConfig(nodes[start:end], certs, base)
		if err != nil {
			return paths, fmt.Errorf("batch %d: %w", len(paths), err)
		}
		path := filepath.Join(outDir, fmt.Sprintf("singbox-batch-%d.json", len(paths)))
		data = append(data, '\n')
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return paths, err
		}
		paths = append(paths, path)
	}
	return paths, nil
}
