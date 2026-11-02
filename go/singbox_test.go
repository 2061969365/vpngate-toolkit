package vpngate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func testCerts() CertBundle {
	return CertBundle{
		CA:   []string{"-----BEGIN CERTIFICATE-----", "CA", "-----END CERTIFICATE-----"},
		Cert: []string{"-----BEGIN CERTIFICATE-----", "CERT", "-----END CERTIFICATE-----"},
		Key:  []string{"-----BEGIN PRIVATE KEY-----", "KEY", "-----END PRIVATE KEY-----"},
	}
}

func TestGenerateBatchConfigStructure(t *testing.T) {
	nodes := []Node{
		{IP: "1.2.3.4", Country: "JP", SSLPorts: []int{443}, Score: 1},
		{IP: "5.6.7.8", Country: "US", SSLPorts: []int{8443}, Score: 2},
	}
	data, err := GenerateBatchConfig(nodes, testCerts(), 20000)
	if err != nil {
		t.Fatalf("GenerateBatchConfig: %v", err)
	}
	var cfg singBoxConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if cfg.Log.Level != "error" {
		t.Errorf("log.level = %q", cfg.Log.Level)
	}
	if len(cfg.Inbounds) != 2 || len(cfg.Endpoints) != 2 || len(cfg.Route.Rules) != 2 {
		t.Fatalf("sizes = %d/%d/%d", len(cfg.Inbounds), len(cfg.Endpoints), len(cfg.Route.Rules))
	}
	if cfg.Inbounds[0].Tag != "in0" || cfg.Inbounds[0].ListenPort != 20000 || cfg.Inbounds[0].Listen != "127.0.0.1" {
		t.Errorf("inbound0 = %+v", cfg.Inbounds[0])
	}
	if cfg.Inbounds[1].Tag != "in1" || cfg.Inbounds[1].ListenPort != 20001 {
		t.Errorf("inbound1 = %+v", cfg.Inbounds[1])
	}
	ep := cfg.Endpoints[0]
	if ep.Type != "openvpn-client" || ep.Tag != "ep0" {
		t.Errorf("endpoint0 = %+v", ep)
	}
	if ep.Server != "1.2.3.4" || ep.ServerPort != 443 || ep.Network != "tcp" {
		t.Errorf("endpoint0 = %+v", ep)
	}
	if ep.System || ep.Username != "vpn" || ep.Password != "vpn" {
		t.Errorf("endpoint0 auth = %+v", ep)
	}
	if ep.TLS.RemoteCertificateTLS != "none" {
		t.Errorf("remote_certificate_tls = %q", ep.TLS.RemoteCertificateTLS)
	}
	if !reflect.DeepEqual(ep.TLS.Certificate, testCerts().CA) {
		t.Errorf("ca = %v", ep.TLS.Certificate)
	}
	if !reflect.DeepEqual(ep.DataCiphers, []string{"AES-128-CBC"}) || ep.Auth != "SHA1" {
		t.Errorf("ciphers/auth = %v/%q", ep.DataCiphers, ep.Auth)
	}
	if !ep.RouteNoPull || !ep.PingRestartDisabled {
		t.Errorf("flags = %v/%v", ep.RouteNoPull, ep.PingRestartDisabled)
	}
	if cfg.Route.Rules[0].Inbound != "in0" || cfg.Route.Rules[0].Outbound != "ep0" {
		t.Errorf("rule0 = %+v", cfg.Route.Rules[0])
	}
	if cfg.Route.Rules[1].Inbound != "in1" || cfg.Route.Rules[1].Outbound != "ep1" {
		t.Errorf("rule1 = %+v", cfg.Route.Rules[1])
	}
}

func TestGenerateBatchConfigErrors(t *testing.T) {
	certs := testCerts()
	if _, err := GenerateBatchConfig([]Node{{IP: "1.2.3.4", SSLPorts: []int{443}}}, CertBundle{}, 20000); err == nil {
		t.Error("expected missing certs error")
	}
	if _, err := GenerateBatchConfig([]Node{{IP: "1.2.3.4"}}, certs, 20000); err == nil {
		t.Error("expected missing port error")
	}
	if _, err := GenerateBatchConfig([]Node{{IP: "bad", SSLPorts: []int{443}}}, certs, 20000); err == nil {
		t.Error("expected invalid ip error")
	}
	if _, err := GenerateBatchConfig([]Node{{IP: "1.2.3.4", SSLPorts: []int{443}}}, certs, 0); err == nil {
		t.Error("expected base port error")
	}
	nodes := make([]Node, 2)
	for i := range nodes {
		nodes[i] = Node{IP: "1.2.3.4", SSLPorts: []int{443}}
	}
	if _, err := GenerateBatchConfig(nodes, certs, 65535); err == nil {
		t.Error("expected port overflow error")
	}
}

func TestWriteBatchConfigs(t *testing.T) {
	nodes := make([]Node, 5)
	for i := range nodes {
		nodes[i] = Node{IP: "1.2.3." + string(rune('1'+i)), SSLPorts: []int{443}}
	}
	dir := t.TempDir()
	paths, err := WriteBatchConfigs(nodes, testCerts(), 20000, 2, dir)
	if err != nil {
		t.Fatalf("WriteBatchConfigs: %v", err)
	}
	if len(paths) != 3 {
		t.Fatalf("paths = %v", paths)
	}
	wantSizes := []int{2, 2, 1}
	allPorts := map[int]bool{}
	for i, path := range paths {
		if filepath.Dir(path) != dir {
			t.Errorf("path %s not in %s", path, dir)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var cfg singBoxConfig
		if err := json.Unmarshal(data, &cfg); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if len(cfg.Endpoints) != wantSizes[i] {
			t.Errorf("batch %d endpoints = %d", i, len(cfg.Endpoints))
		}
		for j := range cfg.Inbounds {
			wantPort := 20000 + i*2 + j
			if cfg.Inbounds[j].ListenPort != wantPort {
				t.Errorf("batch %d inbound %d port = %d, want %d", i, j, cfg.Inbounds[j].ListenPort, wantPort)
			}
			if allPorts[cfg.Inbounds[j].ListenPort] {
				t.Errorf("duplicate listen port %d", cfg.Inbounds[j].ListenPort)
			}
			allPorts[cfg.Inbounds[j].ListenPort] = true
		}
	}
	if len(allPorts) != 5 {
		t.Errorf("unique ports = %d, want 5", len(allPorts))
	}
}
