package vpngate

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseSSLPorts(t *testing.T) {
	got := ParseSSLPorts("443, 443 80,abc,0,70000,8443")
	if !reflect.DeepEqual(got, []int{80, 443, 8443}) {
		t.Fatalf("ports = %v", got)
	}
	if got := ParseSSLPorts(""); len(got) != 0 || got == nil {
		t.Fatalf("empty ports = %#v", got)
	}
}

func TestParseOVPNPorts(t *testing.T) {
	cfg := strings.Join([]string{
		"client",
		"remote 1.2.3.4 443",
		"remote 5.6.7.8 1194 tcp",
		"remote 1.2.3.4 443",
		"# remote 9.9.9.9 1234",
	}, "\r\n")
	got := ParseOVPNPorts(cfg)
	if !reflect.DeepEqual(got, []int{443, 1194}) {
		t.Fatalf("ports = %v", got)
	}
}

func TestCSVSourceParsesRowsAndCerts(t *testing.T) {
	ovpn := strings.Join([]string{
		"client",
		"dev tun",
		"proto tcp",
		"remote 1.2.3.4 443",
		"<ca>",
		"-----BEGIN CERTIFICATE-----",
		"CA",
		"-----END CERTIFICATE-----",
		"</ca>",
		"<cert>",
		"-----BEGIN CERTIFICATE-----",
		"CERT",
		"-----END CERTIFICATE-----",
		"</cert>",
		"<key>",
		"-----BEGIN PRIVATE KEY-----",
		"KEY",
		"-----END PRIVATE KEY-----",
		"</key>",
	}, "\n")
	encoded := base64.StdEncoding.EncodeToString([]byte(ovpn))
	body := fmt.Sprintf("*\n#HostName,IP,Score,NumVpnSessions,CountryShort,OpenVPN_ConfigData_Base64\n"+
		"node-a,1.2.3.4,100,3,JP,%s\n"+
		"bad,999.1.1.1,1,1,US,%s\n"+
		"*\n", encoded, encoded)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ua := r.Header.Get("User-Agent"); ua != defaultUA {
			t.Errorf("User-Agent = %q", ua)
		}
		w.Header().Set("Content-Type", "text/csv")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	src := &CSVSource{URL: srv.URL, Client: srv.Client(), Timeout: 2 * time.Second}
	nodes, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("nodes = %d", len(nodes))
	}
	n := nodes[0]
	if n.IP != "1.2.3.4" || n.Hostname != "node-a" || n.Country != "JP" {
		t.Errorf("node = %+v", n)
	}
	if !reflect.DeepEqual(n.SSLPorts, []int{443}) {
		t.Errorf("ports = %v", n.SSLPorts)
	}
	if n.Score != 100 || n.Sessions != 3 || n.Source != "csv" {
		t.Errorf("node = %+v", n)
	}
	if src.ParseErrors != 1 {
		t.Errorf("ParseErrors = %d", src.ParseErrors)
	}
	if !src.Certificates.Complete() {
		t.Fatalf("certs incomplete: %+v", src.Certificates)
	}
	if !reflect.DeepEqual(src.Certificates.CA, []string{
		"-----BEGIN CERTIFICATE-----", "CA", "-----END CERTIFICATE-----",
	}) {
		t.Errorf("CA = %v", src.Certificates.CA)
	}
}

func TestCSVSourceRejectsMissingHeader(t *testing.T) {
	_, _, _, err := parseCSVNodes([]byte("1.2.3.4,foo\n"), time.Now().Unix())
	if err == nil {
		t.Fatal("expected header error")
	}
}

func TestDecodeBase64Loose(t *testing.T) {
	got, err := decodeBase64Loose("aGVs bG8")
	if err != nil || string(got) != "hello" {
		t.Fatalf("got %q, %v", got, err)
	}
}
