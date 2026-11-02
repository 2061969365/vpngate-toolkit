package vpngate

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestWriteNodesJSONDeterministic(t *testing.T) {
	nodes := []Node{
		{IP: "2.2.2.2", Country: "US", SSLPorts: []int{443, 80, 443}, Source: "csv"},
		{IP: "1.1.1.1", Country: "JP", Source: "plugin"},
	}
	var buf bytes.Buffer
	if err := WriteNodesJSON(&buf, nodes); err != nil {
		t.Fatal(err)
	}
	want := `[{"ip":"1.1.1.1","country":"JP","fqdn":"","hostname":"","ssl_ports":[],"l2tp":false,"udp_port":0,"score":0,"sessions":0,"source":"plugin","first_seen":0,"last_seen":0},` +
		`{"ip":"2.2.2.2","country":"US","fqdn":"","hostname":"","ssl_ports":[80,443],"l2tp":false,"udp_port":0,"score":0,"sessions":0,"source":"csv","first_seen":0,"last_seen":0}]` + "\n"
	if buf.String() != want {
		t.Fatalf("json mismatch\n got: %s\nwant: %s", buf.String(), want)
	}
}

func TestWriteNodesJSONStableForDuplicateIPs(t *testing.T) {
	nodes := []Node{
		{IP: "1.1.1.1", Country: "AA", Source: "plugin"},
		{IP: "2.2.2.2", Country: "BB", Source: "plugin"},
		{IP: "1.1.1.1", Country: "CC", Source: "plugin"},
	}
	var buf bytes.Buffer
	if err := WriteNodesJSON(&buf, nodes); err != nil {
		t.Fatal(err)
	}
	var out []Node
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 3 || out[0].Country != "AA" || out[1].Country != "CC" || out[2].Country != "BB" {
		t.Fatalf("out = %+v", out)
	}
}

func TestCSVExporter(t *testing.T) {
	var buf bytes.Buffer
	nodes := []Node{{IP: "1.2.3.4", Country: "JP", SSLPorts: []int{443}}}
	if err := (CSVExporter{}).Export(&buf, nodes); err != nil {
		t.Fatal(err)
	}
	want := "ip,port,country,egress,elapsed_ms,ok\n1.2.3.4,443,JP,,0,false\n"
	if buf.String() != want {
		t.Fatalf("csv = %q", buf.String())
	}

	buf.Reset()
	results := []Result{{IP: "1.2.3.4", Port: 443, Country: "JP", OK: true, Egress: "9.9.9.9", ElapsedMS: 123}}
	if err := (CSVExporter{}).ExportResults(&buf, results); err != nil {
		t.Fatal(err)
	}
	want = "ip,port,country,egress,elapsed_ms,ok\n1.2.3.4,443,JP,9.9.9.9,123,true\n"
	if buf.String() != want {
		t.Fatalf("csv results = %q", buf.String())
	}
}

func TestPlainExporter(t *testing.T) {
	var buf bytes.Buffer
	nodes := []Node{
		{IP: "1.2.3.4", SSLPorts: []int{443}},
		{IP: "5.6.7.8"},
	}
	if err := (PlainExporter{}).Export(&buf, nodes); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "1.2.3.4:443\n" {
		t.Fatalf("plain = %q", buf.String())
	}
}

func TestSingBoxExporterSelectsBestNode(t *testing.T) {
	var buf bytes.Buffer
	nodes := []Node{
		{IP: "1.1.1.1", SSLPorts: []int{443}, Score: 10},
		{IP: "2.2.2.2", SSLPorts: []int{8443}, Score: 99},
		{IP: "3.3.3.3", Score: 1000},
	}
	exp := SingBoxExporter{Certificates: testCerts()}
	if err := exp.Export(&buf, nodes); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"server":"2.2.2.2"`) || !strings.Contains(buf.String(), `"server_port":8443`) {
		t.Fatalf("config = %s", buf.String())
	}
}

func TestSingBoxExporterSelectsFastestResult(t *testing.T) {
	var buf bytes.Buffer
	results := []Result{
		{IP: "1.1.1.1", Port: 443, OK: true, ElapsedMS: 500},
		{IP: "2.2.2.2", Port: 443, OK: true, ElapsedMS: 100},
	}
	exp := SingBoxExporter{Certificates: testCerts()}
	if err := exp.ExportResults(&buf, results); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"server":"2.2.2.2"`) {
		t.Fatalf("config = %s", buf.String())
	}
}
