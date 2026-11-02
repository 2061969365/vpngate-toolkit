package vpngate

import (
	"reflect"
	"testing"
)

func TestMergeOverlap(t *testing.T) {
	left := Node{
		IP: "1.2.3.4", Country: "JP", FQDN: "left.example", Hostname: "h1",
		SSLPorts: []int{443}, UDPPort: 0, Score: 10, Sessions: 2,
		Source: "plugin", FirstSeen: 100, LastSeen: 200,
	}
	right := Node{
		IP: "1.2.3.4", Country: "JP", FQDN: "right.example", Hostname: "",
		SSLPorts: []int{80, 443}, L2TP: true, UDPPort: 1194, Score: 20, Sessions: 1,
		Source: "csv", FirstSeen: 150, LastSeen: 250,
	}
	out := Merge([]Node{left, right})
	if len(out) != 1 {
		t.Fatalf("len = %d", len(out))
	}
	got := out[0]
	if got.Source != "both" {
		t.Errorf("source = %q", got.Source)
	}
	if !reflect.DeepEqual(got.SSLPorts, []int{80, 443}) {
		t.Errorf("ports = %v", got.SSLPorts)
	}
	if got.Score != 20 || got.Sessions != 2 {
		t.Errorf("score/sessions = %d/%d", got.Score, got.Sessions)
	}
	if got.FQDN != "left.example" || got.Hostname != "h1" {
		t.Errorf("fqdn/hostname = %q/%q", got.FQDN, got.Hostname)
	}
	if !got.L2TP || got.UDPPort != 1194 {
		t.Errorf("l2tp/udp = %v/%d", got.L2TP, got.UDPPort)
	}
	if got.FirstSeen != 100 || got.LastSeen != 250 {
		t.Errorf("seen = %d/%d", got.FirstSeen, got.LastSeen)
	}
}

func TestMergeLeftAndRightOnly(t *testing.T) {
	left := Node{IP: "1.1.1.1", SSLPorts: []int{443}, Source: "plugin", FirstSeen: 10, LastSeen: 20}
	right := Node{IP: "2.2.2.2", SSLPorts: []int{8443}, Source: "csv", FirstSeen: 30, LastSeen: 40}
	out := Merge([]Node{right, left})
	if len(out) != 2 {
		t.Fatalf("len = %d", len(out))
	}
	if out[0].IP != "1.1.1.1" || out[0].Source != "plugin" {
		t.Errorf("out[0] = %+v", out[0])
	}
	if out[1].IP != "2.2.2.2" || out[1].Source != "csv" {
		t.Errorf("out[1] = %+v", out[1])
	}
}

func TestMergeDedupesSameSource(t *testing.T) {
	nodes := []Node{
		{IP: "1.2.3.4", SSLPorts: []int{443, 443}, Score: 1, Source: "plugin"},
		{IP: "1.2.3.4", SSLPorts: []int{80}, Score: 5, Source: "plugin"},
	}
	out := Merge(nodes)
	if len(out) != 1 {
		t.Fatalf("len = %d", len(out))
	}
	if out[0].Source != "plugin" {
		t.Errorf("source = %q", out[0].Source)
	}
	if !reflect.DeepEqual(out[0].SSLPorts, []int{80, 443}) {
		t.Errorf("ports = %v", out[0].SSLPorts)
	}
	if out[0].Score != 5 {
		t.Errorf("score = %d", out[0].Score)
	}
}

func TestMergeDropsInvalidIP(t *testing.T) {
	out := Merge([]Node{
		{IP: "not-an-ip", Source: "plugin"},
		{IP: "1.2.3.4", Source: "plugin"},
	})
	if len(out) != 1 || out[0].IP != "1.2.3.4" {
		t.Fatalf("out = %+v", out)
	}
}
