package vpngate

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidIPv4(t *testing.T) {
	valid := []string{"1.2.3.4", "255.255.255.255", "0.0.0.0"}
	invalid := []string{"", "1.2.3", "1.2.3.4.5", "999.1.1.1", "::1", "1.2.3.4:443"}
	for _, s := range valid {
		if !validIPv4(s) {
			t.Errorf("%q should be valid", s)
		}
	}
	for _, s := range invalid {
		if validIPv4(s) {
			t.Errorf("%q should be invalid", s)
		}
	}
}

func TestTCPPreFilter(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	filter := &TCPPreFilter{Timeout: time.Second}
	node := Node{IP: "127.0.0.1", SSLPorts: []int{port}}
	if err := filter.Check(context.Background(), node); err != nil {
		t.Fatalf("Check: %v", err)
	}
	ln.Close()
	<-done
	if err := filter.Check(context.Background(), node); err == nil {
		t.Fatal("expected connection error after listener close")
	}
}

func TestProbeMarksMissingPort(t *testing.T) {
	prober := &SingBoxBatchProber{}
	results, err := prober.Probe(context.Background(), []Node{{IP: "1.2.3.4"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].OK || results[0].Error != "no ssl port" {
		t.Fatalf("results = %+v", results)
	}
}

func TestProbeMarksInvalidIP(t *testing.T) {
	prober := &SingBoxBatchProber{}
	results, err := prober.Probe(context.Background(), []Node{{IP: "bad", SSLPorts: []int{443}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Error != "invalid IPv4" {
		t.Fatalf("results = %+v", results)
	}
}

func TestProbeStartFailureMarksBatch(t *testing.T) {
	prober := &SingBoxBatchProber{
		Binary:       filepath.Join(t.TempDir(), "missing-sing-box"),
		Certificates: testCerts(),
		BatchSize:    1,
		BasePort:     20000,
	}
	results, err := prober.Probe(context.Background(), []Node{{IP: "1.2.3.4", SSLPorts: []int{443}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].OK || !strings.Contains(results[0].Error, "sing-box start") {
		t.Fatalf("results = %+v", results)
	}
}

func TestBatchBasePort(t *testing.T) {
	p := &SingBoxBatchProber{BasePort: 20000, BatchSize: 40}
	cases := map[int]int{0: 20000, 40: 20040, 80: 20080, 160: 20160}
	for start, want := range cases {
		if got := p.batchBasePort(start); got != want {
			t.Errorf("batchBasePort(%d) = %d, want %d", start, got, want)
		}
	}
	def := &SingBoxBatchProber{}
	if got := def.batchBasePort(0); got != 20000 {
		t.Errorf("default batchBasePort(0) = %d", got)
	}
}

func TestRetryableProbeError(t *testing.T) {
	tests := []struct {
		err  error
		want bool
	}{
		{errors.New("socks5 connect failed: code 1"), true},
		{errors.New("socks5 connect failed: code 4"), true},
		{errors.New("socks5 connect failed: code 2"), false},
		{errors.New("socks5 dial: connection refused"), true},
		{errors.New("socks5 greeting: EOF"), true},
		{errors.New("socks5 reply version 4"), false},
		{errors.New("socks5 reply atyp 9"), false},
		{errors.New("x509: certificate signed by unknown authority"), false},
		{errors.New("tls: first record does not look like a TLS handshake"), true},
		{errors.New("http status 502"), false},
		{context.DeadlineExceeded, true},
	}
	for _, tt := range tests {
		if got := retryableProbeError(tt.err); got != tt.want {
			t.Errorf("retryableProbeError(%q) = %v, want %v", tt.err, got, tt.want)
		}
	}
}

func TestProbeWithRetrySucceedsAfterTransientFailures(t *testing.T) {
	calls := 0
	probe := func(ctx context.Context, addr string, timeout time.Duration) (string, error) {
		calls++
		if calls < 3 {
			return "", errors.New("socks5 connect failed: code 1")
		}
		return "9.9.9.9", nil
	}
	start := time.Now()
	egress, err := probeWithRetry(context.Background(), "127.0.0.1:20000", 3*time.Second, nil, probe)
	if err != nil {
		t.Fatalf("probeWithRetry: %v", err)
	}
	if egress != "9.9.9.9" || calls != 3 {
		t.Fatalf("egress=%q calls=%d", egress, calls)
	}
	if elapsed := time.Since(start); elapsed < 500*time.Millisecond {
		t.Errorf("expected retry delays, elapsed=%v", elapsed)
	}
}

func TestProbeWithRetryStopsOnFatalError(t *testing.T) {
	calls := 0
	probe := func(ctx context.Context, addr string, timeout time.Duration) (string, error) {
		calls++
		return "", errors.New("socks5 reply version 4")
	}
	_, err := probeWithRetry(context.Background(), "127.0.0.1:20000", 3*time.Second, nil, probe)
	if err == nil || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

func TestProbeWithRetryTimeout(t *testing.T) {
	calls := 0
	probe := func(ctx context.Context, addr string, timeout time.Duration) (string, error) {
		calls++
		return "", fmt.Errorf("socks5 connect failed: code 1")
	}
	_, err := probeWithRetry(context.Background(), "127.0.0.1:20000", 400*time.Millisecond, nil, probe)
	if err == nil || !strings.Contains(err.Error(), "timeout after") {
		t.Fatalf("err=%v", err)
	}
	if calls < 2 {
		t.Errorf("calls = %d, want >= 2", calls)
	}
}

func TestProbeWithRetryProcessExit(t *testing.T) {
	done := make(chan struct{})
	close(done)
	probe := func(ctx context.Context, addr string, timeout time.Duration) (string, error) {
		return "", errors.New("socks5 dial: connection refused")
	}
	_, err := probeWithRetry(context.Background(), "127.0.0.1:20000", 3*time.Second, done, probe)
	if err == nil || !strings.Contains(err.Error(), "sing-box exited") {
		t.Fatalf("err=%v", err)
	}
}
