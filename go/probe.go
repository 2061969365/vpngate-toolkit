package vpngate

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Result struct {
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Country   string `json:"country"`
	OK        bool   `json:"ok"`
	Egress    string `json:"egress"`
	ElapsedMS int64  `json:"elapsed_ms"`
	Error     string `json:"error"`
}

type SingBoxBatchProber struct {
	Binary         string
	Certificates   CertBundle
	BatchSize      int
	BasePort       int
	ProbeTimeout   time.Duration
	StartupTimeout time.Duration
	Workers        int
	PreFilter      *TCPPreFilter
	TempDir        string
}

type TCPPreFilter struct {
	Timeout time.Duration
	Workers int
}

type indexedNode struct {
	idx  int
	node Node
}

func (p *SingBoxBatchProber) Probe(ctx context.Context, nodes []Node) ([]Result, error) {
	results := make([]Result, len(nodes))
	targets := make([]indexedNode, 0, len(nodes))
	for i, node := range nodes {
		ports := normalizeSSLPorts(node.SSLPorts)
		port := 0
		if len(ports) > 0 {
			port = ports[0]
		}
		results[i] = Result{IP: node.IP, Port: port, Country: node.Country}
		switch {
		case !validIPv4(node.IP):
			results[i].Error = "invalid IPv4"
		case port <= 0:
			results[i].Error = "no ssl port"
		default:
			targets = append(targets, indexedNode{idx: i, node: node})
		}
	}
	if len(targets) == 0 {
		return results, nil
	}

	binary := p.Binary
	if binary == "" {
		found, err := exec.LookPath("sing-box")
		if err != nil {
			msg := "sing-box not found: " + err.Error()
			for _, t := range targets {
				results[t.idx].Error = msg
			}
			return results, fmt.Errorf("%s", msg)
		}
		binary = found
	}

	if p.PreFilter != nil {
		targets = p.prefilter(ctx, targets, results)
	}

	batchSize := p.batchSize()
	for start := 0; start < len(targets); start += batchSize {
		end := start + batchSize
		if end > len(targets) {
			end = len(targets)
		}
		if err := ctx.Err(); err != nil {
			for _, t := range targets[start:] {
				results[t.idx].Error = err.Error()
			}
			return results, err
		}
		p.probeBatch(ctx, binary, p.batchBasePort(start), targets[start:end], results)
	}
	return results, nil
}

func (p *SingBoxBatchProber) prefilter(ctx context.Context, targets []indexedNode, results []Result) []indexedNode {
	workers := p.workerLimit(len(targets))
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	var mu sync.Mutex
	survivors := make([]indexedNode, 0, len(targets))
	for _, t := range targets {
		wg.Add(1)
		go func(t indexedNode) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results[t.idx].Error = ctx.Err().Error()
				return
			}
			start := time.Now()
			err := p.PreFilter.Check(ctx, t.node)
			results[t.idx].ElapsedMS = time.Since(start).Milliseconds()
			if err != nil {
				results[t.idx].Error = "prefilter: " + err.Error()
				return
			}
			mu.Lock()
			survivors = append(survivors, t)
			mu.Unlock()
		}(t)
	}
	wg.Wait()
	stableByIdx(survivors)
	return survivors
}

func stableByIdx(targets []indexedNode) {
	for i := 1; i < len(targets); i++ {
		for j := i; j > 0 && targets[j].idx < targets[j-1].idx; j-- {
			targets[j], targets[j-1] = targets[j-1], targets[j]
		}
	}
}

func (p *SingBoxBatchProber) probeBatch(ctx context.Context, binary string, basePort int, batch []indexedNode, results []Result) {
	batchStart := time.Now()
	fail := func(msg string) {
		elapsed := time.Since(batchStart).Milliseconds()
		for _, t := range batch {
			results[t.idx].Error = msg
			results[t.idx].ElapsedMS = elapsed
		}
	}
	if len(batch) == 0 {
		return
	}

	certs := p.Certificates.Normalized()
	if basePort+len(batch)-1 > 65535 {
		fail(fmt.Sprintf("port range %d..%d exceeds 65535", basePort, basePort+len(batch)-1))
		return
	}
	batchNodes := make([]Node, len(batch))
	for i, t := range batch {
		batchNodes[i] = t.node
	}
	cfg, err := GenerateBatchConfig(batchNodes, certs, basePort)
	if err != nil {
		fail("config: " + err.Error())
		return
	}

	dir, err := os.MkdirTemp(p.TempDir, "vpngate-batch-")
	if err != nil {
		fail("temp dir: " + err.Error())
		return
	}
	defer os.RemoveAll(dir)

	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, append(cfg, '\n'), 0o600); err != nil {
		fail("write config: " + err.Error())
		return
	}
	logPath := filepath.Join(dir, "sing-box.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		fail("create log: " + err.Error())
		return
	}
	logClosed := false
	readLog := func() string {
		if !logClosed {
			logFile.Close()
			logClosed = true
		}
		return logTail(logPath)
	}

	cmd := exec.Command(binary, "run", "-c", cfgPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		readLog()
		fail("sing-box start: " + err.Error())
		return
	}

	exitCh := make(chan error, 1)
	processDone := make(chan struct{})
	go func() {
		exitCh <- cmd.Wait()
		close(processDone)
	}()
	exited := false
	var procErr error
	checkExit := func() bool {
		if exited {
			return true
		}
		select {
		case <-processDone:
			exited = true
			procErr = <-exitCh
			return true
		default:
			return false
		}
	}
	stop := func() {
		if !exited {
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			select {
			case <-processDone:
				procErr = <-exitCh
			case <-time.After(3 * time.Second):
			}
			exited = true
		}
	}
	defer func() {
		stop()
		if !logClosed {
			logFile.Close()
		}
	}()
	batchCtx, batchCancel := context.WithCancel(ctx)
	defer batchCancel()
	go func() {
		select {
		case <-processDone:
			batchCancel()
		case <-batchCtx.Done():
		}
	}()

	deadline := time.Now().Add(p.startupTimeout())
	for {
		if checkExit() {
			msg := "sing-box exited"
			if procErr != nil {
				msg += ": " + procErr.Error()
			}
			if tail := readLog(); tail != "" {
				msg += ": " + tail
			}
			fail(msg)
			return
		}
		if ctx.Err() != nil {
			stop()
			fail("context: " + ctx.Err().Error())
			return
		}
		ready := true
		for i := range batch {
			addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(basePort+i))
			conn, err := net.DialTimeout("tcp", addr, 150*time.Millisecond)
			if err != nil {
				ready = false
				break
			}
			conn.Close()
		}
		if ready {
			break
		}
		if time.Now().After(deadline) {
			stop()
			msg := "sing-box startup timeout"
			if tail := readLog(); tail != "" {
				msg += ": " + tail
			}
			fail(msg)
			return
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			stop()
			fail("context: " + ctx.Err().Error())
			return
		case <-timer.C:
		}
	}

	timeout := p.probeTimeout()
	workers := p.workerLimit(len(batch))
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i, t := range batch {
		wg.Add(1)
		go func(i int, t indexedNode) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-batchCtx.Done():
				select {
				case <-processDone:
					results[t.idx].Error = "sing-box exited"
				default:
					results[t.idx].Error = batchCtx.Err().Error()
				}
				return
			}
			start := time.Now()
			addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(basePort+i))
			egress, err := probeWithRetry(batchCtx, addr, timeout, processDone, socks5GetIPv4)
			res := &results[t.idx]
			res.ElapsedMS = time.Since(start).Milliseconds()
			if err != nil {
				res.Error = err.Error()
				return
			}
			res.OK = true
			res.Egress = egress
			res.Error = ""
		}(i, t)
	}
	wg.Wait()
}

func (p *SingBoxBatchProber) batchSize() int {
	if p.BatchSize > 0 {
		return p.BatchSize
	}
	return 32
}

func (p *SingBoxBatchProber) basePort() int {
	if p.BasePort > 0 {
		return p.BasePort
	}
	return 20000
}

func (p *SingBoxBatchProber) batchBasePort(start int) int {
	return p.basePort() + start
}

func (p *SingBoxBatchProber) probeTimeout() time.Duration {
	if p.ProbeTimeout > 0 {
		return p.ProbeTimeout
	}
	return 12 * time.Second
}

func (p *SingBoxBatchProber) startupTimeout() time.Duration {
	if p.StartupTimeout > 0 {
		return p.StartupTimeout
	}
	return 10 * time.Second
}

func (p *SingBoxBatchProber) workerLimit(n int) int {
	workers := p.Workers
	if workers <= 0 {
		workers = p.batchSize()
		if workers > 32 {
			workers = 32
		}
	}
	if workers > n {
		workers = n
	}
	if workers < 1 {
		workers = 1
	}
	return workers
}

func (f *TCPPreFilter) Check(ctx context.Context, node Node) error {
	if !validIPv4(node.IP) {
		return fmt.Errorf("invalid IPv4 %q", node.IP)
	}
	ports := normalizeSSLPorts(node.SSLPorts)
	if len(ports) == 0 {
		return fmt.Errorf("no ssl port")
	}
	timeout := f.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(node.IP, strconv.Itoa(ports[0])))
	if err != nil {
		return err
	}
	return conn.Close()
}

const attemptTimeout = 3 * time.Second

func probeWithRetry(ctx context.Context, addr string, budget time.Duration, processDone <-chan struct{}, probe func(context.Context, string, time.Duration) (string, error)) (string, error) {
	if budget <= 0 {
		budget = 12 * time.Second
	}
	deadline := time.Now().Add(budget)
	var lastErr error
	attempts := 0
	for {
		select {
		case <-processDone:
			return "", errors.New("sing-box exited")
		default:
		}
		if err := ctx.Err(); err != nil {
			return "", err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		attemptBudget := attemptTimeout
		if remaining < attemptBudget {
			attemptBudget = remaining
		}
		pctx, cancel := context.WithTimeout(ctx, attemptBudget)
		egress, err := probe(pctx, addr, attemptBudget)
		cancel()
		attempts++
		if err == nil {
			return egress, nil
		}
		select {
		case <-processDone:
			return "", errors.New("sing-box exited")
		default:
		}
		lastErr = err
		if !retryableProbeError(err) {
			return "", err
		}
		delay := retryDelay(attempts)
		if time.Until(deadline) <= delay {
			break
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			select {
			case <-processDone:
				return "", errors.New("sing-box exited")
			default:
			}
			return "", ctx.Err()
		case <-processDone:
			timer.Stop()
			return "", errors.New("sing-box exited")
		case <-timer.C:
		}
	}
	if lastErr == nil {
		lastErr = context.DeadlineExceeded
	}
	return "", fmt.Errorf("timeout after %d attempt(s): %w", attempts, lastErr)
}

func retryDelay(attempt int) time.Duration {
	return 250*time.Millisecond + time.Duration(attempt%3)*50*time.Millisecond
}

func retryableProbeError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "x509:"), strings.Contains(s, "certificate"):
		return false
	case strings.Contains(s, "socks5 reply version"), strings.Contains(s, "socks5 reply atyp"):
		return false
	case strings.HasPrefix(s, "http status "):
		return false
	case strings.Contains(s, "socks5 connect failed: code 1"),
		strings.Contains(s, "socks5 connect failed: code 4"):
		return true
	case strings.HasPrefix(s, "socks5 connect failed: code "):
		return false
	case strings.HasPrefix(s, "socks5 dial:"),
		strings.HasPrefix(s, "socks5 greeting:"),
		strings.HasPrefix(s, "socks5 connect:"),
		strings.HasPrefix(s, "socks5 reply:"),
		strings.HasPrefix(s, "tls:"),
		strings.HasPrefix(s, "http "),
		strings.HasPrefix(s, "invalid egress"):
		return true
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func socks5GetIPv4(ctx context.Context, socksAddr string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = 12 * time.Second
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", socksAddr)
	if err != nil {
		return "", fmt.Errorf("socks5 dial: %w", err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}

	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return "", fmt.Errorf("socks5 greeting: %w", err)
	}
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		return "", fmt.Errorf("socks5 greeting: %w", err)
	}
	if greeting[0] != 5 || greeting[1] != 0 {
		return "", fmt.Errorf("socks5 auth rejected: %v", greeting)
	}

	const host = "api.ipify.org"
	const port = 443
	req := make([]byte, 0, 7+len(host))
	req = append(req, 5, 1, 0, 3, byte(len(host)))
	req = append(req, host...)
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], port)
	req = append(req, portBuf[:]...)
	if _, err := conn.Write(req); err != nil {
		return "", fmt.Errorf("socks5 connect: %w", err)
	}
	if err := readSOCKS5Reply(conn); err != nil {
		return "", err
	}

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return "", fmt.Errorf("tls: %w", err)
	}
	httpReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n", host)
	if _, err := io.WriteString(tlsConn, httpReq); err != nil {
		return "", fmt.Errorf("http write: %w", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	if err != nil {
		return "", fmt.Errorf("http read: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return "", fmt.Errorf("http body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("http status %d", resp.StatusCode)
	}
	egress := strings.TrimSpace(string(body))
	if !validIPv4(egress) {
		return "", fmt.Errorf("invalid egress %q", egress)
	}
	return egress, nil
}

func readSOCKS5Reply(conn net.Conn) error {
	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return fmt.Errorf("socks5 reply: %w", err)
	}
	if head[0] != 5 {
		return fmt.Errorf("socks5 reply version %d", head[0])
	}
	if head[1] != 0 {
		return fmt.Errorf("socks5 connect failed: code %d", head[1])
	}
	var n int
	switch head[3] {
	case 1:
		n = 4
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return fmt.Errorf("socks5 reply: %w", err)
		}
		n = int(l[0])
	case 4:
		n = 16
	default:
		return fmt.Errorf("socks5 reply atyp %d", head[3])
	}
	if _, err := io.CopyN(io.Discard, conn, int64(n)+2); err != nil {
		return fmt.Errorf("socks5 reply: %w", err)
	}
	return nil
}

var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

func logTail(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(ansiRE.ReplaceAllString(string(b), ""))
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 400 {
		s = s[len(s)-400:]
	}
	return s
}
