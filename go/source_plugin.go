package vpngate

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	pluginMirrors  = "0123456789abcdefxyz"
	pluginURL      = "http://x%c.x%c.client.api.vpngate2.jp/api/"
	defaultUA      = "Mozilla/5.0"
	defaultTimeout = 30 * time.Second
	maxDATSize     = 16 << 20
)

type PluginSource struct {
	Client    *http.Client
	Timeout   time.Duration
	UserAgent string
	Now       func() time.Time
	Mirrors   string
	URLFormat string
}

func (s *PluginSource) Name() string { return "plugin" }

func (s *PluginSource) Fetch(ctx context.Context) ([]Node, error) {
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

	mirrors := s.Mirrors
	if mirrors == "" {
		mirrors = pluginMirrors
	}
	format := s.URLFormat
	if format == "" {
		format = pluginURL
	}

	var lastErr error
	for _, a := range mirrors {
		url := fmt.Sprintf(format, a, a)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", ua)
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxDATSize))
		resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
			continue
		}
		if !bytes.HasPrefix(body, []byte(datMagic)) {
			lastErr = fmt.Errorf("%s: not a VPNGate DAT", url)
			continue
		}
		records, _, err := DecodeDAT(body)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", url, err)
			continue
		}
		now := time.Now
		if s.Now != nil {
			now = s.Now
		}
		seen := now().Unix()
		return records.Nodes("plugin", seen, seen), nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no mirrors available")
	}
	return nil, fmt.Errorf("plugin: all mirrors failed: %w", lastErr)
}
