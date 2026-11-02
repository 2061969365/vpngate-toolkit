package vpngate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPluginSourceFetch(t *testing.T) {
	blob := fixtureBytes(t, "api_raw.bin")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ua := r.Header.Get("User-Agent"); ua != defaultUA {
			t.Errorf("User-Agent = %q", ua)
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(blob)
	}))
	defer srv.Close()

	now := time.Unix(123, 0)
	src := &PluginSource{
		Client:    srv.Client(),
		Timeout:   2 * time.Second,
		Mirrors:   "0",
		URLFormat: srv.URL + "/%c/%c",
		Now:       func() time.Time { return now },
	}
	nodes, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(nodes) != 200 {
		t.Fatalf("nodes = %d", len(nodes))
	}
	if nodes[0].Source != "plugin" || nodes[0].FirstSeen != 123 || nodes[0].LastSeen != 123 {
		t.Errorf("node0 = %+v", nodes[0])
	}
	if src.Name() != "plugin" {
		t.Errorf("Name = %q", src.Name())
	}
}

func TestPluginSourceAllMirrorsFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer srv.Close()
	src := &PluginSource{
		Client:    srv.Client(),
		Timeout:   time.Second,
		Mirrors:   "01",
		URLFormat: srv.URL + "/%c/%c",
	}
	if _, err := src.Fetch(context.Background()); err == nil {
		t.Fatal("expected error")
	}
}
