package vpngate

import (
	"os"
	"path/filepath"
	"testing"
)

func fixturePath(tb testing.TB, name string) string {
	tb.Helper()
	candidates := []string{
		filepath.Join("..", "fixtures", name),
		filepath.Join("fixtures", name),
		filepath.Join("..", "..", "fixtures", name),
	}
	for _, path := range candidates {
		if st, err := os.Stat(path); err == nil && !st.IsDir() {
			return path
		}
	}
	tb.Fatalf("fixture %s not found", name)
	return ""
}

func fixtureBytes(tb testing.TB, name string) []byte {
	tb.Helper()
	blob, err := os.ReadFile(fixturePath(tb, name))
	if err != nil {
		tb.Fatalf("read fixture %s: %v", name, err)
	}
	return blob
}
