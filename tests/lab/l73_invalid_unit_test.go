//go:build lab

package lab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestL73InvalidScreenDropsPEM(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PORT49_L73_INVALID_DIR", dir)
	e := &l73Env{l: &lab{p: platform{name: "x"}}}
	e.invalidScreen("device-2", "Issuer: CN=L73\n-----BEGIN CERTIFICATE-----\nZZZZ\n-----END CERTIFICATE-----\n")
	b, err := os.ReadFile(filepath.Join(dir, "l73-invalid-x-device-2.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "ZZZZ") || !strings.Contains(string(b), "Issuer: CN=L73") {
		t.Fatal(string(b))
	}
}
