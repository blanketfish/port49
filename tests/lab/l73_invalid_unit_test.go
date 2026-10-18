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

func TestL73InvalidScreenMasksTheTacplusSecret(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PORT49_L73_INVALID_DIR", dir)
	e := &l73Env{l: &lab{p: platform{name: "x"}}}
	e.invalidScreen("device-3", "set system tacplus-server 172.100.100.1 port 300\n"+
		"set system tacplus-server 172.100.100.1 secret \"$9$abcdefgh1234\"\n"+
		"set system tacplus-server 172.100.100.1 authentication-key \"$9$zzzzyyyy5678\"\n")
	b, err := os.ReadFile(filepath.Join(dir, "l73-invalid-x-device-3.txt"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if strings.Contains(got, "$9$") || strings.Contains(got, "abcdefgh") || strings.Contains(got, "zzzzyyyy") ||
		!strings.Contains(got, "tacplus-server 172.100.100.1 port 300") {
		t.Fatal(got)
	}
}
