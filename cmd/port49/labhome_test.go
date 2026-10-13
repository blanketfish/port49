package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Each lab broker gets a home of its own: the issued pairs, the kept CA
// bundles and the CRLs are named by host and port alone, so a broker on a
// port an earlier lab used would otherwise find that lab's pair, signed by
// that lab's CA, and its login would be refused "unknown certificate
// authority" (final review client I3).
func TestEachLabBrokerHasItsOwnHome(t *testing.T) {
	newLabBroker(t, time.Hour)
	first := os.Getenv("HOME")
	stale := filepath.Join(".port49", "issued", "127.0.0.1_1.pem")
	if err := os.MkdirAll(filepath.Dir(filepath.Join(first, stale)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(first, stale), []byte("an earlier lab's certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	newLabBroker(t, time.Hour)
	if home := os.Getenv("HOME"); home == first {
		t.Fatalf("the second lab shares the first's home %s", home)
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("HOME"), stale)); err == nil {
		t.Fatal("the second lab sees the first lab's issued pair")
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != filepath.Join(os.Getenv("HOME"), ".config") {
		t.Fatalf("XDG_CONFIG_HOME %s is not under the lab's home", xdg)
	}
}
