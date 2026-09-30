//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// A refusal quotes what it found, and a policy file can hold anything a link
// aimed it at: every quoted value on the line is cut to 64 characters.
func TestARefusalQuotesAtMost64Characters(t *testing.T) {
	cfg := brokerConfig(t, minimalPolicy)
	long := strings.Repeat("x", 200)
	_, err := parseBundle(cfg, []byte(strings.Replace(minimalPolicy, "roles: [r]", "roles: ["+long+"]", 1)), cfg.Inventory)
	if err == nil {
		t.Fatal("a grant naming no role must not load")
	}
	if strings.Contains(err.Error(), strings.Repeat("x", 65)) || !strings.Contains(err.Error(), strings.Repeat("x", 64)) {
		t.Fatalf("the quoted role name is cut to 64 characters: %v", err)
	}
}

// At start an unsafe policy file refuses the start, as a policy that does not
// load does, naming the config key and the file.
func TestAnUnsafePolicyFileRefusesTheStart(t *testing.T) {
	cfg := brokerConfig(t, minimalPolicy)
	if err := os.Chmod(cfg.Broker.PolicyFile, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := buildWith(cfg); err == nil || !strings.Contains(err.Error(), "broker.policy_file "+cfg.Broker.PolicyFile) ||
		!strings.Contains(err.Error(), "writable by others") {
		t.Fatalf("%v", err)
	}
}

// With a broker nothing reads the inventory before the fence: a FIFO at its
// path is refused with the fence's words, and the start returns rather than
// hanging in a plain read (runExpectingRefusal's deadline).
func TestRunRefusesAnInventoryFIFOWithoutHanging(t *testing.T) {
	cfgPath := writeRunConfig(t, brokerConfig(t, minimalPolicy).Broker)
	inv := filepath.Join(filepath.Dir(cfgPath), "inventory.yaml")
	if err := os.Remove(inv); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(inv, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runExpectingRefusal(t, cfgPath); err == nil || !strings.Contains(err.Error(), "inventory_file "+inv) ||
		!strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("run: %v", err)
	}
}
