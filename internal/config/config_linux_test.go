//go:build linux

package config

import (
	"fmt"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// loadWithin runs Load(path) and fails the test if it does not return within
// a deadline: a FIFO read blocks until something writes to it.
func loadWithin(t *testing.T, path string) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { _, err := Load(path); done <- err }()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatalf("Load(%s) blocked", path)
		return nil
	}
}

// Task 11a's carry: a named pipe at port49d.yaml's path refuses the start
// rather than hanging it.
func TestLoadRefusesANamedPipeForItsConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "port49d.yaml")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := loadWithin(t, p); err == nil || !strings.Contains(err.Error(), "is not a regular file") {
		t.Fatalf("got %v", err)
	}
}

// And with no broker, where Load reads the inventory itself, a named pipe
// there refuses the start the same way.
func TestLoadRefusesANamedPipeForItsInventory(t *testing.T) {
	setKeyEnv(t)
	inv := filepath.Join(t.TempDir(), "inventory.yaml")
	if err := syscall.Mkfifo(inv, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := write(t, "port49d.yaml", fmt.Sprintf(sample, inv))
	if err := loadWithin(t, cfg); err == nil || !strings.Contains(err.Error(), "is not a regular file") {
		t.Fatalf("got %v", err)
	}
}
