//go:build linux

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestHoldLockRefusesASecondHolderAndNamesTheFirst(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lab.lock") // never the real /tmp/port49-lab.lock
	f, err := holdLock(path, "first holder")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := holdLock(path, "second"); err == nil || !strings.Contains(err.Error(), "first holder") {
		t.Fatalf("a held lab must be refused, naming its holder: %v", err)
	}
}
