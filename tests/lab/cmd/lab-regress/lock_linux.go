//go:build linux

package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"
)

// holdLock takes path exclusively and without waiting, as tests/lab's
// labOccupy does, writes who into it, and returns the open file: its
// descriptor is each child's fd 3.
func holdLock(path, who string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		holder, _ := os.ReadFile(path)
		f.Close()
		return nil, fmt.Errorf("the lab is occupied: %s holds %s; wait for it, never kill it", strings.TrimSpace(string(holder)), path)
	}
	_ = f.Truncate(0)
	_, _ = f.WriteAt([]byte(who+"\n"), 0)
	return f, nil
}
