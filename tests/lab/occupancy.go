package lab

import (
	"fmt"
	"os"
	"strings"
	"syscall"
)

// labLockPath is the lab's single-occupant lock: one containerlab topology,
// one port49d on the bridge's port 49 and 300. A run that deploys a device
// takes it first and holds it to the end; a second run is refused at once,
// told who holds it, rather than tearing down the first run's device.
const labLockPath = "/tmp/port49-lab.lock"

// labOccupy takes the exclusive, non-blocking lock on path and writes who
// into it. release lets it go; the lock also dies with the process.
func labOccupy(path, who string) (release func(), err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		holder, _ := os.ReadFile(path)
		f.Close()
		return nil, fmt.Errorf("the lab is occupied: %s holds %s (%v); wait for it, never kill it",
			strings.TrimSpace(string(holder)), path, err)
	}
	if err := f.Truncate(0); err == nil {
		_, _ = f.WriteAt([]byte(who+"\n"), 0)
	}
	return func() { f.Close() }, nil
}

// labHeld is the run's lock. A package variable keeps the file reachable:
// an unreachable *os.File is closed by its finalizer, and the flock with it.
var labHeld func()

// labOccupyForRun takes the lock for the rest of the process. TestMain lets
// it go after teardown (labRelease), so the next run never deploys beside a
// topology that containerlab is still destroying; a signal's exit lets it go
// with the process.
func labOccupyForRun(path, who string) error {
	if labHeld != nil {
		return nil
	}
	release, err := labOccupy(path, who)
	if err != nil {
		return err
	}
	labHeld = release
	return nil
}

// labRelease lets go of the run's lock, if this process holds it.
func labRelease() {
	if labHeld != nil {
		labHeld()
		labHeld = nil
	}
}
