//go:build linux

package lab

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
)

// labInheritedLock adopts the lock a parent (lab-regress) holds on path and
// passed as PORT49_LAB_LOCK_FD; ok is false when the variable is unset. The
// descriptor must be path itself (same device and inode). Flock with LOCK_NB
// on the same open file description succeeds when the parent holds it; on a
// description nobody holds it takes the lock instead, which is just as safe:
// either way this process now holds the lab, and a third process is refused.
func labInheritedLock(path string) (release func(), ok bool, err error) {
	v := os.Getenv("PORT49_LAB_LOCK_FD")
	if v == "" {
		return nil, false, nil
	}
	fd, err := strconv.Atoi(v)
	if err != nil || fd < 3 {
		return nil, true, fmt.Errorf("PORT49_LAB_LOCK_FD=%q is not an inherited descriptor", v)
	}
	var have, want syscall.Stat_t
	if err := syscall.Fstat(fd, &have); err != nil {
		return nil, true, fmt.Errorf("PORT49_LAB_LOCK_FD %d: %v", fd, err)
	}
	if err := syscall.Stat(path, &want); err != nil || have.Dev != want.Dev || have.Ino != want.Ino {
		return nil, true, fmt.Errorf("PORT49_LAB_LOCK_FD %d is not %s", fd, path)
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, true, fmt.Errorf("PORT49_LAB_LOCK_FD %d is not held: %v", fd, err)
	}
	return func() {}, true, nil // the parent releases it
}
