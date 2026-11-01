package port49d

import (
	"errors"
	"fmt"
	"github.com/blanketfish/port49/internal/broker"
	"os"
	"syscall"
	"time"
)

// errRevocationsLocked is a revocations file whose lock another process holds.
var errRevocationsLocked = errors.New("locked")

// revocationsLockWait is how long a starting port49d waits for an offline
// revoke or lift to finish before it exits. The offline command is a few
// seconds of work, and a start that exits at once would be restarted by its
// supervisor into the same wait, so it waits first and then says why it left.
var revocationsLockWait = 30 * time.Second

// persistDrainWait is how long a stopping port49d waits for a write of the
// revocations file that outlived its call before it gives up the lock anyway:
// a mount that never answers must not keep shutdown from finishing.
var persistDrainWait = 20 * time.Second

// daemonBrokerHook, set by a test, is handed the in-process broker once it is
// wired. Nil in production.
var daemonBrokerHook func(*broker.Broker)

// revocationsLockPath is the sidecar the file's lock lives on. The lock is on
// a file beside broker.revocations_file, never on it: every save renames a
// new file over it, and a rename swaps the inode a lock would be held on.
func revocationsLockPath(file string) string { return file + ".lock" }

// lockRevocations takes the exclusive lock on file's sidecar without waiting,
// and returns what releases it. It is errRevocationsLocked when another
// process holds it: a running or starting port49d (held for its whole life),
// or an offline revoke (held through its write). The kernel drops the lock if
// the holder dies, so a killed process never leaves one behind.
func lockRevocations(file string) (release func(), err error) {
	f, err := os.OpenFile(revocationsLockPath(file), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("the revocations lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errRevocationsLocked
		}
		return nil, fmt.Errorf("the revocations lock: %w", err)
	}
	return func() { f.Close() }, nil
}

// lockRevocationsWait is lockRevocations, retrying until wait has passed.
func lockRevocationsWait(file string, wait time.Duration) (func(), error) {
	deadline := time.Now().Add(wait)
	for {
		release, err := lockRevocations(file)
		if !errors.Is(err, errRevocationsLocked) || !time.Now().Before(deadline) {
			return release, err
		}
		time.Sleep(100 * time.Millisecond)
	}
}
