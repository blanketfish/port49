//go:build !linux

package main

import (
	"os"
	"syscall"
)

// askpassPath is the path ssh is told to run as SSH_ASKPASS: port49's own file.
func askpassPath(self string) string { return self }

// sshParent is the process that ran this askpass, held so that a signal can
// reach only it.
type sshParent struct {
	pid int
}

func watchParent() sshParent { return sshParent{pid: os.Getppid()} }

// terminate sends SIGTERM to the parent, and only while it is still this
// process's parent: once it has exited and this has been adopted, Getppid no
// longer names it.
func (p sshParent) terminate() {
	if p.pid > 1 && os.Getppid() == p.pid {
		_ = syscall.Kill(p.pid, syscall.SIGTERM)
	}
}
