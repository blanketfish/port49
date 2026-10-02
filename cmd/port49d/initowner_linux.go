//go:build linux

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"strconv"

	"github.com/rhwendt/port49/internal/fence"
)

// initOwner refuses `port49d init-revocations` run by anyone but the owner
// of dir, the directory that holds broker.revocations_file (pre-flight I5).
// port49d runs as that user, and a 0600 file another user wrote, root above
// all, is one port49d cannot read: its first start would fail on
// "permission denied". The refusal names the owner, by name where the
// system knows it, and the line to run; it never chowns. A directory that
// is not there is left to fence.CheckDir to say so.
func initOwner(dir string) error {
	fi, err := os.Stat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	uid, ok := fence.FileOwner(fi)
	if !ok {
		return fmt.Errorf("the directory %s: cannot read its owner", dir)
	}
	euid := fence.Geteuid()
	if uint32(euid) == uid {
		return nil
	}
	who := strconv.FormatUint(uint64(uid), 10)
	if u, err := user.LookupId(who); err == nil {
		who = u.Username
	}
	return fmt.Errorf("the directory %s belongs to %s, and this runs as uid %d: port49d, running as %s, could not "+
		"read what this would write; run as %s, e.g. sudo -u %s port49d init-revocations", dir, who, euid, who, who, who)
}
