//go:build linux

package port49d

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"github.com/rhwendt/port49/internal/fence"
)

// initOwner refuses `port49d init-revocations` run by anyone but the owner
// of dir, the directory that holds broker.revocations_file (pre-flight I5).
// port49d runs as that user, and a 0600 file another user wrote, root above
// all, is one port49d cannot read: its first start would fail on
// "permission denied". The refusal names the owner, by name where the
// system knows it, and the line to run, with cfgPath, the config init read;
// it never chowns. A directory root owns, asked by anyone else, is most
// often a bare mount point whose volume did not mount, and is never one a
// port49d not running as root can write the file into, so that refusal
// names the mount and the owner the directory needs, never "sudo -u root"
// (task 2 review I1). A directory that is not there is left to
// fence.CheckDir to say so.
func initOwner(dir, cfgPath string) error {
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
	if uid == 0 {
		return fmt.Errorf("the directory %s belongs to root, and this runs as uid %d: if a volume should be mounted "+
			"there, it is not; mount it. Otherwise the directory must belong to the user port49d runs as, which "+
			"writes the file there after every revocation; make it so, then run port49d init-revocations --config %s "+
			"as that user", dir, euid, cfgPath)
	}
	who := strconv.FormatUint(uint64(uid), 10)
	if u, err := user.LookupId(who); err == nil {
		who = u.Username
	}
	return fmt.Errorf("the directory %s belongs to %s, and this runs as uid %d: port49d, running as %s, could not "+
		"read what this would write; run as %s, e.g. sudo -u %s port49d init-revocations --config %s", dir, who, euid,
		who, who, who, cfgPath)
}

// offlineOwner refuses `port49d revoke --offline` run by a uid that does not
// own broker.revocations_file, or the directory for a file not yet there, and
// changes nothing. Run as root, the write would leave the file and its .lock
// root's, 0600, and the port49d that runs as another user could not start:
// a break-glass that leaves the service down. The one line names the owner and
// the command to run as it.
func offlineOwner(file, cfgPath string) error {
	abs, err := filepath.Abs(file)
	if err != nil {
		return err
	}
	what := "broker.revocations_file " + abs
	fi, err := os.Stat(abs)
	if errors.Is(err, fs.ErrNotExist) {
		what = "the directory " + filepath.Dir(abs) + " of broker.revocations_file"
		fi, err = os.Stat(filepath.Dir(abs))
	}
	if errors.Is(err, fs.ErrNotExist) {
		return nil // fence.CheckDir says so
	}
	if err != nil {
		return err
	}
	uid, ok := fence.FileOwner(fi)
	if !ok {
		return fmt.Errorf("%s: cannot read its owner", what)
	}
	euid := fence.Geteuid()
	if uint32(euid) == uid {
		return nil
	}
	who := strconv.FormatUint(uint64(uid), 10)
	if u, err := user.LookupId(who); err == nil {
		who = u.Username
	}
	return fmt.Errorf("%s belongs to %s, and this runs as uid %d: what it wrote would not be readable by port49d, "+
		"which could not start; nothing was changed; run as %s, e.g. sudo -u %s port49d revoke --offline --config %s ...",
		what, who, euid, who, who, cfgPath)
}
