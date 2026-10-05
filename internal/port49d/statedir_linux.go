//go:build linux

package port49d

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/rhwendt/port49/internal/fence"
	"github.com/rhwendt/port49/internal/inventory"
)

// The files port49-broker keeps in broker.state_dir beside the CRLs: its
// copy of the marks (Task 15b) and the restore witness's record (Task
// 15c).
const (
	stateMarksFile   = "marks.json"
	stateWitnessFile = "witness.json"
)

// ownStateDir refuses broker.state_dir, or marks.json or witness.json in
// it, owned by anyone but the user port49-broker runs as or root (plan 7e,
// Ruling 12): whoever owns the directory can chmod it and replace a file,
// and whoever owns marks.json could put back a lifted mark, or drop one,
// at the next takeover. A state file that is not a regular file, a link
// among them, is refused too. config.LoadBroker has refused a directory
// its group or others can write; the start asks this before anything
// reads or writes there. A 0700 directory the service user owns, as a
// container's or a Kubernetes volume's state directory is, passes.
func ownStateDir(dir string) error {
	if err := ownedHere("broker.state_dir "+dir, dir, true); err != nil {
		return err
	}
	for _, name := range []string{stateMarksFile, stateWitnessFile} {
		if err := ownedHere(filepath.Join(dir, name), filepath.Join(dir, name), false); err != nil {
			return err
		}
	}
	return nil
}

// ownedHere is ownStateDir's check of one path, named what in its
// refusal: a directory (dir) that exists, or a state file, which may not
// exist yet.
func ownedHere(what, path string, dir bool) error {
	fi, err := os.Lstat(path)
	switch {
	case !dir && errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return err
	case dir && fi.Mode()&fs.ModeSymlink != 0:
		// config.LoadBroker followed it; this check does not, so say why.
		target, _ := filepath.EvalSymlinks(path)
		return fmt.Errorf("%s is a symbolic link: point broker.state_dir at the directory itself (%s)", what, target)
	case dir && !fi.IsDir():
		return fmt.Errorf("%s is not a directory", what)
	case dir && fi.Mode().Perm()&0o022 != 0:
		return fmt.Errorf("%s is writable by its group or others (mode %04o): port49-broker's own state is kept "+
			"there; chmod 0700 it", what, fi.Mode().Perm())
	case !dir && !fi.Mode().IsRegular():
		return fmt.Errorf("%s is not a regular file (%v): port49-broker writes it itself; remove it", what,
			fi.Mode().Type())
	}
	uid, ok := fence.FileOwner(fi)
	if !ok {
		return fmt.Errorf("%s: cannot read its owner", what)
	}
	if euid := fence.Geteuid(); uid != uint32(euid) && uid != 0 {
		return &wrongOwnerError{what: what, uid: uid, euid: uint32(euid)}
	}
	return nil
}

// writeOwnerOnly is the one writer of broker.state_dir's state files
// (marks.json, witness.json): it refuses the directory or the file owned
// by anyone else (ownedHere), then writes body to a temporary file in the
// same directory at mode 0600 and renames it over path, so a reader sees
// the old file or the new one.
func writeOwnerOnly(path string, body []byte) error {
	dir := filepath.Dir(path)
	if err := ownedHere("broker.state_dir "+dir, dir, true); err != nil {
		return err
	}
	if err := ownedHere(path, path, false); err != nil {
		return err
	}
	return inventory.WriteAtomic(dir, filepath.Base(path), body, 0o600)
}
