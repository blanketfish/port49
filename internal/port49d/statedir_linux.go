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
// copy of the marks (Task 15b), the restore witness's record (Task 15c) and,
// on the memory backend, the sealed enrollment store (plan 9e).
const (
	stateMarksFile       = "marks.json"
	stateWitnessFile     = "witness.json"
	stateEnrollmentsFile = "enrollments.json"
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
	for _, name := range []string{stateMarksFile, stateWitnessFile, stateEnrollmentsFile} {
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
	case !dir && !fi.Mode().IsRegular():
		return fmt.Errorf("%s is not a regular file (%v): port49-broker writes it itself; remove it", what,
			fi.Mode().Type())
	}
	// The owner before the mode: a path another user owns is a wrong owner whatever its mode, so the
	// offline tools refuse it before a write rather than treating it as an I/O failure.
	uid, ok := fence.FileOwner(fi)
	if !ok {
		return fmt.Errorf("%s: cannot read its owner", what)
	}
	if euid := fence.Geteuid(); uid != uint32(euid) && uid != 0 {
		return &wrongOwnerError{what: what, uid: uid, euid: uint32(euid)}
	}
	if dir && fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is writable by its group or others (mode %04o): port49-broker's own state is kept "+
			"there; chmod 0700 it", what, fi.Mode().Perm())
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

// createOwnerOnly is writeOwnerOnly for a file that must not be there yet:
// it makes path with O_EXCL at mode 0600, so two writers cannot both make it
// (init-issuer's key), and removes what it made if the write fails.
func createOwnerOnly(path string, body []byte) error {
	dir := filepath.Dir(path)
	if err := ownedHere("broker.state_dir "+dir, dir, true); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(body); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(path)
	}
	return err
}

// readOwnerOnly reads a kept file the broker wrote itself: a regular file
// owned by its user or root (ownedHere), or nothing when there is none.
func readOwnerOnly(path string) ([]byte, error) {
	if err := ownedHere(path, path, false); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return b, err
}
