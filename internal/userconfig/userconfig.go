// Package userconfig is the operator's own files under
// $XDG_CONFIG_HOME/port49 (spec §13 decision 42, ruling 6): config.yaml,
// which gives `port49 login` its broker, broker CA, certificate and key; and
// the private-file reading and writing it shares with the pinned host keys
// (internal/hostkeys). Whoever can write these files chooses which broker the
// operator trusts and which device keys `port49 ssh` accepts, so a file, or a
// directory holding one, that anyone else can write is refused, never read.
// It is keyfile's rule for a private key, for writing rather than reading,
// and unlike internal/fence it holds on macOS too.
package userconfig

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"gopkg.in/yaml.v3"
)

// getuid is os.Getuid, swapped in tests: no second uid exists to own a file.
var getuid = os.Getuid

// Dir is $XDG_CONFIG_HOME/port49, else ~/.config/port49.
func Dir() string {
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "port49")
	}
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".config", "port49")
	}
	return filepath.Join(".config", "port49")
}

// Path is the config file's default path.
func Path() string { return filepath.Join(Dir(), "config.yaml") }

// File is config.yaml. Every key is optional; `port49 login` takes each one
// its flags leave out. Paths are resolved by Load: relative to the file's
// directory, and ~/ the home directory.
type File struct {
	Broker   string `yaml:"broker"`
	BrokerCA string `yaml:"broker_ca"`
	Cert     string `yaml:"cert"`
	Key      string `yaml:"key"`
}

// maxFile bounds config.yaml.
const maxFile = 64 << 10

// Load reads config.yaml at path. ok is false, with no error, when there is
// no file; a file that is there and cannot be used is an error, never a file
// ignored.
func Load(path string) (f File, ok bool, err error) {
	raw, err := ReadPrivate(path, maxFile, "port49 config file")
	if errors.Is(err, fs.ErrNotExist) {
		return File{}, false, nil
	}
	if err != nil {
		return File{}, false, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return File{}, false, fmt.Errorf("%s: %w", path, err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return File{}, false, fmt.Errorf("%s holds a second YAML document; port49 reads one", path)
	}
	base := filepath.Dir(path)
	for _, p := range []*string{&f.BrokerCA, &f.Cert, &f.Key} {
		if *p, err = resolve(base, *p); err != nil {
			return File{}, false, fmt.Errorf("%s: %w", path, err)
		}
	}
	// The CA this file names pins the broker as the file does, so it is held
	// to the same line: nobody else may write it. A missing one is left to
	// the read that follows, which says so.
	if f.BrokerCA != "" {
		if fi, err := os.Stat(f.BrokerCA); err == nil && fi.Mode().Perm()&0o022 != 0 {
			return File{}, false, fmt.Errorf("%s is writable by others (mode %v); whoever can write the broker CA "+
				"chooses which broker port49 trusts: chmod go-w %s", f.BrokerCA, fi.Mode().Perm(), f.BrokerCA)
		}
	}
	return f, true, nil
}

// resolve is p as Load reads it: ~ and ~/ from the home directory, a relative
// path from base.
func resolve(base, p string) (string, error) {
	switch {
	case p == "":
		return "", nil
	case p == "~" || strings.HasPrefix(p, "~/"):
		h, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(h, strings.TrimPrefix(p, "~")), nil
	case filepath.IsAbs(p):
		return p, nil
	}
	return filepath.Join(base, p), nil
}

// ReadPrivate reads path, at most max bytes, refusing it unless it is a
// regular file of its own (a symlink is refused, not followed) that this
// user or root owns and nobody else can write, and every directory above it
// is held to dirsOwnedAlone. A missing file is an error errors.Is(err,
// fs.ErrNotExist) reports. what names the file in a refusal.
func ReadPrivate(path string, max int64, what string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, syscall.ELOOP) {
		return nil, fmt.Errorf("%s is a symbolic link; the %s is read only as a file of its own", path, what)
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file; the %s must be one", path, what)
	}
	if err := ownedAlone(path, fi, what); err != nil {
		return nil, err
	}
	if err := dirsOwnedAlone(filepath.Dir(path), what); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > max {
		return nil, fmt.Errorf("%s is over %d bytes; a %s is never that large", path, max, what)
	}
	return raw, nil
}

// ownedAlone refuses what fi describes unless this user or root owns it and
// neither its group nor others can write it. A directory with the sticky bit
// set, as /tmp has, is the exception: there nobody can rename or replace an
// entry they do not own, which is all a directory above the file is checked
// for. Root owning a file is OpenSSH's StrictModes rule too: root can write
// anything, so trusting it trusts nobody new.
func ownedAlone(path string, fi fs.FileInfo, what string) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || (int(st.Uid) != getuid() && st.Uid != 0) {
		return fmt.Errorf("%s is not owned by you (uid %d); whoever owns the %s chooses what port49 trusts, "+
			"so it is refused", path, getuid(), what)
	}
	if fi.Mode().Perm()&0o022 != 0 && !(fi.IsDir() && fi.Mode()&fs.ModeSticky != 0) {
		return fmt.Errorf("%s is writable by others (mode %v); whoever can write the %s chooses what port49 "+
			"trusts: chmod go-w %s", path, fi.Mode().Perm(), what, path)
	}
	return nil
}

// dirsOwnedAlone holds dir and each directory above it to ownedAlone, up to
// the home directory or /: one that someone else can write lets them rename
// the directory below it and put their own in its place (OpenSSH's
// StrictModes walk). The walk is of the path as written, each component
// stat'ed through any symlink.
func dirsOwnedAlone(dir, what string) error {
	d, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	home, _ := os.UserHomeDir()
	for {
		di, err := os.Stat(d)
		if err != nil {
			return err
		}
		if err := ownedAlone(d, di, "directory holding the "+what); err != nil {
			return err
		}
		if d == home || d == filepath.Dir(d) {
			return nil
		}
		d = filepath.Dir(d)
	}
}

// WritePrivate replaces path with data at mode 0600, through a temporary
// file in its directory renamed over it, so a reader never sees half a file.
// The directory is made 0700 when missing. It is refused as ReadPrivate
// refuses it, and before anything is created: the walk covers the nearest
// directory that exists first, so no directory or file is made under a path
// that would be refused.
func WritePrivate(path string, data []byte, what string) error {
	dir, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return err
	}
	existing := dir
	for {
		if _, err := os.Stat(existing); err == nil {
			break
		}
		if up := filepath.Dir(existing); up != existing {
			existing = up
			continue
		}
		break
	}
	if err := dirsOwnedAlone(existing, what); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	di, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !di.IsDir() {
		return fmt.Errorf("%s is not a directory; the %s's directory must be one", dir, what)
	}
	if err := dirsOwnedAlone(dir, what); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // after the rename there is nothing at name
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}
