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

	// BrokerCAPEM is the bytes of the file BrokerCA names, read once by Load
	// through the same ownership walk; nil under WithoutCA or with no CA named.
	BrokerCAPEM []byte `yaml:"-"`
}

// Option changes what Load does.
type Option func(*loadOptions)

type loadOptions struct{ skipCA bool }

// WithoutCA is for a caller whose --broker-ca overrides the file's: a CA that
// is not going to be used is neither read nor checked, so a bad one does not
// block a login that never touches it.
func WithoutCA() Option { return func(o *loadOptions) { o.skipCA = true } }

// maxFile bounds config.yaml; maxCA bounds the broker CA.
const (
	maxFile = 64 << 10
	maxCA   = 1 << 20
)

// Load reads config.yaml at path. ok is false, with no error, when there is
// no file; a file that is there and cannot be used is an error, never a file
// ignored.
func Load(path string, opts ...Option) (f File, ok bool, err error) {
	var o loadOptions
	for _, opt := range opts {
		opt(&o)
	}
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
	// to the same line, ReadPrivate's: owned by you or root, nobody else can
	// write it or the directories above it. It is read here, once, and its
	// bytes carried, so nothing can be swapped in between a check and a read.
	if f.BrokerCA != "" && !o.skipCA {
		if f.BrokerCAPEM, err = ReadPrivate(f.BrokerCA, maxCA, "broker CA"); err != nil {
			return File{}, false, fmt.Errorf("broker_ca in %s: %w", path, err)
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
	case strings.HasPrefix(p, "~") && p != "~" && !strings.HasPrefix(p, "~/"):
		return "", fmt.Errorf("%q: port49 expands ~ and ~/ to your home directory, not ~user; write the path out", p)
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
//
// path is walked as the kernel resolves it, one component at a time from the
// path as written (resolveOwned), and the file is opened by the resolved path,
// so the file read is the one whose directories were judged.
func ReadPrivate(path string, max int64, what string) ([]byte, error) {
	dir, base, err := splitPath(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w; the %s must be a file", path, err, what)
	}
	resolved, err := resolveOwned(dir, false, what)
	if err != nil {
		// Nothing is read from a path refused, and nothing is there to read
		// when the kernel finds no file: that is no file, as it always was,
		// not a complaint about a directory that holds nothing.
		if _, serr := os.Lstat(path); errors.Is(serr, fs.ErrNotExist) {
			return nil, serr
		}
		return nil, err
	}
	file := joinPath(resolved, base)
	li, err := os.Lstat(file)
	if errors.Is(err, fs.ErrPermission) {
		return nil, dirError(resolved, err, what)
	}
	if err != nil {
		return nil, err
	}
	if li.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is a symbolic link; the %s is read only as a file of its own", path, what)
	}
	if !li.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file; the %s must be one", path, what)
	}
	if err := ownedAlone(file, li, what); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(file, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, syscall.ELOOP) {
		return nil, fmt.Errorf("%s is a symbolic link; the %s is read only as a file of its own", path, what)
	}
	if errors.Is(err, fs.ErrPermission) {
		return nil, fmt.Errorf("cannot open %s: permission denied; the %s must be readable by you: chmod u+r %s (%w)",
			file, what, file, err)
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	// The file opened is the file judged, not one swapped in between.
	if !os.SameFile(li, fi) {
		return nil, fmt.Errorf("%s changed while port49 was checking it; run the command again", file)
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
	if err := ownedBy(path, fi, what); err != nil {
		return err
	}
	if fi.Mode().Perm()&0o022 != 0 && !(fi.IsDir() && fi.Mode()&fs.ModeSticky != 0) {
		return fmt.Errorf("%s is writable by others (mode %v); whoever can write the %s chooses what port49 "+
			"trusts: chmod go-w %s", path, fi.Mode().Perm(), what, path)
	}
	return nil
}

// ownedBy refuses what fi describes unless this user or root owns it.
func ownedBy(path string, fi fs.FileInfo, what string) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || (int(st.Uid) != getuid() && st.Uid != 0) {
		var owner any = "an unknown user"
		if ok {
			owner = st.Uid
		}
		return fmt.Errorf("%s is owned by uid %v, not you (uid %d); whoever owns the %s chooses what port49 "+
			"trusts, so it is refused: move it aside and recreate it as yourself", path, owner, getuid(), what)
	}
	return nil
}

// maxLinks is how many symbolic links resolveOwned follows before it calls a
// path a loop; Linux's own limit is 40.
const maxLinks = 40

// splitPath is path's directory part, as written, and its last element. It
// does not Clean: Dir would fold `link/..` away lexically, and the kernel does
// not.
func splitPath(path string) (dir, base string, err error) {
	i := strings.LastIndexByte(path, '/')
	switch {
	case i < 0:
		dir, base = ".", path
	case i == 0:
		dir, base = "/", path[1:]
	default:
		dir, base = path[:i], path[i+1:]
	}
	if base == "" || base == "." || base == ".." {
		return "", "", errors.New("names a directory")
	}
	return dir, base, nil
}

// joinPath is dir, a resolved absolute path, and one name.
func joinPath(dir, name string) string {
	if dir == "/" {
		return "/" + name
	}
	return dir + "/" + name
}

// resolveOwned resolves dir as the kernel does, from "/" one component at a
// time, and judges every component on the way (OpenSSH's StrictModes walk,
// with the check in the loop). A directory must be owned by you or root and
// not writable by its group or others: one that someone else can write lets
// them rename the directory below it and put their own in its place. A
// symbolic link must be owned by you or root, and the directory holding it has
// passed already, so nobody else can repoint it; its target is spliced in
// front of the rest of the path and walked the same way, so a link met inside
// a target is judged like the first. `..` goes to the parent of the resolved
// prefix, which holds no links, never to the lexical one. The returned path
// holds no links.
//
// dir is taken as written, never cleaned; a relative one is joined to the
// working directory as a string. The directories above the home directory are
// not judged: root's, and the one a login got to the home through. With create
// set, a missing directory is made 0700 and judged like the rest, which only
// happens below a prefix that has passed, so a refused path creates nothing.
func resolveOwned(dir string, create bool, what string) (string, error) {
	if !strings.HasPrefix(dir, "/") {
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		dir = cwd + "/" + dir
	}
	home, _ := os.UserHomeDir()
	if h, err := filepath.EvalSymlinks(home); err == nil && home != "" {
		home = h
	}
	holder := "directory holding the " + what
	prefix, links := "/", 0
	pending := strings.Split(dir, "/")
	for len(pending) > 0 {
		c := pending[0]
		pending = pending[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			prefix = filepath.Dir(prefix)
			continue
		}
		next := joinPath(prefix, c)
		fi, err := os.Lstat(next)
		if create && errors.Is(err, fs.ErrNotExist) {
			if err = os.Mkdir(next, 0o700); err == nil || errors.Is(err, fs.ErrExist) {
				fi, err = os.Lstat(next)
			}
		}
		if err != nil {
			return "", dirError(prefix, err, what)
		}
		switch {
		case fi.Mode()&fs.ModeSymlink != 0:
			// A link's own mode is never the point; who owns it is.
			if err := ownedBy(next, fi, holder); err != nil {
				return "", err
			}
			if links++; links > maxLinks {
				return "", fmt.Errorf("%s: too many symbolic links (over %d) on the way to the %s; a link loop is refused",
					dir, maxLinks, what)
			}
			target, err := os.Readlink(next)
			if err != nil {
				return "", err
			}
			if strings.HasPrefix(target, "/") {
				prefix = "/"
			}
			pending = append(strings.Split(target, "/"), pending...)
		case !fi.IsDir():
			return "", fmt.Errorf("%s is not a directory; the directory for the %s must be one", next, what)
		default:
			if home != "" && home != next && strings.HasPrefix(home, next+"/") {
				prefix = next // above the home directory: not judged
				continue
			}
			if err := ownedAlone(next, fi, holder); err != nil {
				return "", err
			}
			prefix = next
		}
	}
	return prefix, nil
}

// dirError says which directory port49 could not look inside, and for a
// refused one what to run. d is the directory that was being searched, not
// the entry below it that failed.
func dirError(d string, err error, what string) error {
	if errors.Is(err, fs.ErrPermission) {
		return fmt.Errorf("%s: permission denied; port49 must look inside it to check who can write the %s: "+
			"chmod u+rx %s (%w)", d, what, d, err)
	}
	return err
}

// WritePrivate replaces path with data at mode 0600, through a temporary
// file in its directory renamed over it, so a reader never sees half a file.
// Missing directories are made 0700. The directory is walked as ReadPrivate
// walks it (resolveOwned), top down, and a directory is made only under a
// prefix that has passed, so a path that would be refused creates nothing.
func WritePrivate(path string, data []byte, what string) error {
	dirPart, base, err := splitPath(path)
	if err != nil {
		return fmt.Errorf("%s: %w; the %s must be a file", path, err, what)
	}
	dir, err := resolveOwned(dirPart, true, what)
	if err != nil {
		return err
	}
	path = joinPath(dir, base)
	tmp, err := os.CreateTemp(dir, "."+base+".*")
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
