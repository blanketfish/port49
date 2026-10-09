package userconfig

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// privateDir is a fresh directory only this user can write, whatever the
// umask: under umask 002, the default on Ubuntu, a t.TempDir is
// group-writable, which ReadPrivate refuses to read from.
func privateDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

// private writes body as name in a fresh 0700 directory.
func private(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(privateDir(t), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// Relative paths are the file's directory's; ~/ is the home directory.
func TestLoadResolvesPaths(t *testing.T) {
	t.Setenv("HOME", "/home/alice")
	p := private(t, "config.yaml", "broker: https://b.example:8443\nbroker_ca: ca.pem\ncert: ~/.port49/a.pem\nkey: /k.pem\n")
	f, ok, err := Load(p)
	if err != nil || !ok {
		t.Fatalf("ok %v err %v", ok, err)
	}
	if f.Broker != "https://b.example:8443" || f.BrokerCA != filepath.Join(filepath.Dir(p), "ca.pem") ||
		f.Cert != "/home/alice/.port49/a.pem" || f.Key != "/k.pem" {
		t.Fatalf("%+v", f)
	}
}

// No file is no config, and no error.
func TestAMissingFileIsNoFile(t *testing.T) {
	if _, ok, err := Load(filepath.Join(t.TempDir(), "config.yaml")); ok || err != nil {
		t.Fatalf("ok %v err %v", ok, err)
	}
}

// Whoever can write the file or its directory chooses the broker the
// operator trusts: every such file is refused, never read (decision 42
// ruling 6).
func TestAFileOthersCouldWriteIsRefused(t *testing.T) {
	p := private(t, "config.yaml", "broker: https://b.example:8443\n")
	if err := os.Chmod(p, 0o620); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(p); err == nil || !strings.Contains(err.Error(), "writable by others") {
		t.Fatalf("a group-writable file: %v", err)
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(p), 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Dir(p), 0o700) })
	if _, _, err := Load(p); err == nil || !strings.Contains(err.Error(), "directory holding the port49 config file") {
		t.Fatalf("a world-writable directory: %v", err)
	}
}

// A directory higher up that others can write is refused too: they could
// rename the one below it and put their own in its place. A sticky one, as
// /tmp is, cannot be used so, and is read through (decision 42 ruling 6).
func TestADirectoryAboveOthersCanWriteIsRefused(t *testing.T) {
	top := filepath.Join(privateDir(t), "shared")
	dir := filepath.Join(top, "port49")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte("broker: https://b.example:8443\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(top, 0o700) })
	if err := os.Chmod(top, 0o777); err != nil {
		t.Fatal(err)
	}
	// The refusal tells the operator what to run.
	if _, _, err := Load(p); err == nil || !strings.Contains(err.Error(), top+" is writable by others") ||
		!strings.Contains(err.Error(), "chmod go-w "+top) {
		t.Fatalf("a world-writable directory two up: %v", err)
	}
	if err := os.Chmod(top, 0o777|fs.ModeSticky); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := Load(p); err != nil || !ok {
		t.Fatalf("a sticky directory two up: ok %v err %v", ok, err)
	}
}

// A config directory reached through a symlink lives where the link points:
// whoever can write that directory's parent can rename it and put their own
// in its place, so the walk covers the resolved path too (decision 42 ruling
// 6; OpenSSH's secure_path resolves first).
func TestASymlinkedDirectoryIntoAWritableOneIsRefused(t *testing.T) {
	home := privateDir(t)
	t.Setenv("HOME", home)
	shared := filepath.Join(privateDir(t), "shared")
	real := filepath.Join(shared, "port49")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "config.yaml"), []byte("broker: https://b.example:8443\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(home, ".config"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(home, ".config", "port49")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(shared, 0o700) })
	if err := os.Chmod(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(home, ".config", "port49", "config.yaml")
	if _, _, err := Load(p); err == nil || !strings.Contains(err.Error(), shared+" is writable by others") {
		t.Fatalf("a link into a world-writable directory: %v", err)
	}
	if err := WritePrivate(p, []byte("x\n"), "pinned host keys file"); err == nil ||
		!strings.Contains(err.Error(), shared+" is writable by others") {
		t.Fatalf("a write through it: %v", err)
	}
}

// A symlinked ~/.config into a directory only you can write is how a dotfiles
// repo lays out a home: accepted, by ReadPrivate and WritePrivate alike.
func TestASymlinkedConfigDirectoryYouOwnAloneIsAccepted(t *testing.T) {
	home := privateDir(t)
	t.Setenv("HOME", home)
	dotfiles := privateDir(t)
	if err := os.Mkdir(filepath.Join(dotfiles, "port49"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(dotfiles, filepath.Join(home, ".config")); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(home, ".config", "port49", "config.yaml")
	if err := WritePrivate(p, []byte("broker: https://b.example:8443\n"), "port49 config file"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if f, ok, err := Load(p); err != nil || !ok || f.Broker != "https://b.example:8443" {
		t.Fatalf("read: %+v ok %v err %v", f, ok, err)
	}
}

// The refusal names the owner and you, and says what to do.
func TestTheNotOwnedRefusalNamesTheOwnerAndYou(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("run as root, the file is root's")
	}
	p := private(t, "config.yaml", "broker: https://b.example:8443\n")
	prev := getuid
	getuid = func() int { return os.Getuid() + 1 }
	t.Cleanup(func() { getuid = prev })
	_, _, err := Load(p)
	want := "owned by uid " + strconv.Itoa(os.Getuid()) + ", not you (uid " + strconv.Itoa(os.Getuid()+1) + ")"
	if err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "recreate it as yourself") {
		t.Fatalf("%v, want %q", err, want)
	}
}

// ~user is not expanded; it is refused, not read as <dir>/~user.
func TestATildeNotFollowedBySlashIsRefused(t *testing.T) {
	p := private(t, "config.yaml", "cert: ~bob/cert.pem\n")
	if _, _, err := Load(p); err == nil || !strings.Contains(err.Error(), "~bob/cert.pem") ||
		!strings.Contains(err.Error(), "~user") {
		t.Fatalf("~bob: %v", err)
	}
}

// A file or directory port49 may not open says which, and what to run.
func TestAnUnreadableFileSaysWhatToRun(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("run as root, nothing is unreadable")
	}
	p := private(t, "config.yaml", "broker: https://b.example:8443\n")
	if err := os.Chmod(p, 0o200); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(p); err == nil || !strings.Contains(err.Error(), "chmod u+r "+p) {
		t.Fatalf("an unreadable file: %v", err)
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	d := filepath.Dir(p)
	if err := os.Chmod(d, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(d, 0o700) })
	if _, _, err := Load(p); err == nil || !strings.Contains(err.Error(), "chmod u+rx "+d) {
		t.Fatalf("an unsearchable directory: %v", err)
	}
}

// The broker CA the file names is refused when others can write it: whoever
// can chooses which broker the operator trusts.
func TestABrokerCAOthersCanWriteIsRefused(t *testing.T) {
	p := private(t, "config.yaml", "broker_ca: ca.pem\n")
	ca := filepath.Join(filepath.Dir(p), "ca.pem")
	if err := os.WriteFile(ca, []byte("x"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ca, 0o664); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(p); err == nil || !strings.Contains(err.Error(), ca+" is writable by others") {
		t.Fatalf("a group-writable CA: %v", err)
	}
}

func TestAFileAnotherUserOwnsIsRefused(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("run as root, the file is root's, and a root-owned file is accepted")
	}
	p := private(t, "config.yaml", "broker: https://b.example:8443\n")
	prev := getuid
	getuid = func() int { return os.Getuid() + 1 }
	t.Cleanup(func() { getuid = prev })
	if _, _, err := Load(p); err == nil || !strings.Contains(err.Error(), "not you (uid") {
		t.Fatalf("another user's file: %v", err)
	}
}

func TestASymlinkIsRefused(t *testing.T) {
	p := private(t, "real.yaml", "broker: https://b.example:8443\n")
	link := filepath.Join(filepath.Dir(p), "config.yaml")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(link); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("a symlink: %v", err)
	}
}

func TestAnUnknownKeyOrASecondDocumentIsRefused(t *testing.T) {
	for name, body := range map[string]string{
		"unknown key":     "brokr: https://b.example:8443\n",
		"second document": "broker: https://b.example:8443\n---\nbroker: https://c.example:8443\n",
	} {
		if _, _, err := Load(private(t, "config.yaml", body)); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}

// WritePrivate makes the directory 0700 and the file 0600, and ReadPrivate
// reads it back.
func TestWritePrivateThenReadPrivate(t *testing.T) {
	p := filepath.Join(privateDir(t), "port49", "known_hosts")
	if err := WritePrivate(p, []byte("x\n"), "pinned host keys file"); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	di, derr := os.Stat(filepath.Dir(p))
	if err != nil || derr != nil || fi.Mode().Perm() != 0o600 || di.Mode().Perm() != 0o700 {
		t.Fatalf("file %v dir %v (%v %v)", fi.Mode(), di.Mode(), err, derr)
	}
	raw, err := ReadPrivate(p, 64, "pinned host keys file")
	if err != nil || string(raw) != "x\n" {
		t.Fatalf("%q %v", raw, err)
	}
	if _, err := ReadPrivate(filepath.Join(filepath.Dir(p), "none"), 64, "x"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a missing file: %v", err)
	}
	if _, err := ReadPrivate(p, 1, "pinned host keys file"); err == nil {
		t.Fatal("a file over max was read")
	}
}

// WritePrivate creates nothing under a directory it would refuse: not the
// missing directories, not the temporary file.
func TestWritePrivateCreatesNothingUnderARefusedDirectory(t *testing.T) {
	top := privateDir(t)
	if err := os.Chmod(top, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(top, 0o700) })
	p := filepath.Join(top, "a", "b", "known_hosts")
	if err := WritePrivate(p, []byte("x\n"), "pinned host keys file"); err == nil ||
		!strings.Contains(err.Error(), top+" is writable by others") {
		t.Fatalf("a world-writable parent: %v", err)
	}
	if ents, err := os.ReadDir(top); err != nil || len(ents) != 0 {
		t.Fatalf("left behind: %v %v", ents, err)
	}
	// An existing refused directory gets no temporary file either.
	if err := os.Mkdir(filepath.Join(top, "a"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivate(filepath.Join(top, "a", "known_hosts"), []byte("x\n"), "pinned host keys file"); err == nil {
		t.Fatal("wrote under a world-writable directory")
	}
	if ents, _ := os.ReadDir(filepath.Join(top, "a")); len(ents) != 0 {
		t.Fatalf("left behind: %v", ents)
	}
}
