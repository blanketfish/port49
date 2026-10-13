package userconfig

import (
	"errors"
	"fmt"
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
	if err := os.WriteFile(filepath.Join(filepath.Dir(p), "ca.pem"), []byte("PEM"), 0o644); err != nil {
		t.Fatal(err)
	}
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
	// The refusal says what the directory needs, and no chmod: it may be
	// shared, as a group-writable ~/.config is.
	if _, _, err := Load(p); err == nil || !strings.Contains(err.Error(), top+" is writable by others") ||
		!strings.Contains(err.Error(), "writable by its owner alone (mode 0755 or 0700)") ||
		strings.Contains(err.Error(), "chmod") {
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

// walkLab is a private parent P holding HOME=P/home (0700) and P/shared, a
// directory anyone can write and without the sticky bit: whoever is in it can
// rename any entry, so a path through it is refused.
func walkLab(t *testing.T) (home, shared string) {
	t.Helper()
	p := privateDir(t)
	home = filepath.Join(p, "home")
	shared = filepath.Join(p, "shared")
	for _, d := range []string{home, shared} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	return home, shared
}

func mustDo(t *testing.T, errs ...error) {
	t.Helper()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

// A chain of links whose middle one sits in a directory others can write is
// refused: they rename it and put their own link in its place, one hop further
// than the link the path names (probe C).
func TestAChainOfLinksThroughAWritableDirectoryIsRefused(t *testing.T) {
	home, shared := walkLab(t)
	real := filepath.Join(home, "real")
	mustDo(t, os.MkdirAll(filepath.Join(real, "port49"), 0o700),
		os.WriteFile(filepath.Join(real, "port49", "config.yaml"), []byte("broker: https://b.example:8443\n"), 0o600),
		os.Symlink(real, filepath.Join(shared, "hop")),
		os.Symlink(filepath.Join(shared, "hop"), filepath.Join(home, ".config")))
	p := filepath.Join(home, ".config", "port49", "config.yaml")
	if _, _, err := Load(p); err == nil || !strings.Contains(err.Error(), shared+" is writable by others") {
		t.Fatalf("a chain through a writable directory: %v", err)
	}
}

// A link inside a link's target is judged too, and the directory holding it
// (probe C3).
func TestALinkInsideALinksTargetIsRefused(t *testing.T) {
	home, shared := walkLab(t)
	stuff := filepath.Join(home, "stuff")
	mustDo(t, os.MkdirAll(filepath.Join(stuff, "b"), 0o700),
		os.WriteFile(filepath.Join(stuff, "b", "config.yaml"), []byte("broker: https://b.example:8443\n"), 0o600),
		os.Symlink(stuff, filepath.Join(shared, "a")),
		os.Symlink(filepath.Join(shared, "a", "b"), filepath.Join(home, ".config")))
	if _, _, err := Load(filepath.Join(home, ".config", "config.yaml")); err == nil ||
		!strings.Contains(err.Error(), shared+" is writable by others") {
		t.Fatalf("a link mid-target: %v", err)
	}
}

// `..` after a link goes to the link target's parent, as the kernel does, not
// to the path's lexical parent: the file read is the directory walked (probe
// E3).
func TestDotDotAfterALinkIsWalkedWhereTheKernelGoes(t *testing.T) {
	home, shared := walkLab(t)
	mustDo(t, os.Mkdir(filepath.Join(shared, "sub"), 0o700),
		os.Mkdir(filepath.Join(shared, "x"), 0o700),
		os.WriteFile(filepath.Join(shared, "x", "config.yaml"), []byte("broker: https://evil:1\n"), 0o600),
		os.Mkdir(filepath.Join(home, "x"), 0o700),
		os.Symlink(filepath.Join(shared, "sub"), filepath.Join(home, "link")))
	f, _, err := Load(home + "/link/../x/config.yaml")
	if err == nil || f.Broker != "" {
		t.Fatalf("read the attacker's file: %+v %v", f, err)
	}
	// A plain a/b/.. is the same directory either way.
	mustDo(t, os.MkdirAll(filepath.Join(home, "a", "b"), 0o700),
		os.WriteFile(filepath.Join(home, "a", "config.yaml"), []byte("broker: https://b.example:8443\n"), 0o600))
	if f, ok, err := Load(home + "/a/b/../config.yaml"); err != nil || !ok || f.Broker != "https://b.example:8443" {
		t.Fatalf("a/b/..: %+v ok %v err %v", f, ok, err)
	}
}

// A refused chain creates nothing (item 5): not a directory, not a file.
func TestWritePrivateCreatesNothingWhenTheChainIsRefused(t *testing.T) {
	home, shared := walkLab(t)
	real := filepath.Join(home, "real2")
	mustDo(t, os.Mkdir(real, 0o700),
		os.Symlink(real, filepath.Join(shared, "hop")),
		os.Symlink(filepath.Join(shared, "hop"), filepath.Join(home, ".cfg2")))
	err := WritePrivate(filepath.Join(home, ".cfg2", "sub", "pins.yaml"), []byte("x\n"), "pinned host keys file")
	if err == nil {
		t.Fatal("wrote through a chain that ReadPrivate refuses")
	}
	if ents, _ := os.ReadDir(real); len(ents) != 0 {
		t.Fatalf("left behind in %s: %v", real, ents)
	}
}

// A loop of links is refused, not followed forever.
func TestALinkLoopIsRefused(t *testing.T) {
	home, _ := walkLab(t)
	mustDo(t, os.Symlink(filepath.Join(home, "b"), filepath.Join(home, "a")),
		os.Symlink(filepath.Join(home, "a"), filepath.Join(home, "b")))
	if _, _, err := Load(filepath.Join(home, "a", "config.yaml")); err == nil ||
		!strings.Contains(err.Error(), "too many symbolic links") {
		t.Fatalf("a loop: %v", err)
	}
	if err := WritePrivate(filepath.Join(home, "a", "k"), []byte("x"), "k"); err == nil ||
		!strings.Contains(err.Error(), "too many symbolic links") {
		t.Fatalf("a loop, writing: %v", err)
	}
}

// The refusal for a directory port49 cannot search names that directory, not
// the one below it.
func TestAnUnsearchableAncestorIsNamed(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("run as root, nothing is unsearchable")
	}
	home, _ := walkLab(t)
	mustDo(t, os.MkdirAll(filepath.Join(home, "up", "down"), 0o700),
		os.WriteFile(filepath.Join(home, "up", "down", "config.yaml"), []byte("x"), 0o600),
		os.Chmod(filepath.Join(home, "up"), 0o600))
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(home, "up"), 0o700) })
	if _, _, err := Load(filepath.Join(home, "up", "down", "config.yaml")); err == nil ||
		!strings.Contains(err.Error(), "chmod u+rx "+filepath.Join(home, "up")) {
		t.Fatalf("an unsearchable ancestor: %v", err)
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

// Load reads the CA once, through the ownership walk, and carries its bytes;
// a CA in a directory others can write is refused like the file is.
func TestTheBrokerCAIsReadOnceThroughTheWalk(t *testing.T) {
	p := private(t, "config.yaml", "broker_ca: ca.pem\n")
	ca := filepath.Join(filepath.Dir(p), "ca.pem")
	if err := os.WriteFile(ca, []byte("PEM"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, _, err := Load(p)
	if err != nil || string(f.BrokerCAPEM) != "PEM" {
		t.Fatalf("%q %v", f.BrokerCAPEM, err)
	}
	// In a directory anyone can write, the CA could be renamed over.
	open := privateDir(t)
	if err := os.WriteFile(filepath.Join(open, "ca.pem"), []byte("PEM"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(open, 0o700) })
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	p = private(t, "config.yaml", "broker_ca: "+filepath.Join(open, "ca.pem")+"\n")
	if _, _, err := Load(p); err == nil || !strings.Contains(err.Error(), open+" is writable by others") {
		t.Fatalf("a CA in a writable directory: %v", err)
	}
	// A CA that is not there is said so, naming the path.
	p = private(t, "config.yaml", "broker_ca: gone.pem\n")
	if _, _, err := Load(p); err == nil || !strings.Contains(err.Error(), "gone.pem") {
		t.Fatalf("a missing CA: %v", err)
	}
}

// A CA the file names but --broker-ca overrides is not used, so a bad one does
// not block the login.
func TestAnOverriddenBrokerCAIsNotChecked(t *testing.T) {
	p := private(t, "config.yaml", "broker_ca: ca.pem\n")
	ca := filepath.Join(filepath.Dir(p), "ca.pem")
	if err := os.WriteFile(ca, []byte("x"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ca, 0o666); err != nil {
		t.Fatal(err)
	}
	f, ok, err := Load(p, WithoutCA())
	if err != nil || !ok || f.BrokerCAPEM != nil {
		t.Fatalf("%+v ok %v err %v", f, ok, err)
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

// WritePrivateAll renames nothing until every file is staged: a second file
// the walk refuses leaves the first path, and its directory, as they were.
func TestWritePrivateAllLeavesEveryPathAsItWasWhenOneIsRefused(t *testing.T) {
	good := privateDir(t)
	bad := privateDir(t)
	if err := os.Chmod(bad, 0o777); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(good, "a.key")
	if err := os.WriteFile(first, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := WritePrivateAll(PrivateFile{first, []byte("new"), "key"}, PrivateFile{filepath.Join(bad, "a.pem"), []byte("new"), "cert"})
	if err == nil {
		t.Fatal("a refused directory was written")
	}
	if raw, rerr := os.ReadFile(first); rerr != nil || string(raw) != "old" {
		t.Fatalf("the first path: %q %v", raw, rerr)
	}
	if ents, _ := os.ReadDir(good); len(ents) != 1 {
		t.Fatalf("%d entries left in the good directory, want 1", len(ents))
	}
	if err := WritePrivateAll(PrivateFile{first, []byte("new"), "key"}, PrivateFile{filepath.Join(good, "a.pem"), []byte("cert"), "cert"}); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(first); string(raw) != "new" {
		t.Fatalf("the first path: %q", raw)
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

// PrivateDir makes a missing directory 0700 and returns it judged; a refused
// one is an error and creates nothing.
func TestPrivateDirCreatesAndJudges(t *testing.T) {
	top := privateDir(t)
	got, err := PrivateDir(filepath.Join(top, "a", "b"), "pinned host keys file")
	if err != nil || got != filepath.Join(top, "a", "b") {
		t.Fatalf("%q %v", got, err)
	}
	if fi, err := os.Stat(got); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("%v %v", fi, err)
	}
	if err := os.Chmod(top, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(top, 0o700) })
	if _, err := PrivateDir(filepath.Join(top, "c"), "pinned host keys file"); err == nil ||
		!strings.Contains(err.Error(), "writable by others") {
		t.Fatalf("a world-writable parent: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(top, "c")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a refused path created a directory: %v", err)
	}
}

// The OIDC keys (decision 43 ruling 19): oidc_ca is resolved and read once
// through the walk, as broker_ca is.
func TestTheOIDCKeysAreRead(t *testing.T) {
	p := private(t, "config.yaml", "method: oidc\noidc_issuer: https://kc.example/r\noidc_ca: idp.pem\n"+
		"oidc_redirect_port: 18749\n")
	ca := filepath.Join(filepath.Dir(p), "idp.pem")
	if err := os.WriteFile(ca, []byte("PEM"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, ok, err := Load(p)
	if err != nil || !ok || f.Method != "oidc" || f.OIDCIssuer != "https://kc.example/r" || f.OIDCCA != ca ||
		string(f.OIDCCAPEM) != "PEM" || f.OIDCRedirectPort != 18749 {
		t.Fatalf("%+v %v %v", f, ok, err)
	}
	if f, _, err := Load(p, WithoutOIDCCA()); err != nil || f.OIDCCAPEM != nil {
		t.Fatalf("WithoutOIDCCA: %q %v", f.OIDCCAPEM, err)
	}
}

func TestAnOIDCCAOthersCanWriteIsRefused(t *testing.T) {
	p := private(t, "config.yaml", "oidc_ca: idp.pem\n")
	ca := filepath.Join(filepath.Dir(p), "idp.pem")
	if err := os.WriteFile(ca, []byte("x"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ca, 0o664); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(p); err == nil || !strings.Contains(err.Error(), ca+" is writable by others") ||
		!strings.Contains(err.Error(), "oidc_ca in") {
		t.Fatalf("%v", err)
	}
}

func TestAnUnknownMethodOrABadPortIsRefused(t *testing.T) {
	for body, want := range map[string]string{
		"method: saml\n":              `method "saml"`,
		"oidc_redirect_port: 70000\n": "is not a port",
		"oidc_redirect_port: -1\n":    "is not a port",
	} {
		if _, _, err := Load(private(t, "config.yaml", body)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", body, err, want)
		}
	}
}

// An issued certificate is kept per broker, by its host and port, and a
// broker URL that would not make a plain file name is refused (decision 43
// ruling 7).
func TestIssuedPaths(t *testing.T) {
	for broker, want := range map[string]string{
		"https://Broker.Example:8443":  "broker.example_8443",
		"https://broker.example":       "broker.example_443",
		"https://[2001:db8::1]:8443/x": "2001-db8--1_8443",
	} {
		c, k, err := IssuedPathsIn("/d", broker)
		if err != nil || c != "/d/issued/"+want+".pem" || k != "/d/issued/"+want+".key" {
			t.Errorf("%s: %s %s %v", broker, c, k, err)
		}
	}
	for _, bad := range []string{"http://broker.example", "https://", "https://u:p@broker.example", "broker.example:8443"} {
		if _, _, err := IssuedPathsIn("/d", bad); err == nil {
			t.Errorf("%q made a path", bad)
		}
	}
}

// A TPM-held pair is named for the machine as well, beside the file pair, so
// hosts that share a home directory keep a pair each (decision 45 ruling 7;
// pre-flight I12); a broker URL IssuedPathsIn refuses is refused, and a
// machine with no id makes no path.
func TestIssuedTPMPaths(t *testing.T) {
	prev := MachineID
	t.Cleanup(func() { MachineID = prev })
	MachineID = func() (string, error) { return "0123abcd", nil }
	for broker, want := range map[string]string{
		"https://Broker.Example:8443":  "broker.example_8443",
		"https://broker.example":       "broker.example_443",
		"https://[2001:db8::1]:8443/x": "2001-db8--1_8443",
	} {
		c, k, err := IssuedTPMPathsIn("/d", broker)
		if err != nil || c != "/d/issued/"+want+".0123abcd.pem" || k != "/d/issued/"+want+".0123abcd.tpmkey" {
			t.Errorf("%s: %s %s %v", broker, c, k, err)
		}
	}
	for _, bad := range []string{"http://broker.example", "https://", "https://u:p@broker.example", "broker.example:8443"} {
		if _, _, err := IssuedTPMPathsIn("/d", bad); err == nil {
			t.Errorf("%q made a path", bad)
		}
	}
	MachineID = func() (string, error) { return "", errors.New("no machine id") }
	if _, _, err := IssuedTPMPathsIn("/d", "https://broker.example"); err == nil {
		t.Error("a machine with no id made a path")
	}
}

// The machine's name is the first 8 hex digits of SHA-256 of
// /etc/machine-id as the file is (so `sha256sum /etc/machine-id` says it); a
// missing or empty file is an error.
func TestMachineID(t *testing.T) {
	prev := machineIDFile
	t.Cleanup(func() { machineIDFile = prev })
	machineIDFile = filepath.Join(t.TempDir(), "machine-id")
	if _, err := MachineID(); err == nil {
		t.Fatal("no machine-id file gave an id")
	}
	if err := os.WriteFile(machineIDFile, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := MachineID(); err == nil {
		t.Fatal("an empty machine-id file gave an id")
	}
	if err := os.WriteFile(machineIDFile, []byte("abc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// sha256("abc\n") = edeaaff3f1774ad2888673770c6d64097e391bc362d7d6fb34982ddf0efd18cb
	if id, err := MachineID(); err != nil || id != "edeaaff3" {
		t.Fatalf("MachineID = %q, %v", id, err)
	}
}

// asSystem stands path in for /etc/port49/config.yaml for the rest of the
// test, owned by owner in root's place.
func asSystem(t *testing.T, path string, owner uint32) {
	t.Helper()
	oldPath, oldOwner := SystemPath, SystemOwner
	SystemPath, SystemOwner = path, owner
	t.Cleanup(func() { SystemPath, SystemOwner = oldPath, oldOwner })
}

// ~/.port49 is the directory, $PORT49_CONFIG names another file, and plan
// 9a's directory is kept for the pins alone (decision 43 ruling 24).
func TestTheDirectories(t *testing.T) {
	t.Setenv("HOME", "/home/alice")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv(EnvConfig, "")
	if Dir() != "/home/alice/.port49" || Path() != "/home/alice/.port49/config.yaml" ||
		LegacyDir() != "/home/alice/.config/port49" {
		t.Fatalf("%s %s %s", Dir(), Path(), LegacyDir())
	}
	t.Setenv(EnvConfig, "/srv/p49.yaml")
	t.Setenv("XDG_CONFIG_HOME", "/x")
	if Path() != "/srv/p49.yaml" || Dir() != "/home/alice/.port49" || LegacyDir() != "/x/port49" {
		t.Fatalf("%s %s %s", Dir(), Path(), LegacyDir())
	}
}

// The personal file is over the system file, key by key; each file's
// relative paths are its own directory's, and the CA is read from the file
// whose key won. The system file alone is a config.
func TestLoadAllLayersYoursOverTheSystemFile(t *testing.T) {
	sys := private(t, "config.yaml", "broker: https://sys.example:8443\nbroker_ca: ca.pem\nmethod: oidc\n"+
		"oidc_issuer: https://idp.example\noidc_redirect_port: 18000\n")
	if err := os.WriteFile(filepath.Join(filepath.Dir(sys), "ca.pem"), []byte("SYSTEM CA"), 0o644); err != nil {
		t.Fatal(err)
	}
	asSystem(t, sys, uint32(os.Getuid()))
	t.Setenv("XDG_CONFIG_HOME", privateDir(t))
	mine := private(t, "config.yaml", "broker: https://mine.example:8443\noidc_redirect_port: 18001\n")
	f, ok, err := LoadAll(mine, false)
	if err != nil || !ok || f.Broker != "https://mine.example:8443" || f.OIDCRedirectPort != 18001 ||
		f.Method != "oidc" || f.OIDCIssuer != "https://idp.example" ||
		f.BrokerCA != filepath.Join(filepath.Dir(sys), "ca.pem") || string(f.BrokerCAPEM) != "SYSTEM CA" {
		t.Fatalf("%+v %v %v", f, ok, err)
	}
	f, ok, err = LoadAll(filepath.Join(privateDir(t), "config.yaml"), false)
	if err != nil || !ok || f.Broker != "https://sys.example:8443" || string(f.BrokerCAPEM) != "SYSTEM CA" {
		t.Fatalf("the system file alone: %+v %v %v", f, ok, err)
	}
	// A CA the system file names is refused in the system file's name.
	if err := os.Chmod(filepath.Join(filepath.Dir(sys), "ca.pem"), 0o666); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadAll(mine, false); err == nil || !strings.Contains(err.Error(), "broker_ca in "+sys) {
		t.Fatalf("a CA others can write: %v", err)
	}
}

// A key reference is not a path (plan 9c): it is carried byte for byte, not
// joined to the file's directory, and the words issued_key_store and
// broker_crl take are checked.
func TestKeyReferencesAreNotPaths(t *testing.T) {
	key := "pkcs11:id=%01?module-path=/usr/lib/libykcs11.so"
	touch := "pkcs11:id=%02?module-path=/usr/lib/libykcs11.so"
	p := private(t, "config.yaml", "key: \""+key+"\"\ntouch_key: \""+touch+"\"\n"+
		"issued_key_store: tpm\nissued_key: \"tpm:file=/var/lib/p/issued.tss\"\nbroker_crl: require\n")
	f, ok, err := Load(p)
	if err != nil || !ok {
		t.Fatalf("ok %v err %v", ok, err)
	}
	if f.Key != key || f.TouchKey != touch || f.IssuedKeyStore != "tpm" ||
		f.IssuedKey != "tpm:file=/var/lib/p/issued.tss" || f.BrokerCRL != "require" {
		t.Fatalf("%+v", f)
	}
	for body, want := range map[string]string{
		"issued_key_store: floppy\n": "auto, file, tpm, secure_enclave or pkcs11",
		"broker_crl: maybe\n":        "check, require or off",
		"touch_key: /k.pem\n":        "touch_key",
		"issued_key: /k.pem\n":       "issued_key",
	} {
		if _, _, err := Load(private(t, "config.yaml", body)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", body, err, want)
		}
	}
	sys := private(t, "config.yaml", "touch_key: \"pkcs11:id=%09\"\nissued_key_store: file\n")
	asSystem(t, sys, uint32(os.Getuid()))
	t.Setenv("XDG_CONFIG_HOME", privateDir(t))
	f, ok, err = LoadAll(p, false)
	if err != nil || !ok || f.TouchKey != touch || f.IssuedKeyStore != "tpm" {
		t.Fatalf("the personal file's touch_key must win: %+v %v %v", f, ok, err)
	}
}

// Neither file is no config; a named file must be there.
func TestLoadAllWithNeitherFile(t *testing.T) {
	asSystem(t, filepath.Join(t.TempDir(), "none.yaml"), uint32(os.Getuid()))
	t.Setenv("XDG_CONFIG_HOME", privateDir(t))
	p := filepath.Join(privateDir(t), "config.yaml")
	if _, ok, err := LoadAll(p, false); ok || err != nil {
		t.Fatalf("ok %v err %v", ok, err)
	}
	if _, _, err := LoadAll(p, true); err == nil || err.Error() != p+": no such file" {
		t.Fatalf("named: %v", err)
	}
}

// The system file names the broker for every user on the host, so it is
// root's alone; this user's own is refused, naming the owner it needs.
func TestASystemFileNotRootsIsRefused(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("run as root, this user's file is root's")
	}
	sys := private(t, "config.yaml", "broker: https://sys.example:8443\n")
	asSystem(t, sys, 0)
	if _, _, err := LoadAll(filepath.Join(privateDir(t), "config.yaml"), false); err == nil ||
		!strings.Contains(err.Error(), sys+" is not owned by root") || !strings.Contains(err.Error(), "chown root "+sys) {
		t.Fatalf("%v", err)
	}
	// Writable by others, it is refused as any config file is.
	asSystem(t, sys, uint32(os.Getuid()))
	if err := os.Chmod(sys, 0o664); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadAll(filepath.Join(privateDir(t), "config.yaml"), false); err == nil ||
		!strings.Contains(err.Error(), sys+" is writable by others") {
		t.Fatalf("%v", err)
	}
}

// A config file at plan 9a's place, with none at the default path, is
// refused naming the move; with one at the default path it is not read.
func TestAConfigAtPlan9asPlaceIsRefused(t *testing.T) {
	asSystem(t, filepath.Join(t.TempDir(), "none.yaml"), uint32(os.Getuid()))
	xdg := privateDir(t)
	t.Setenv("XDG_CONFIG_HOME", xdg)
	old := filepath.Join(xdg, "port49", "config.yaml")
	if err := WritePrivate(old, []byte("broker: https://old.example:8443\n"), "port49 config file"); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(privateDir(t), "config.yaml")
	if _, _, err := LoadAll(p, false); err == nil ||
		err.Error() != old+" is where plan 9a kept port49's config file; port49 reads "+p+" now: mkdir -m 700 -p "+
			filepath.Dir(p)+" && mv "+old+" "+p+" (if it holds a certificate login, add `method: x509`)" {
		t.Fatalf("%v", err)
	}
	if err := os.WriteFile(p, []byte("broker: https://new.example:8443\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if f, ok, err := LoadAll(p, false); err != nil || !ok || f.Broker != "https://new.example:8443" {
		t.Fatalf("%+v %v %v", f, ok, err)
	}
}

// A root-owned file or directory this user cannot read is refused naming the
// mode it has, the mode it needs and that its installer sets it, never a
// chmod this user cannot make. /etc/shadow and /root stand in for an
// installer's file and directory; the mode asserted is the one they have.
func TestARootFileThisUserCannotReadNamesTheModeItNeeds(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can read them")
	}
	fi, err := os.Lstat("/etc/shadow")
	if _, oerr := os.Open("/etc/shadow"); err != nil || !errors.Is(oerr, fs.ErrPermission) {
		t.Skip("no unreadable root-owned file to test with")
	}
	_, err = ReadPrivate("/etc/shadow", 1<<10, "port49 config file")
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("/etc/shadow is %04o and owned by root", fi.Mode().Perm())) ||
		!strings.Contains(err.Error(), "installed it must make it 0644") || strings.Contains(err.Error(), "chmod") {
		t.Fatalf("file: %v", err)
	}
	di, err := os.Lstat("/root")
	if _, derr := os.Stat("/root/x"); err != nil || !errors.Is(derr, fs.ErrPermission) {
		t.Skip("no unsearchable root-owned directory to test with")
	}
	_, err = ReadPrivate("/root/x/config.yaml", 1<<10, "port49 config file")
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("/root is %04o and owned by root", di.Mode().Perm())) ||
		!strings.Contains(err.Error(), "installed it must make it 0755") || strings.Contains(err.Error(), "chmod") {
		t.Fatalf("directory: %v", err)
	}
}

// Under the user's own home a root-owned file is no installer's: the fix is
// the user's, with sudo; outside it, the installer's.
func TestTheFixForARootFileUnderYourHomeIsYours(t *testing.T) {
	t.Setenv("HOME", "/home/alice")
	t.Setenv("USER", "alice")
	if got := fixFor("/home/alice/.port49/config.yaml", "0644"); got !=
		"make it yours (sudo chown alice /home/alice/.port49/config.yaml) or 0644" {
		t.Fatalf("%q", got)
	}
	if got := fixFor("/etc/port49/config.yaml", "0644"); got != "whoever installed it must make it 0644" {
		t.Fatalf("%q", got)
	}
	if got := fixFor("/home/alicia/x", "0644"); strings.Contains(got, "yours") {
		t.Fatalf("a sibling of the home directory: %q", got)
	}
}

// The usual install is a link chain (libykcs11.so -> libykcs11.so.2 -> the
// file): the directory each link's target is in is judged too, or a module
// whose real file sits where someone else can write would pass (review I2).
func TestCheckOwnedWalksTheDirectoryOfALinkTarget(t *testing.T) {
	open := filepath.Join(privateDir(t), "open")
	if err := os.Mkdir(open, 0o700); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(open, "libmod.so.2")
	if err := os.WriteFile(real, []byte("ELF"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(privateDir(t), "libmod.so")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := CheckOwned(link); err != nil {
		t.Fatalf("a link into a 0700 directory: %v", err)
	}
	if err := os.Chmod(open, 0o770); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(open, 0o700) })
	if err := CheckOwned(link); err == nil || !strings.Contains(err.Error(), open) {
		t.Fatalf("a link into a group-writable directory: %v", err)
	}
}

// A PKCS#11 module is code the agent runs: the file, the links to it and
// every directory above it are judged (plan 9c, ruling 3; pre-flight I1).
func TestCheckOwnedJudgesTheModuleAndItsDirectories(t *testing.T) {
	dir := privateDir(t)
	mod := filepath.Join(dir, "libmod.so")
	if err := os.WriteFile(mod, []byte("ELF"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := CheckOwned(mod); err != nil {
		t.Fatalf("a 0755 module in a 0700 directory: %v", err)
	}

	if err := os.Chmod(mod, 0o775); err != nil {
		t.Fatal(err)
	}
	if err := CheckOwned(mod); err == nil || !strings.Contains(err.Error(), mod) ||
		!strings.Contains(err.Error(), "writable by others") {
		t.Fatalf("a group-writable module: %v", err)
	}
	if err := os.Chmod(mod, 0o755); err != nil {
		t.Fatal(err)
	}

	open := filepath.Join(privateDir(t), "open")
	if err := os.Mkdir(open, 0o700); err != nil {
		t.Fatal(err)
	}
	inOpen := filepath.Join(open, "libmod.so")
	if err := os.WriteFile(inOpen, []byte("ELF"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o770); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(open, 0o700) })
	if err := CheckOwned(inOpen); err == nil || !strings.Contains(err.Error(), open) {
		t.Fatalf("a module in a group-writable directory: %v", err)
	}

	// The libykcs11.so chain: a link of the user's to a regular file of the
	// user's passes.
	link := filepath.Join(dir, "libmod.so.2")
	if err := os.Symlink("libmod.so", link); err != nil {
		t.Fatal(err)
	}
	if err := CheckOwned(link); err != nil {
		t.Fatalf("a link to a regular file: %v", err)
	}

	// A link to a directory is no module.
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	dlink := filepath.Join(dir, "libdir.so")
	if err := os.Symlink("sub", dlink); err != nil {
		t.Fatal(err)
	}
	if err := CheckOwned(dlink); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("a link to a directory: %v", err)
	}
}
