//go:build linux

package port49d

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/fence"
)

// ownedAs makes fence.FileOwner report uid for the files named in names,
// and the real owner for the rest: CI has no second uid to own a file.
func ownedAs(t *testing.T, uid uint32, names ...string) {
	t.Helper()
	real := fence.FileOwner
	t.Cleanup(func() { fence.FileOwner = real })
	fence.FileOwner = func(fi fs.FileInfo) (uint32, bool) {
		for _, n := range names {
			if fi.Name() == n {
				return uid, true
			}
		}
		return real(fi)
	}
}

// broker.state_dir, and marks.json and witness.json in it, are written by
// port49-broker alone (plan 7e, Ruling 12; Task 13 review carry): whoever
// else owns one could put back a lifted mark or forge the restore witness.
// One owned by another user is refused, naming it, and the writer writes
// nothing; root's is kept, as is the user's own 0700 directory, the shape
// of a container's or a Kubernetes volume's state directory owned by the
// service user, and a 0750 one, as a volume mounted group-readable is.
func TestTheStateDirsWriterRefusesAnotherOwner(t *testing.T) {
	dir := t.TempDir() // this process's user's, made 0700: a normal volume
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	marks := filepath.Join(dir, stateMarksFile)
	if err := ownStateDir(dir); err != nil {
		t.Fatalf("a 0700 directory of this user's with nothing in it: %v", err)
	}
	if err := writeOwnerOnly(marks, []byte(`{"marks":[]}`)); err != nil {
		t.Fatalf("a write into it: %v", err)
	}
	if fi, err := os.Stat(marks); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("written %v %v, want 0600", fi, err)
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := ownStateDir(dir); err != nil {
		t.Fatalf("a 0750 directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, stateWitnessFile), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name  string
		uid   uint32
		owned []string
		want  string
	}{
		{"root owns the directory", 0, []string{filepath.Base(dir)}, ""},
		{"root owns marks.json", 0, []string{stateMarksFile}, ""},
		{"another user owns the directory", 4242, []string{filepath.Base(dir)}, "broker.state_dir " + dir +
			" is owned by uid 4242"},
		{"another user owns marks.json", 4242, []string{stateMarksFile}, marks + " is owned by uid 4242"},
		{"another user owns witness.json", 4242, []string{stateWitnessFile}, filepath.Join(dir, stateWitnessFile) +
			" is owned by uid 4242"},
	} {
		t.Run(c.name, func(t *testing.T) {
			ownedAs(t, c.uid, c.owned...)
			target := marks
			if c.owned[0] == stateWitnessFile {
				target = filepath.Join(dir, stateWitnessFile)
			}
			err := ownStateDir(dir)
			werr := writeOwnerOnly(target, []byte(c.name))
			if c.want == "" {
				if err != nil || werr != nil {
					t.Fatalf("refused: %v; %v", err, werr)
				}
				return
			}
			for _, e := range []error{err, werr} {
				if e == nil || !strings.Contains(e.Error(), c.want) || !strings.Contains(e.Error(), "chown") {
					t.Fatalf("%v, want %q", e, c.want)
				}
			}
			if got, _ := os.ReadFile(target); string(got) == c.name {
				t.Fatal("the refused writer wrote")
			}
		})
	}
	// A link in a state file's place is refused, never written through.
	other := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.Remove(marks); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, marks); err != nil {
		t.Fatal(err)
	}
	if err := ownStateDir(dir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("a symlink at marks.json: %v", err)
	}
	if err := writeOwnerOnly(marks, []byte("x")); err == nil {
		t.Fatal("written through a symlink")
	}
	if _, err := os.Lstat(other); err == nil {
		t.Fatal("the link's target was created")
	}
	// A directory others can write is refused at the write as at the load.
	if err := os.Remove(marks); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := writeOwnerOnly(marks, []byte("x")); err == nil || !strings.Contains(err.Error(), "writable by") {
		t.Fatalf("a group-writable state_dir: %v", err)
	}
}

// port49-broker refuses to start on a broker.state_dir another user owns,
// before it waits for the store or serves anything.
func TestABrokerOnAnotherUsersStateDirDoesNotStart(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	f := splitFleet(t)
	cfg, _ := loadBroker(t, f.broker)
	ownedAs(t, 4242, filepath.Base(cfg.Broker.StateDir))
	// Bounded: a start that wrongly went on would serve until its ctx ends.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	err := runBroker(ctx, f.broker)
	if err == nil || !strings.Contains(err.Error(), "broker.state_dir") || !strings.Contains(err.Error(), "uid 4242") ||
		strings.Contains(out.String(), "listening on") {
		t.Fatalf("%v\n%s", err, out.String())
	}
}

// A broker.state_dir that is a symbolic link is refused, as before, but
// named as one, with where it points, so the refusal does not read as
// wrong when config.LoadBroker, which follows it, took it (Task 15 review
// M-7).
func TestAStateDirThatIsALinkIsNamedAsOne(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "state")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	err := ownStateDir(link)
	if err == nil || !strings.Contains(err.Error(), "is a symbolic link: point broker.state_dir at the directory "+
		"itself ("+target+")") {
		t.Fatalf("a state_dir that is a link: %v", err)
	}
}
