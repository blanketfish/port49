package port49d

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// armSpy stands in for the host's signal handling and records when it was asked to start.
type armSpy struct {
	k                *kt
	calls, releases  int
	namesAtFirstCall []string
}

func (a *armSpy) arm() (func() bool, func()) {
	a.calls++
	if a.calls == 1 {
		a.namesAtFirstCall = a.k.names()
	}
	return func() bool { return false }, func() { a.releases++ }
}

// Until the first file is made there is nothing to clean up, so the signals are the host's: a
// Ctrl-C during a user lookup, a directory stat or the read of an --import file ends the command at
// once. The check that no file exists when the catching starts, and that a refusal before it never
// starts it, is what keeps that true.
func TestKeyCatchesSignalsOnlyOnceItIsAboutToWriteAFile(t *testing.T) {
	refused := map[string]func(k *kt) int{
		"an unknown user": func(k *kt) int {
			_, _, c := k.run("sealing", "--dir", k.dir, "--daemon-user", "no-such-user-p49", "--broker-user", k.user)
			return c
		},
		"a missing directory": func(k *kt) int {
			_, _, c := k.run("sealing", "--dir", filepath.Join(k.dir, "none"), "--daemon-user", k.user, "--broker-user", k.user)
			return c
		},
		"a name that exists": func(k *kt) int {
			if err := os.WriteFile(k.path("encryption.key"), []byte("EXISTING-NOT-A-REAL-KEY"), 0o400); err != nil {
				t.Fatal(err)
			}
			_, _, c := k.seal()
			return c
		},
		"an import that is too short": func(k *kt) int {
			src := filepath.Join(t.TempDir(), "copy")
			if err := os.WriteFile(src, goodKey(t)[:31], 0o600); err != nil {
				t.Fatal(err)
			}
			_, _, c := k.seal("--import", src)
			return c
		},
	}
	for name, run := range refused {
		k := newKT(t, goodKey(t))
		spy := &armSpy{k: k}
		k.env.stop, k.env.arm = nil, spy.arm
		if code := run(k); code != 1 {
			t.Errorf("%s: exit %d, want 1", name, code)
		}
		if spy.calls != 0 {
			t.Errorf("%s: the signals were caught before any file was to be made", name)
		}
	}
	for _, how := range []string{"drawn", "imported"} {
		k := newKT(t, goodKey(t))
		spy := &armSpy{k: k}
		k.env.stop, k.env.arm = nil, spy.arm
		args := []string{}
		if how == "imported" {
			src := filepath.Join(t.TempDir(), "copy")
			if err := os.WriteFile(src, goodKey(t), 0o600); err != nil {
				t.Fatal(err)
			}
			args = append(args, "--import", src)
		}
		if _, errs, code := k.seal(args...); code != 0 {
			t.Fatalf("%s: exit %d: %s", how, code, errs)
		}
		if spy.calls != 1 || spy.releases != 1 {
			t.Errorf("%s: armed %d times and released %d, want once each", how, spy.calls, spy.releases)
		}
		if len(spy.namesAtFirstCall) != 0 {
			t.Errorf("%s: %v existed when the signals were caught", how, spy.namesAtFirstCall)
		}
	}
	k := newKT(t, make([]byte, 16))
	spy := &armSpy{k: k}
	k.env.stop, k.env.arm = nil, spy.arm
	if _, errs, code := k.device("core-v2"); code != 0 || spy.calls != 1 || spy.releases != 1 || len(spy.namesAtFirstCall) != 0 {
		t.Errorf("device: exit %d (%s), armed %d, released %d, files at arming %v", code, errs, spy.calls, spy.releases, spy.namesAtFirstCall)
	}
}

// What is linked into place is already complete, 0400 (0440 for a device key) and owned as asked:
// the mode and owner are set on the temporary file, never after the name is visible.
func TestKeyFilesAreCompleteAndPrivateBeforeTheyAreLinked(t *testing.T) {
	for _, c := range []struct {
		name string
		mode os.FileMode
		size int64
		run  func(k *kt) int
	}{
		{"sealing", 0o400, 32, func(k *kt) int { _, _, code := k.seal(); return code }},
		{"device", 0o440, 33, func(k *kt) int { _, _, code := k.device("core-v2"); return code }},
	} {
		k := newKT(t, goodKey(t), goodKey(t))
		real, links, bad := k.env.link, 0, 0
		k.env.link = func(oldname, newname string) error {
			links++
			fi, err := os.Lstat(oldname)
			if err != nil || fi.Mode() != c.mode || fi.Size() != c.size {
				bad++
			}
			if uid, _, ok := ownerOf(fi); err == nil && ok && uid != k.uid {
				bad++
			}
			return real(oldname, newname)
		}
		if code := c.run(k); code != 0 {
			t.Fatalf("%s: exit %d", c.name, code)
		}
		if links == 0 || bad != 0 {
			t.Errorf("%s: %d links, %d of them to a file that was not complete, %v and owned as asked", c.name, links, bad, c.mode)
		}
	}
}

// A temporary file is opened O_EXCL: a name another user planted, a symlink above all, is skipped
// and never written through. The first name drawn here is a link to a file of someone else's.
func TestKeyNeverWritesThroughATemporaryNameItDidNotMake(t *testing.T) {
	for _, c := range []struct {
		name string
		run  func(k *kt) int
	}{
		{"sealing", func(k *kt) int { _, _, code := k.seal(); return code }},
		{"device", func(k *kt) int { _, _, code := k.device("core-v2"); return code }},
	} {
		k := newKT(t, goodKey(t), goodKey(t))
		victim := filepath.Join(t.TempDir(), "victim")
		if err := os.WriteFile(victim, []byte("EXISTING-NOT-A-REAL-KEY"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(victim, k.path(".key.aaaa")); err != nil {
			t.Fatal(err)
		}
		names, i := []string{"aaaa", "bbbb", "cccc"}, 0
		k.env.suffix = func() (string, error) {
			s := names[min(i, len(names)-1)]
			i++
			return s, nil
		}
		if code := c.run(k); code != 0 {
			t.Fatalf("%s: exit %d", c.name, code)
		}
		if b, _ := os.ReadFile(victim); string(b) != "EXISTING-NOT-A-REAL-KEY" {
			t.Errorf("%s: the file behind a planted temporary name was written through", c.name)
		}
		if fi, err := os.Lstat(k.path(".key.aaaa")); err != nil || fi.Mode()&os.ModeSymlink == 0 {
			t.Errorf("%s: the planted link was replaced or removed", c.name)
		}
	}
}

// A symlink is not a copied key: --import opens its path without following one.
func TestKeySealingImportRefusesASymlink(t *testing.T) {
	k := newKT(t)
	real := filepath.Join(t.TempDir(), "real")
	if err := os.WriteFile(real, goodKey(t), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, errs, code := k.seal("--import", link); code != 1 || errs == "" {
		t.Errorf("exit %d, stderr %q, want 1", code, errs)
	}
	k.wantNames("a symlink import")
}

// The next step names the one file to copy, and the usage says what a number means.
func TestKeySealingSaysWhichFileToCopyAndWhatANumberIs(t *testing.T) {
	for id, want := range map[string]string{"": "copy encryption.key ", "e2": "copy encryption-e2.key "} {
		k := newKT(t, goodKey(t))
		args := []string{}
		if id != "" {
			args = append(args, "--id", id)
		}
		out, _, code := k.seal(args...)
		if code != 0 || !strings.Contains(out, want) || strings.Contains(out, "both files") {
			t.Errorf("--id %q: exit %d, output %q, want it to say %q", id, code, out, want)
		}
	}
	_, errs, _ := newKT(t).run()
	if !strings.Contains(errs, "a number is both uid and gid") {
		t.Errorf("the usage does not say what a number means: %q", errs)
	}
}
