package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestNormalizeMasksOnlyWhatARerunAlwaysChanges(t *testing.T) {
	a := normalize("- **Date measured:** 2026-10-18\n- **Run:** commit `7ff5249f`, x\nlogin at 2026-10-18T06:22:54Z on port 48350 as alice03\n- (h) NX-OS opened 5 connections\n")
	b := normalize("- **Date measured:** 2026-11-20\n- **Run:** commit `0abc1234`, x\nlogin at 2026-11-20T01:02:03Z on port 51111 as alice05\n- (h) NX-OS opened 5 connections\n")
	if r, ad := changed(a, b, 0.2); len(r) != 0 || len(ad) != 0 {
		t.Fatalf("only volatile lines differ, yet: -%q +%q", r, ad)
	}
}

func TestAChangedTimingIsAnObservation(t *testing.T) {
	a := normalize("- operator fact: NX-OS waits exactly 5.00 s before its flight\n")
	b := normalize("- operator fact: NX-OS waits exactly 3.00 s before its flight\n")
	if r, ad := changed(a, b, 0.2); len(r) != 1 || len(ad) != 1 {
		t.Fatalf("5.00 s to 3.00 s is a measured change: -%q +%q", r, ad)
	}
}

func TestATimingWithinToleranceIsNotReported(t *testing.T) {
	a := normalize("- token logins took about 21.2 s\n")
	b := normalize("- token logins took about 20.9 s\n")
	if r, ad := changed(a, b, 0.2); len(r)+len(ad) != 0 {
		t.Fatalf("1.4%% is run-to-run noise: -%q +%q", r, ad)
	}
}

func TestChangedNamesAChangedCount(t *testing.T) {
	a := normalize("- (h) NX-OS opened 5 connections\n")
	b := normalize("- (h) NX-OS opened 6 connections\n")
	if r, ad := changed(a, b, 0.2); len(r) != 1 || len(ad) != 1 {
		t.Fatalf("a changed count is an observation: -%q +%q", r, ad)
	}
	a = normalize("- the reply was 40 bytes\n")
	b = normalize("- the reply was 41 bytes\n")
	if r, ad := changed(a, b, 0.2); len(r) != 1 || len(ad) != 1 {
		t.Fatalf("integers compare exactly, whatever the tolerance: -%q +%q", r, ad)
	}
	a = normalize("- image SR Linux 26.7.2\n")
	b = normalize("- image SR Linux 26.8.2\n")
	if r, ad := changed(a, b, 0.2); len(r) != 1 || len(ad) != 1 {
		t.Fatalf("a bare decimal is a version, not a duration: -%q +%q", r, ad)
	}
}

func TestARangeIsTwoDurations(t *testing.T) {
	a := normalize("- break-glass landed in 81–85ms\n")
	b := normalize("- break-glass landed in 83–86ms\n")
	if r, ad := changed(a, b, 0.2); len(r)+len(ad) != 0 {
		t.Fatalf("both ends of a range carry its unit: -%q +%q", r, ad)
	}
}

func TestMaskIsByKindNotByLength(t *testing.T) {
	for _, keep := range []string{
		"no_permit_dominates_deny",
		"TLS_CHACHA20_POLY1305_SHA256",
		"image `vrnetlab/juniper_vjunos-router:23.4R2-S2.1`", // the tag stays whole
		"diagnosis=admission_refused reason=device_quarantined",
	} {
		if got := normalize(keep + "\n"); len(got) != 1 || got[0] != keep {
			t.Errorf("an observation was masked: %q -> %q", keep, got)
		}
	}
}

func TestALongRunIsMasked(t *testing.T) {
	hex := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	b64u := "QUJD-REVG_R0hJSktMTU5PUFFSU1RVVldYWVo1"
	short := "1085c7dbdfa563e3"
	for _, secret := range []string{hex, b64u, short} {
		for _, l := range normalize("- cert_sha256 " + secret + " seen\n") {
			if strings.Contains(l, secret[:12]) {
				t.Errorf("a long run survived masking: %q", l)
			}
		}
	}
}

func TestRemovedKeepsFileOrder(t *testing.T) {
	old := []string{"- zebra 1", "- apple 1", "- mango 1", "- kiwi 1"}
	for i := 0; i < 20; i++ {
		r, _ := changed(old, nil, 0.2)
		if strings.Join(r, "|") != strings.Join(old, "|") {
			t.Fatalf("removed order varies: %q", r)
		}
	}
}

func TestUnitSpacingIsNotAChange(t *testing.T) {
	if r, a := changed(normalize("- took 5 s\n"), normalize("- took 5s\n"), 0.2); len(r)+len(a) != 0 {
		t.Fatalf("spacing: -%q +%q", r, a)
	}
}

func gitRepo(t *testing.T, notes map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		c := exec.Command("git", args...)
		c.Dir = dir
		c.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	for p, body := range notes {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, p), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run("add", ".")
	run("commit", "-q", "-m", "x")
	return dir
}

func TestCompareExitCodesAndRepoRootPaths(t *testing.T) {
	const note = "tests/lab/results/L1-x.md"
	dir := gitRepo(t, map[string]string{note: "- opened 5 connections\n"})
	sub := filepath.Join(dir, "tests", "lab") // a subdirectory: the path is still root-relative
	var out, errw bytes.Buffer

	if c := compare(sub, note, 0.2, true, &out, &errw); c != 0 || !strings.Contains(out.String(), "unchanged") {
		t.Fatalf("unchanged: exit %d, %q %q", c, out.String(), errw.String())
	}
	if err := os.WriteFile(filepath.Join(dir, note), []byte("- opened 6 connections\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if c := compare(sub, note, 0.2, true, &out, &errw); c != 1 || !strings.Contains(out.String(), "+ - opened 6") {
		t.Fatalf("changed with -fail-on-change: exit %d, %q", c, out.String())
	}
	if c := compare(sub, note, 0.2, false, &out, &errw); c != 0 {
		t.Fatalf("changed without -fail-on-change: exit %d", c)
	}
	out.Reset()
	if c := compare(sub, "tests/lab/results/new.md", 0.2, true, &out, &errw); c != 0 || !strings.Contains(out.String(), "new (not at HEAD)") {
		t.Fatalf("new note: exit %d, %q", c, out.String())
	}
	if c := compare(t.TempDir(), note, 0.2, true, &out, &errw); c != 2 {
		t.Fatalf("not a git repo must be an I/O error, got exit %d", c)
	}
	if err := os.Remove(filepath.Join(dir, note)); err != nil {
		t.Fatal(err)
	}
	if c := compare(sub, note, 0.2, true, &out, &errw); c != 2 {
		t.Fatalf("a note at HEAD that cannot be read: exit %d", c)
	}
}

// Every committed note, normalized, holds no 64-hex digest and no base64 run
// with a digit. The expressions are independent of the mask's.
func TestNoRealNoteKeepsADigestOrToken(t *testing.T) {
	notes, _ := filepath.Glob("../../results/*.md")
	if len(notes) == 0 {
		t.Fatal("no results notes found")
	}
	hex64 := regexp.MustCompile(`[0-9a-fA-F]{64}`)
	b64 := regexp.MustCompile(`[A-Za-z0-9+/_-]{24,}`)
	for _, n := range notes {
		b, err := os.ReadFile(n)
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range normalize(string(b)) {
			if hex64.MatchString(l) {
				t.Errorf("%s keeps a 64-hex run", filepath.Base(n))
			}
			for _, m := range b64.FindAllString(l, -1) {
				if strings.ContainsAny(m, "0123456789") && m != strings.ToUpper(m) && m != strings.ToLower(m) {
					t.Errorf("%s keeps a %d-byte base64-like run with a digit", filepath.Base(n), len(m))
				}
			}
		}
	}
}
