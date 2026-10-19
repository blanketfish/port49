package main

import (
	"os"
	"path/filepath"
	"regexp"
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

func TestALongRunIsNeverPrinted(t *testing.T) {
	hex := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	for _, l := range normalize("- cert_sha256 " + hex + " seen\n- blob QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo= x\n") {
		if len(l) > 0 && (contains(l, hex) || contains(l, "QUJDREVG")) {
			t.Fatalf("a long run survived masking: %q", l)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// Every committed note, normalized, holds no long hex or base64 run: what
// notediff prints is what normalize returns.
func TestNoRealNoteKeepsALongRun(t *testing.T) {
	notes, _ := filepath.Glob("../../results/*.md")
	if len(notes) == 0 {
		t.Skip("no results notes")
	}
	long := regexp.MustCompile(`[0-9A-Za-z+/=]{24,}`)
	for _, n := range notes {
		b, err := os.ReadFile(n)
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range normalize(string(b)) {
			if long.MatchString(l) {
				t.Errorf("%s keeps a long run after masking: %d bytes, run lengths %v", filepath.Base(n), len(l), lens(long.FindAllString(l, -1)))
			}
		}
	}
}

func lens(ss []string) []int {
	var n []int
	for _, s := range ss {
		n = append(n, len(s))
	}
	return n
}
