package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An overlay is laid over the capture its sha256 names and no other: one that
// names none of the captures given, or a second for the same capture, is
// refused, and so is a single capture.
func TestOverlaysMatchTheirCaptures(t *testing.T) {
	r := "../../results/"
	a, b := r+"L26-keywords-juniper_vjunos-router.yaml", r+"L26-keywords-juniper_vsrx.yaml"
	oa, ob := r+"L26b-keywords-juniper_vjunos-router.yaml", r+"L26b-keywords-juniper_vsrx.yaml"
	stale := filepath.Join(t.TempDir(), "stale.yaml")
	raw, err := os.ReadFile(ob)
	if err != nil {
		t.Fatal(err)
	}
	first, rest, _ := strings.Cut(string(raw), "\n")
	if err := os.WriteFile(stale, []byte(first[:len(first)-64]+strings.Repeat("0", 64)+"\n"+rest), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{a},
		{"-overlay", stale, a, b},
		{"-overlay", oa, "-overlay", oa, a, b},
	} {
		if err := run(args); err == nil {
			t.Errorf("ran: %q", args)
		}
	}
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()
	stdout := os.Stdout
	os.Stdout = devnull
	defer func() { os.Stdout = stdout }()
	if err := run([]string{"-overlay", oa, "-overlay", ob, a, b}); err != nil {
		t.Fatal(err)
	}
}
