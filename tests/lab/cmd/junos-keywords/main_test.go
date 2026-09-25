package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An overlay pins the latest capture of its image by sha256 and is laid over
// every run of that image: one that names none of the captures given, or an
// earlier run, or a second for the same image, is refused, and so are a
// single image, two latest runs of one image, and a file not named as a
// capture.
func TestOverlaysMatchTheirCaptures(t *testing.T) {
	r := "../../results/"
	a, b := r+"L26-keywords-juniper_vjunos-router.yaml", r+"L26-keywords-juniper_vsrx.yaml"
	b1 := r + "L26-keywords-juniper_vsrx.run1.yaml"
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
	// The overlay re-pinned to the earlier run: its sha256 names b1.
	sum := sha256.Sum256(must(os.ReadFile(b1)))
	early := filepath.Join(t.TempDir(), "early.yaml")
	if err := os.WriteFile(early, []byte(first[:len(first)-64]+hex.EncodeToString(sum[:])+"\n"+rest), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{a},
		{b, b1},
		{a, b, b},
		{a, b, r + "L26b-keywords-juniper_vsrx.yaml"},
		{"-overlay", stale, a, b},
		{"-overlay", oa, "-overlay", oa, a, b},
		{"-overlay", early, a, b, b1},
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
	if err := run([]string{"-overlay", oa, "-overlay", ob, a, b1, b}); err != nil {
		t.Fatal(err)
	}
}

func must(raw []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return raw
}
