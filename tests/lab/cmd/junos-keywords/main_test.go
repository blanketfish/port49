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
		{a, b, b1, b1},
		{a, b, b1, r + "L26b-keywords-juniper_vsrx.yaml"},
		{"-overlay", stale, a, b, b1},
		{"-overlay", oa, "-overlay", oa, a, b, b1},
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

// Every run of an image beside a capture given must be given too: a run left
// off, a run committed later (run2) and not named, and an image with no
// latest run are each refused, and so is a file beside them named as a run
// of the image in no form the tool reads.
func TestEveryRunIsGiven(t *testing.T) {
	r := "../../results/"
	dir := t.TempDir()
	copyTo := func(dir, name string, raw []byte) string {
		f := filepath.Join(dir, name)
		if err := os.WriteFile(f, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return f
	}
	a := copyTo(dir, "L26-keywords-juniper_vjunos-router.yaml", must(os.ReadFile(r+"L26-keywords-juniper_vjunos-router.yaml")))
	b := copyTo(dir, "L26-keywords-juniper_vsrx.yaml", must(os.ReadFile(r+"L26-keywords-juniper_vsrx.yaml")))
	run1 := must(os.ReadFile(r + "L26-keywords-juniper_vsrx.run1.yaml"))
	b1 := copyTo(dir, "L26-keywords-juniper_vsrx.run1.yaml", run1)

	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()
	stdout := os.Stdout
	os.Stdout = devnull
	defer func() { os.Stdout = stdout }()

	if err := run([]string{a, b, b1}); err != nil {
		t.Fatalf("every run given: %v", err)
	}
	if err := run([]string{a, b}); err == nil {
		t.Error("ran with run1 left off")
	}
	b2 := copyTo(dir, "L26-keywords-juniper_vsrx.run2.yaml", append([]byte("# another run\n"), run1...))
	if err := run([]string{a, b, b1}); err == nil {
		t.Error("ran with run2 beside the captures and not given")
	}
	if err := run([]string{a, b, b1, b2}); err != nil {
		t.Errorf("run2 given: %v", err)
	}
	copyTo(dir, "L26-keywords-juniper_vsrx.bak.yaml", run1)
	if err := run([]string{a, b, b1, b2}); err == nil {
		t.Error("ran with a stray run file beside the captures")
	}

	// An image committed beside the captures and left off the command line
	// is refused: its tree is one more to intersect (kw-merge review M4).
	third := t.TempDir()
	ta := copyTo(third, "L26-keywords-juniper_vjunos-router.yaml", must(os.ReadFile(a)))
	tb := copyTo(third, "L26-keywords-juniper_vsrx.yaml", must(os.ReadFile(b)))
	tb1 := copyTo(third, "L26-keywords-juniper_vsrx.run1.yaml", run1)
	if err := run([]string{ta, tb, tb1}); err != nil {
		t.Fatalf("two images: %v", err)
	}
	copyTo(third, "L26-keywords-juniper_vmx.yaml", append([]byte("# a third image\n"), must(os.ReadFile(a))...))
	if err := run([]string{ta, tb, tb1}); err == nil || !strings.Contains(err.Error(), "image juniper_vmx is committed") {
		t.Errorf("ran with a committed image left off: %v", err)
	}

	lone := t.TempDir()
	la := copyTo(lone, "L26-keywords-juniper_vjunos-router.yaml", must(os.ReadFile(a)))
	lb1 := copyTo(lone, "L26-keywords-juniper_vsrx.run1.yaml", run1)
	if err := run([]string{la, lb1}); err == nil {
		t.Error("ran with no latest vSRX run")
	}
}

func must(raw []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return raw
}
