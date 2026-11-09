package fence

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"unicode/utf8"
)

// Short is bounded at shortMax with its ellipsis counted, is cut on a rune
// boundary, shows no control byte, and leaves a text that fits whole (#60).
func TestShortIsBoundedWithItsEllipsis(t *testing.T) {
	for _, tail := range []string{"", "é", "日本", "\x1b[2J\x00‮"} {
		for pad := 0; pad < 4; pad++ { // slide the multibyte text across the cut
			short := strings.Repeat("a", shortMax-6+pad) + strings.Repeat("日\x07é\x1b", 12) + tail
			got := (&Refusal{short: short}).Short()
			if len(got) > shortMax || !utf8.ValidString(got) || !strings.HasSuffix(got, "…") {
				t.Errorf("pad %d tail %q: %d bytes, valid %v: %q", pad, tail, len(got), utf8.ValidString(got), got)
			}
			if strings.ContainsAny(got, "\x07\x1b\x00‮") {
				t.Errorf("pad %d: a control or format character survives: %q", pad, got)
			}
		}
	}
	exact := strings.Repeat("é", shortMax/2)
	if got := (&Refusal{short: exact}).Short(); got != exact {
		t.Errorf("a text of exactly shortMax bytes was cut: %d bytes", len(got))
	}
	if got := (&Refusal{short: exact + "x"}).Short(); len(got) > shortMax || !strings.HasSuffix(got, "…") {
		t.Errorf("one byte over: %d bytes %q", len(got), got)
	}
}

// Brief shortens every Refusal an errors.Join carries, not the first alone.
func TestBriefShortensEveryRefusalInAJoin(t *testing.T) {
	long := func(c string) string { return "/" + strings.Repeat(c, 100) + "/f.json" }
	a := &Refusal{full: "the file " + long("a") + " is wrong", short: "the file " + shown(long("a")) + ": wrong"}
	b := &Refusal{full: "the file " + long("b") + " is wrong", short: "the file " + shown(long("b")) + ": wrong"}
	pe := &fs.PathError{Op: "open", Path: long("c"), Err: fs.ErrPermission}
	got := Brief(fmt.Errorf("x: %w", errors.Join(a, fmt.Errorf("y: %w", b), pe)))
	want := "x: " + a.Short() + "\ny: " + b.Short() + "\nopen " + shown(long("c")) + ": permission denied"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

// Brief puts a Refusal's Short in place of its full text inside whatever
// wraps it, names a PathError's path by its tail, and leaves any other
// error's text as it is (#60).
func TestBriefShortensOnlyWhatTheFenceNames(t *testing.T) {
	long := "/" + strings.Repeat("d", 250) + "/enrollments.json"
	tail := "…" + long[len(long)-shortPathMax:]
	r := &Refusal{full: "the file " + long + " is wrong", short: "the file " + shown(long) + ": wrong - fix it"}
	if got, want := Brief(fmt.Errorf("verify_key_files[0]: %w", r)), "verify_key_files[0]: the file "+tail+": wrong - fix it"; got != want {
		t.Errorf("a wrapped refusal: %q, want %q", got, want)
	}
	pe := &fs.PathError{Op: "open", Path: long, Err: fs.ErrPermission}
	if got, want := Brief(fmt.Errorf("x: %w", pe)), "x: open "+tail+": permission denied"; got != want {
		t.Errorf("a path error: %q, want %q", got, want)
	}
	if got := Brief(errors.New("plain")); got != "plain" {
		t.Errorf("another error: %q", got)
	}
	if got := Brief(nil); got != "" {
		t.Errorf("nil: %q", got)
	}
}
