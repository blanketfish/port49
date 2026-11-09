package fence

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"
)

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
