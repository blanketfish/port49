package fence

import (
	"io/fs"
	"strings"
	"unicode/utf8"

	"github.com/blanketfish/port49/internal/printsafe"
)

// shortPathMax is how much of a path a Short keeps: its last 32 bytes, the
// file name and a directory or two. Two of them, the cause, the values and
// the remedy stay within shortMax. The tightest is the ancestor mode refusal,
// at 191 bytes: a longer path tail or wording drops its remedy.
const shortPathMax = 32

// shortMax bounds a Short. The enrollment store's late reason puts 99 bytes
// around it and the broker cuts that reason at 300 bytes
// (internal/broker/signin.go, CheckEnrollmentStore), so a Short of at most
// 192 bytes leaves the whole reason standing (#60).
const shortMax = 192

// Refusal is a refusal the fence words itself: an owner, a mode, a link, a
// size or a file type that fails its rule. Error is the full text, naming
// every path whole, for a start error, a log line or a command's stderr.
// Short is the same check, the value seen against the one wanted and the
// remedy, with each path cut to its last shortPathMax bytes, for a reason
// that is cut short (#60). It wraps err when that is set, so errors.Is and
// errors.As see through it as they saw through the fmt.Errorf it replaces.
type Refusal struct {
	full, short string
	err         error
}

func (r *Refusal) Error() string { return r.full }

// Short is the refusal in at most shortMax bytes, its ellipsis included. The
// cut is a backstop, never the design: every refusal's worst case fits whole
// with its remedy (TestEveryFenceRefusalHasAShortFormThatKeepsItsCause), and a
// longer wording must be shortened there, not left to the cut, which drops the
// end, where the remedy is.
func (r *Refusal) Short() string {
	s := r.short
	if len(s) <= shortMax {
		return printsafe.Line(s, shortMax)
	}
	n := shortMax - len("…")
	for n > 0 && !utf8.RuneStart(s[n]) {
		n-- // never split a rune
	}
	return printsafe.Line(s[:n], shortMax) + "…"
}

func (r *Refusal) Unwrap() error { return r.err }

// shown is a path as a Short names it.
func shown(p string) string { return printsafe.Tail(p, shortPathMax) }

// Brief is err's text for a line that is cut short. Every Refusal's full text
// is replaced by its Short, and every fs.PathError's path by its tail, inside
// whatever err wraps them in, an errors.Join included. Any other error's text
// is unchanged.
func Brief(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	var walk func(error)
	walk = func(e error) {
		switch x := e.(type) {
		case nil:
			return
		case *Refusal:
			s = strings.Replace(s, x.Error(), x.Short(), 1)
			return
		case *fs.PathError:
			s = strings.Replace(s, x.Error(), x.Op+" "+shown(x.Path)+": "+x.Err.Error(), 1)
			return
		}
		switch u := e.(type) {
		case interface{ Unwrap() error }:
			walk(u.Unwrap())
		case interface{ Unwrap() []error }:
			for _, c := range u.Unwrap() {
				walk(c)
			}
		}
	}
	walk(err)
	return s
}
