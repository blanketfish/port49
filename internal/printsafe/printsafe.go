// Package printsafe makes another party's text safe to print on one line:
// the inventory service's text for its clients, a source of truth's for the
// service.
package printsafe

import (
	"strings"
	"unicode"
)

// Line is s as one line of at most limit bytes: a control character, a
// format character (a bidi override), a line or paragraph separator, or an
// invalid byte is `?`, never terminal control or a forged line, and past
// limit bytes it is cut and marked.
func Line(s string, limit int) string {
	cut := len(s) > limit
	if cut {
		s = s[:limit]
	}
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			return '?'
		}
		return r
	}, strings.ToValidUTF8(s, "?"))
	if cut {
		s += "…"
	}
	return s
}
