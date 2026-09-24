package policy

import (
	"strings"
	"unicode"
)

// CompareVersions orders two vendor version strings with the one generic
// comparator of spec §5.5 ("Version comparison"; §13, decision 7): tokenize
// into runs of digits and runs of letters, discarding separators and
// upper-casing letters, then compare element by element — digit runs
// numerically, letter runs by equality only, a letter run against a digit run
// not at all, and a sequence that is a prefix of the other is the lower.
//
// It returns -1, 0 or 1, and false when the two cannot be compared. Semver is
// deliberately not used: it would sort Junos service release `21.4R3-S5`
// below `21.4R3`.
func CompareVersions(a, b string) (int, bool) {
	x, y := versionTokens(a), versionTokens(b)
	if len(x) == 0 || len(y) == 0 {
		return 0, false
	}
	for i := 0; i < len(x) && i < len(y); i++ {
		xn, xNum := x[i].number()
		yn, yNum := y[i].number()
		switch {
		case xNum && yNum:
			if c := xn.cmp(yn); c != 0 {
				return c, true
			}
		case !xNum && !yNum:
			// Letters are equality only: `M > F` means nothing across vendors.
			if x[i] != y[i] {
				return 0, false
			}
		default:
			return 0, false
		}
	}
	switch {
	case len(x) < len(y):
		return -1, true
	case len(x) > len(y):
		return 1, true
	}
	return 0, true
}

type versionToken string

// numeric is a digit run without its leading zeros, compared by length and
// then lexically, so no run is too long to compare.
type numeric string

func (t versionToken) number() (numeric, bool) {
	if t == "" || !unicode.IsDigit(rune(t[0])) {
		return "", false
	}
	s := strings.TrimLeft(string(t), "0")
	return numeric(s), true
}

func (n numeric) cmp(m numeric) int {
	if len(n) != len(m) {
		if len(n) < len(m) {
			return -1
		}
		return 1
	}
	return strings.Compare(string(n), string(m))
}

// versionTokens splits v into digit and letter runs; everything else — `.`,
// `-`, `(`, `)`, `_`, `/`, spaces — separates.
func versionTokens(v string) []versionToken {
	var out []versionToken
	var cur strings.Builder
	kind := 0 // 0 none, 1 digits, 2 letters
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, versionToken(cur.String()))
			cur.Reset()
		}
		kind = 0
	}
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
			if kind != 1 {
				flush()
				kind = 1
			}
			cur.WriteRune(r)
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			if kind != 2 {
				flush()
				kind = 2
			}
			cur.WriteRune(unicode.ToUpper(r))
		default:
			flush()
		}
	}
	flush()
	return out
}
