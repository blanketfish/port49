package authen

import "strings"

// Canonical is the form the broker writes tokens under and the daemon looks
// them up by: lower-cased, with a DOMAIN\ prefix or an @suffix removed (spec §2).
func Canonical(username string) string {
	u := strings.ToLower(strings.TrimSpace(username))
	if i := strings.LastIndex(u, `\`); i >= 0 {
		u = u[i+1:]
	}
	if i := strings.Index(u, "@"); i >= 0 {
		u = u[:i]
	}
	return u
}
