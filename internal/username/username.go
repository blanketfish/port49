// Package username is the canonical form of a device-facing username, in a
// package that imports nothing of port49's. Both sides of one import edge need
// it: the daemon, which must canonicalize whatever the wire sends, and the
// minter, which refuses a name canonicalization would change — and the daemon
// imports the minter's package for the device tag.
package username

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
