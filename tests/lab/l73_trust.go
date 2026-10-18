package lab

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"strings"
)

// l73ScreenHasCert reports whether a device's trustpoint screen shows c, by
// fingerprint (SHA-1 or SHA-256, with or without colons, either case). A
// trustpoint keeps its name between runs, so a subject proves nothing: after
// an earlier run's CA the name matches and the key does not. NX-OS's CA import
// has no Done marker, so this is the only evidence the import took this run's.
func l73ScreenHasCert(screen string, c *x509.Certificate) bool {
	var hex16 strings.Builder
	for _, r := range strings.ToLower(screen) {
		if r >= '0' && r <= '9' || r >= 'a' && r <= 'f' {
			hex16.WriteRune(r)
		} else if r != ':' && r != ' ' {
			hex16.WriteByte('.') // any other character breaks a run of digits
		}
	}
	s1, s256 := sha1.Sum(c.Raw), sha256.Sum256(c.Raw)
	return strings.Contains(hex16.String(), hex.EncodeToString(s1[:])) ||
		strings.Contains(hex16.String(), hex.EncodeToString(s256[:]))
}
