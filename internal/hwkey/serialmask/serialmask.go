// Package serialmask is the one rule that keeps a YubiKey's serial out of
// output. It is a leaf package so the L60 harness, hwkeysetup and pkcs11 all
// call the same function and the rule cannot drift.
package serialmask

import "regexp"

var (
	serialHash  = regexp.MustCompile(`(#|%23)\d+`)
	serialWords = regexp.MustCompile(`(?i)(serial[^0-9\n]{0,4})\d+`)
)

// MaskSerial masks a device serial: libykcs11's token label carries it
// ("YubiKey PIV #<serial>"), and a results note or a message keeps it out.
func MaskSerial(s string) string {
	s = serialHash.ReplaceAllString(s, "${1}<serial>")
	return serialWords.ReplaceAllString(s, "${1}<serial>")
}
