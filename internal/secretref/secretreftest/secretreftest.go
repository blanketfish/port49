// Package secretreftest is what the tests of every type that holds a secret
// share: the verbs to print it under and every spelling of it to look for.
package secretreftest

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// Verbs are the fmt verbs a holder is printed under.
var Verbs = []string{"%v", "%+v", "%#v", "%s", "%x", "%d", "%q", "%t", "%c"}

// Forms are the spellings of secret that must not appear in any output: the
// raw bytes, hex, base64, the decimal list and the 0x list fmt prints for a
// byte slice or array, each whole and as its first few elements (a verb that
// truncates still shows the start). All are derived from secret.
func Forms(secret []byte) [][]byte {
	var dec, hexList []string
	for _, b := range secret {
		dec = append(dec, fmt.Sprint(b))
		hexList = append(hexList, fmt.Sprintf("0x%02x", b))
	}
	forms := []string{string(secret), hex.EncodeToString(secret), base64.StdEncoding.EncodeToString(secret),
		base64.RawURLEncoding.EncodeToString(secret), fmt.Sprintf("%q", secret), fmt.Sprintf("%#v", secret),
		strings.Join(dec, " "), strings.Join(dec[:min(4, len(dec))], " "), strings.Join(dec, ", "),
		strings.Join(hexList, ", "), strings.Join(hexList[:min(2, len(hexList))], ", "), strings.Join(hexList[:min(2, len(hexList))], " "),
		string(secret[:min(6, len(secret))]), hex.EncodeToString(secret[:min(4, len(secret))])}
	out := make([][]byte, len(forms))
	for i, f := range forms {
		out[i] = []byte(f)
	}
	return out
}

// Leak is the first of forms found in out, or "" (its index, never the form,
// so a failure prints no secret).
func Leak(out []byte, forms [][]byte) string {
	for i, f := range forms {
		if bytes.Contains(out, f) {
			return fmt.Sprintf("form %d", i)
		}
	}
	return ""
}
