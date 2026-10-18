package lab

import (
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"
)

// A trustpoint that holds an earlier run's CA (same name, other key) must not
// pass for this run's: the screen is matched by fingerprint, in either digest
// and either colon form, never by subject.
func TestL73ScreenHasCertMatchesByFingerprint(t *testing.T) {
	now := time.Now()
	p, err := l73NewPKI("ecdsa", now)
	if err != nil {
		t.Fatal(err)
	}
	q, err := l73NewPKI("ecdsa", now)
	if err != nil {
		t.Fatal(err)
	}
	root, other := p.Root.Cert, q.Root.Cert
	colon := func(b []byte) string {
		parts := make([]string, len(b))
		for i, x := range b {
			parts[i] = fmt.Sprintf("%02X", x)
		}
		return strings.Join(parts, ":")
	}
	s1, s256 := sha1.Sum(root.Raw), sha256.Sum256(root.Raw)
	for name, screen := range map[string]string{
		"sha1 colon":    "CA certificate 0:\nSHA1 Fingerprint=" + colon(s1[:]) + "\npurposes: sslserver",
		"sha256 colon":  "Fingerprint(sha-256): " + colon(s256[:]),
		"sha1 bare low": "fp " + strings.ToLower(strings.ReplaceAll(colon(s1[:]), ":", "")),
	} {
		if !l73ScreenHasCert(screen, root) {
			t.Errorf("%s: this run's CA not found on its own screen", name)
		}
		if l73ScreenHasCert(screen, other) {
			t.Errorf("%s: another CA matched", name)
		}
	}
	if l73ScreenHasCert("Trustpoint: l73-root\nsubject= "+root.Subject.String(), root) {
		t.Error("a subject alone matched: only a fingerprint says it is this run's CA")
	}
}
