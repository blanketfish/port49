package api

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/testpki"
)

// A bundle is CAs alone, at most MaxCABundleCerts of them in at most
// MaxCABundleBytes; anything else is refused whole (decision 43 ruling 25).
func TestParseCABundle(t *testing.T) {
	now := time.Now()
	ca := func() []byte {
		c, err := testpki.NewCA("port49 test CA", now.Add(-time.Hour), now.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		return c.PEM()
	}
	cur, next := ca(), ca()
	certs, err := ParseCABundle(append(append([]byte{}, cur...), next...))
	if err != nil || len(certs) != 2 || !bytes.Equal(EncodeCABundle(certs), append(append([]byte{}, cur...), next...)) ||
		strings.Count(CAFingerprints(certs), "sha256:") != 2 {
		t.Fatalf("%d %v", len(certs), err)
	}
	issuer, err := testpki.NewCA("port49 test CA", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := issuer.Issue(testpki.Leaf{CommonName: "broker", NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	leafPEM, _, err := testpki.PEMs(leaf)
	if err != nil {
		t.Fatal(err)
	}
	five := bytes.Repeat(cur, 5)
	for name, c := range map[string]struct {
		raw  []byte
		want string
	}{
		"empty":     {nil, "no certificate"},
		"a leaf":    {leafPEM, "is not a CA"},
		"five":      {five, "over 4 certificates"},
		"too large": {bytes.Repeat([]byte(" "), MaxCABundleBytes+1), "over 65536"},
		"a key":     {[]byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"), "block 1 is not a CERTIFICATE"},
		"a key after": {append(append([]byte{}, cur...), "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"...),
			"block 2 is not a CERTIFICATE"},
		"trailing":    {append(append([]byte{}, cur...), "junk"...), "other than PEM"},
		"leading":     {append([]byte("junk\n"), cur...), "before block 1"},
		"between":     {bytes.Join([][]byte{cur, []byte("junk\n"), next}, nil), "before block 2"},
		"not parsing": {[]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), "block 1 does not parse"},
		"corrupt then a good one": {append([]byte("-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n"), cur...),
			"before block 1"},
		"corrupt alone": {[]byte("-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n"), "other than PEM"},
	} {
		_, err := ParseCABundle(c.raw)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
		// An error never quotes the input.
		if err != nil && (strings.Contains(err.Error(), "PRIVATE KEY") || strings.Contains(err.Error(), "port49 test CA") ||
			strings.Contains(err.Error(), "junk")) {
			t.Errorf("%s: the error quotes the input: %v", name, err)
		}
	}
	// Whitespace around and between blocks is fine.
	if certs, err := ParseCABundle(bytes.Join([][]byte{[]byte("\n\n"), cur, []byte("\n\n"), next, []byte("\n")}, nil)); err != nil ||
		len(certs) != 2 {
		t.Errorf("whitespace: %d %v", len(certs), err)
	}
}
