package l60

import (
	"crypto/x509"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
)

// chainWords names each link of a chain: the touch slot's attestation, the
// device certificate, the session slot's attestation.
func chainWords(chain []string, err error, describe func(*x509.Certificate) string) string {
	if err != nil {
		return "error: " + err.Error()
	}
	names := []string{"touch", "device", "session"}
	var out []string
	for i, b := range chain {
		name := "link " + itoa(i)
		if i < len(names) {
			name = names[i]
		}
		der, err := base64.RawURLEncoding.DecodeString(b)
		if err != nil {
			out = append(out, name+" undecodable")
			continue
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			out = append(out, name+" unparsable")
			continue
		}
		out = append(out, name+" "+describe(c))
	}
	return strings.Join(out, "; ")
}

// labCertDER is the certificate the import step made for slot 9a, nil when
// there is none.
func labCertDER(dir string) []byte {
	raw, err := os.ReadFile(filepath.Join(dir, fileSlotCert))
	if err != nil {
		return nil
	}
	c, err := parsePEMCert(raw)
	if err != nil {
		return nil
	}
	return c.Raw
}
