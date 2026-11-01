package keyfile

import (
	"crypto/ed25519"

	"github.com/blanketfish/port49/internal/edkey"
)

// LoadEd25519 reads the inventory service's signing key (spec §13, decision
// 30): one PKCS#8 "PRIVATE KEY" block holding an ed25519 key, read with
// ReadSecret's rule. No error quotes the file.
func LoadEd25519(path string) (ed25519.PrivateKey, error) {
	raw, err := ReadSecret(path)
	if err != nil {
		return nil, err
	}
	return edkey.ParsePrivate(raw, path)
}
