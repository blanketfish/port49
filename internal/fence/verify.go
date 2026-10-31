package fence

import (
	"crypto/ed25519"
	"fmt"

	"github.com/rhwendt/port49/internal/edkey"
)

// maxVerifyKey bounds a verify key's read: a PEM ed25519 public key is 113
// bytes.
const maxVerifyKey = 64 << 10

// ReadVerifyKeys reads each verify key behind the fence and parses it. A
// verify key is public, but whoever can write it decides which inventories
// are accepted (spec §13, decision 30), so it is held to the policy file's
// rule. key is the configuration key that lists them, for the error.
func ReadVerifyKeys(key string, files []string) ([]ed25519.PublicKey, error) {
	out := make([]ed25519.PublicKey, 0, len(files))
	for i, f := range files {
		raw, err := Read(f, maxVerifyKey, "verify key")
		if err != nil {
			return nil, fmt.Errorf("%s[%d] %s: %w", key, i, f, err)
		}
		k, err := edkey.ParseEd25519Public(raw, f)
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: %w", key, i, err)
		}
		out = append(out, k)
	}
	return out, nil
}
