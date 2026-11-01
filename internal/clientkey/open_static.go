//go:build !hwkey_dlopen

package clientkey

import (
	"fmt"

	"github.com/blanketfish/port49/internal/hwkey"
)

// HasPKCS11 is whether this build carries the purego backends (the
// hwkey_dlopen tag, ruling 22): false here.
const HasPKCS11 = false

// openToken refuses by name: the static build, the container image's, has no
// dynamic loader to load a PKCS#11 module with.
func openToken(ref string, pin []byte) (hwkey.Key, error) {
	clear(pin)
	return nil, fmt.Errorf("clientkey: %s: this port49 was built without PKCS#11 support (the static build, as in the "+
		"container image); use the client release", scheme(ref))
}

// scheme is ref's scheme, never the rest of it.
func scheme(ref string) string {
	for i := 0; i < len(ref); i++ {
		if ref[i] == ':' {
			return ref[:i+1]
		}
	}
	return ref
}
