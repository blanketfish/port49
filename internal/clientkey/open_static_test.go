//go:build !hwkey_dlopen

package clientkey

import (
	"path/filepath"
	"strings"
	"testing"
)

// The static build (the container image's) carries no purego: a pkcs11: or
// secure-enclave: reference says so and names the client release (ruling 22),
// while a tpm: file still reaches the TPM backend.
func TestTheStaticBuildSaysItHasNoPKCS11(t *testing.T) {
	if HasPKCS11 {
		t.Fatal("HasPKCS11 is true in the static build")
	}
	for _, ref := range []string{"pkcs11:id=%01?module-path=/x.so", "secure-enclave:label=x"} {
		_, err := Open(ref, nil)
		if err == nil || !strings.Contains(err.Error(), "built without PKCS#11 support") ||
			!strings.Contains(err.Error(), "client release") {
			t.Errorf("%s: %v", ref, err)
		}
	}
	_, err := Open("tpm:file="+filepath.Join(t.TempDir(), "missing.tss"), nil)
	if err == nil || strings.Contains(err.Error(), "built without") {
		t.Fatalf("tpm:file= must reach tpm.Open: %v", err)
	}
}
