//go:build hwkey

// Package hwtest is the hardware-key tests' harness: SoftHSM2 tokens for the
// PKCS#11 backend (hwtest_pkcs11.go) and, from Task 4, swtpm for the TPM's.
// It builds only under the hwkey tag, which only `make test-hw` sets, so no
// release build carries it.
package hwtest

import (
	"os"
	"testing"
)

// Required reports whether a missing tool or module is a failure, not a
// skip: $PORT49_TEST_HW_REQUIRED is set, as `make test-hw` and CI set it, so a
// run cannot go green by skipping.
func Required() bool { return os.Getenv("PORT49_TEST_HW_REQUIRED") != "" }

// Missing ends t for want of a tool or module: a failure when Required, else
// a skip.
func Missing(t testing.TB, why string) {
	t.Helper()
	if Required() {
		t.Fatalf("PORT49_TEST_HW_REQUIRED is set and %s", why)
	}
	t.Skip(why)
}
