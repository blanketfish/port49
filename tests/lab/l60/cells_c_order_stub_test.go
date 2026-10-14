//go:build !(hwkey && hwkey_dlopen)

package l60

import "testing"

// TestL60COrder reads the token's certificate objects through pkcs11's
// hwkey test hooks, so it builds only with -tags hwkey,hwkey_dlopen
// (cells_c_order_test.go).
func TestL60COrder(t *testing.T) {
	t.Skip("cell c_order builds only with -tags hwkey,hwkey_dlopen and CGO_ENABLED=0 (tests/lab/l60/RUNBOOK.md)")
}
