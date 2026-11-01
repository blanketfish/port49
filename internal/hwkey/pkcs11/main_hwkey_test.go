//go:build hwkey && hwkey_dlopen

package pkcs11_test

import (
	"os"
	"testing"

	"github.com/blanketfish/port49/internal/hwkey/hwtest"
)

// SoftHSM2 reads SOFTHSM2_CONF once, at C_Initialize, and Load keeps one
// Module per path: one configuration and token directory per test binary.
func TestMain(m *testing.M) { os.Exit(hwtest.SoftHSMMain(m)) }
