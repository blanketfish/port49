//go:build hwkey_dlopen && !hwkey

package pkcs11

// closeProbe runs just before C_CloseSession. Outside the hwkey test build it
// does nothing, so no release build has a hook to set or read.
func closeProbe(*Module) {}

// fakeTokenFlags and fakeLoginRV are the test harness's (BlockPIN); outside
// the hwkey test build the token's own flags and C_Login answer stand.
func fakeTokenFlags() uint      { return 0 }
func fakeLoginRV() (uint, bool) { return 0, false }
