//go:build hwkey_dlopen && !hwkey

package pkcs11

// closeProbe runs just before C_CloseSession. Outside the hwkey test build it
// does nothing, so no release build has a hook to set or read.
func closeProbe(*Module) {}
