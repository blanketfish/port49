//go:build hwkey && hwkey_dlopen

package main

import "github.com/rhwendt/port49/internal/hwkey/hwtest"

// SoftHSM2 reads SOFTHSM2_CONF once, at C_Initialize: one configuration and
// token directory per test binary, set before TestMain runs a test. The agent
// a login starts is this binary again and inherits the variable.
func init() { runTests = hwtest.SoftHSMMain }
