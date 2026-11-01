//go:build hwkey && hwkey_dlopen

package pkcs11_test

import (
	"testing"

	"github.com/blanketfish/port49/internal/hwkey"
	"github.com/blanketfish/port49/internal/hwkey/hwtest"
	"github.com/blanketfish/port49/internal/hwkey/pkcs11"
)

// L86 (d): a token pulled with nothing signing since is not seen by State,
// which keeps the state last seen; Probe looks, with no PIN and no login, and
// finds it gone. The touch key is probed before an admin request is sent.
func TestProbeSeesAPulledTokenWithNoLogin(t *testing.T) {
	module, label := hwtest.SoftHSM(t)
	s, err := pkcs11.Open(uriFor(t, module, label), pin())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if got := s.Probe(); got != hwkey.Present {
		t.Fatalf("Probe with the token in: %v, want present", got)
	}
	logins := pkcs11.LoginCalls()
	hwtest.SoftHSMUnplug(t, label)
	if got := s.State(); got != hwkey.Present {
		t.Logf("State saw the pull by itself (%v): Probe is then a second look", got)
	}
	if got := s.Probe(); got != hwkey.Absent {
		t.Fatalf("Probe with the token pulled: %v, want absent", got)
	}
	if got := s.State(); got != hwkey.Absent {
		t.Fatalf("State after the Probe: %v, want absent", got)
	}
	if n := pkcs11.LoginCalls() - logins; n != 0 {
		t.Fatalf("Probe made %d C_Login calls, want 0", n)
	}
}
