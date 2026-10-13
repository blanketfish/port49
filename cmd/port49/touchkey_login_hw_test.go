//go:build hwkey && hwkey_dlopen && linux

package main

import (
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/clientkey"
	"github.com/rhwendt/port49/internal/hwkey"
	"github.com/rhwendt/port49/internal/hwkey/hwtest"
	"github.com/rhwendt/port49/internal/hwkey/pkcs11"
	"github.com/rhwendt/port49/internal/testpki"
)

// A session key unlocked from pin-source leaves s.pin empty, so the touch key
// on the same token has no PIN to be unlocked with. The token's login is the
// application's, shared by its sessions, so the touch key reads it back and
// goes Present with no PIN sent (final re-review M14).
func TestATouchKeyOnTheTokenOfAPINSourceSessionKeyGoesPresent(t *testing.T) {
	l := newLabBroker(t, time.Hour)
	touchRef := tokenWithTheLabKey(t, l)
	ref := refWithPINSource(t, touchRef, hwtest.SoftHSMUserPIN)
	cert, err := clientkey.LoadPair(filepath.Join(l.dir, testpki.LabClientCert), ref, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &agent.Config{Cert: cert}
	t.Cleanup(func() { _ = cert.PrivateKey.(hwkey.Key).Close() })
	if st := cert.PrivateKey.(hwkey.Key).State(); st != hwkey.Present {
		t.Fatalf("the session key is %v after its pin-source login", st)
	}
	logins := pkcs11.LoginCalls()
	sf := &sessionFlags{touchKey: touchRef}
	sf.openTouchKey(cfg, io.Discard)
	if cfg.TouchKey == nil {
		t.Fatalf("the touch key did not open: %q", cfg.TouchKeyUnusable)
	}
	t.Cleanup(func() { _ = cfg.TouchKey.Close() })
	if st := cfg.TouchKey.State(); st != hwkey.Present {
		t.Fatalf("the touch key is %v, want present", st)
	}
	if n := pkcs11.LoginCalls() - logins; n != 0 {
		t.Fatalf("the touch key sent a PIN: %d C_Login call(s)", n)
	}
}
