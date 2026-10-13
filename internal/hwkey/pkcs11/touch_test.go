//go:build hwkey && hwkey_dlopen

package pkcs11_test

import (
	"crypto"
	"errors"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/hwkey"
	"github.com/rhwendt/port49/internal/hwkey/hwtest"
	"github.com/rhwendt/port49/internal/hwkey/pkcs11"
)

// libykcs11 reports an untouched sign as CKR_USER_NOT_LOGGED_IN after about
// 14.4s while the token stays logged in (L60, 2026-10-13). A not-logged-in
// that took 5s or more is a touch timeout; one that answers at once is a lock.
func signAfter(t *testing.T, took time.Duration) (s *pkcs11.Signer, err error, calls func() int) {
	t.Helper()
	module, label := hwtest.SoftHSM(t)
	s, err = pkcs11.Open(uriFor(t, module, label), pin())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	calls, restore := pkcs11.FakeSign(s, pkcs11.RVUserNotLoggedIn, took)
	t.Cleanup(restore)
	_, err = s.Sign(nil, make([]byte, 32), crypto.SHA256)
	return s, err, calls
}

func TestAnUntouchedSignThatTook14sIsATouchTimeoutAndTheKeyStaysUnlocked(t *testing.T) {
	s, err, calls := signAfter(t, 14400*time.Millisecond)
	if !errors.Is(err, hwkey.ErrTouchTimeout) || errors.Is(err, hwkey.ErrLocked) {
		t.Fatalf("Sign = %v, want ErrTouchTimeout", err)
	}
	if s.State() != hwkey.Present {
		t.Fatalf("state %v after a touch timeout, want Present", s.State())
	}
	if got, want := err.Error(), "hwkey: no touch within 15s; touch the key when it blinks and try again"; got != want {
		t.Fatalf("message %q, want %q", got, want)
	}
	// The next Sign asks the token again instead of refusing at once.
	if calls() != 1 {
		t.Fatalf("%d C_Sign calls, want 1", calls())
	}
	s.Sign(nil, make([]byte, 32), crypto.SHA256)
	if calls() != 2 {
		t.Fatalf("%d C_Sign calls after a second Sign, want 2", calls())
	}
}

func TestANotLoggedInAnsweredAtOnceIsLockedAndTheNextSignRefusesWithoutTheToken(t *testing.T) {
	s, err, calls := signAfter(t, 0)
	if !errors.Is(err, hwkey.ErrLocked) || errors.Is(err, hwkey.ErrTouchTimeout) {
		t.Fatalf("Sign = %v, want ErrLocked", err)
	}
	if s.State() != hwkey.Locked {
		t.Fatalf("state %v, want Locked", s.State())
	}
	if _, err := s.Sign(nil, make([]byte, 32), crypto.SHA256); !errors.Is(err, hwkey.ErrLocked) || calls() != 1 {
		t.Fatalf("second Sign = %v after %d C_Sign calls, want ErrLocked with 1", err, calls())
	}
}

func TestExactlyFiveSecondsIsATouchTimeoutAndJustUnderIsNot(t *testing.T) {
	if _, err, _ := signAfter(t, 5*time.Second); !errors.Is(err, hwkey.ErrTouchTimeout) {
		t.Fatalf("a not-logged-in after exactly 5s: %v, want ErrTouchTimeout", err)
	}
	if s, err, _ := signAfter(t, 5*time.Second-time.Nanosecond); !errors.Is(err, hwkey.ErrLocked) || s.State() != hwkey.Locked {
		t.Fatalf("a not-logged-in after just under 5s: %v, want ErrLocked", err)
	}
}
