//go:build l60probe

// The second L60 touch probe as it ran on 2026-10-13 (tests/lab/results/L60-ser8.md):
// after an untouched sign, is the token really logged out? Built and run as
// touch_test.go is (package pkcs11, -overlay, the tag removed); the l60probe
// tag keeps it out of every other build. The PIN is read from Ryan's terminal
// with echo off, sent once and zeroed; no signature byte is printed.

package pkcs11

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"os"
	"testing"
	"time"

	"golang.org/x/term"
)

// TestL60TouchAfterTimeout asks whether the token is really logged out after
// a touch times out, or whether libykcs11 only reports it so: after the
// untouched sign, it calls C_Sign straight on the same session, past the
// Signer's locked state. Lab probe only (scratch, -overlay). The PIN is read
// with echo off, sent once, and zeroed; no signature byte is printed.
func TestL60TouchAfterTimeout(t *testing.T) {
	if os.Getenv("PORT49_L60_TOUCH") != "1" {
		t.Skip("set PORT49_L60_TOUCH=1 and run from a terminal")
	}
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer tty.Close()
	u, err := ParseURI("pkcs11:id=%02?module-path=/usr/lib/x86_64-linux-gnu/libykcs11.so")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(tty, "PIV PIN (not shown): ")
	pin, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(u, pin) // Open zeroes pin
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	pub := s.Public().(*ecdsa.PublicKey)
	digest := sha256.Sum256([]byte("port49 L60 touch probe 2"))
	mech, param, err := s.mechanism(nil)
	if err != nil {
		t.Fatal(err)
	}
	raw := func(cell string) {
		start := time.Now()
		sig, err := s.m.sign(s.session, mech, param, s.handle, digest[:])
		took := time.Since(start).Round(time.Millisecond)
		if err != nil {
			t.Logf("%s: raw C_Sign error after %v: %v", cell, took, err)
			return
		}
		der, derr := rawECDSAToDER(sig, s.sigSize)
		t.Logf("%s: raw C_Sign signed in %v, verifies: %v", cell, took, derr == nil && ecdsa.VerifyASN1(pub, digest[:], der))
	}

	fmt.Fprintln(tty, "\n>>> Cell A: do NOT touch. Press Enter, then hands off until it reports.")
	_, _ = term.ReadPassword(int(tty.Fd()))
	raw("cell A (untouched)")

	fmt.Fprintln(tty, "\n>>> Cell B: TOUCH when it blinks. Press Enter to start.")
	_, _ = term.ReadPassword(int(tty.Fd()))
	raw("cell B (touched, same session, after the timeout)")

	fmt.Fprintln(tty, "\n>>> Cell C: TOUCH again. Press Enter to start.")
	_, _ = term.ReadPassword(int(tty.Fd()))
	raw("cell C (touched again)")
}
