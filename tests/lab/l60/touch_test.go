//go:build l60probe

// The L60 touch probe as it ran on 2026-10-13 (tests/lab/results/L60-ser8.md),
// kept as the capture of that run. Like probe_test.go it is package pkcs11 and
// ran through `go test -tags hwkey_dlopen -overlay` with this file mapped into
// internal/hwkey/pkcs11 and the build tag removed; the l60probe tag keeps it
// out of every other build. Ryan ran it from his own terminal: the PIN is read
// from /dev/tty with echo off, sent once and zeroed, and no signature byte is
// printed.

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

// TestL60Touch signs twice with slot 9c (touch policy always): once touched,
// once left alone, and reports how long each took and what the library said.
// Lab probe only; it lives in scratch and is compiled through -overlay. The
// PIN is read from the terminal with echo off, sent once, and zeroed; no
// signature byte is printed.
func TestL60Touch(t *testing.T) {
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
	pub, ok := s.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("slot 9c public key is %T, want *ecdsa.PublicKey", s.Public())
	}
	digest := sha256.Sum256([]byte("port49 L60 touch probe"))

	fmt.Fprintln(tty, "\n>>> Cell 1: TOUCH the YubiKey when it blinks. Press Enter to start.")
	_, _ = term.ReadPassword(int(tty.Fd()))
	start := time.Now()
	sig, err := s.Sign(nil, digest[:], nil)
	took := time.Since(start)
	if err != nil {
		t.Logf("cell 1 (touched): error after %v: %v", took.Round(time.Millisecond), err)
	} else {
		t.Logf("cell 1 (touched): signed in %v, %d-byte signature, verifies: %v",
			took.Round(time.Millisecond), len(sig), ecdsa.VerifyASN1(pub, digest[:], sig))
	}

	fmt.Fprintln(tty, "\n>>> Cell 2: do NOT touch. Press Enter, then keep your hands off until it reports.")
	_, _ = term.ReadPassword(int(tty.Fd()))
	start = time.Now()
	sig, err = s.Sign(nil, digest[:], nil)
	took = time.Since(start)
	if err != nil {
		t.Logf("cell 2 (untouched): error after %v: %v", took.Round(time.Millisecond), err)
	} else {
		t.Logf("cell 2 (untouched): SIGNED in %v with no touch, %d-byte signature", took.Round(time.Millisecond), len(sig))
	}
	t.Logf("key state after cell 2: %v", s.State())

	fmt.Fprintln(tty, "\n>>> Cell 3: TOUCH again. Press Enter to start (is the session still usable after a timeout?).")
	_, _ = term.ReadPassword(int(tty.Fd()))
	start = time.Now()
	sig, err = s.Sign(nil, digest[:], nil)
	took = time.Since(start)
	if err != nil {
		t.Logf("cell 3 (touched after a timeout): error after %v: %v", took.Round(time.Millisecond), err)
	} else {
		t.Logf("cell 3 (touched after a timeout): signed in %v, verifies: %v",
			took.Round(time.Millisecond), ecdsa.VerifyASN1(pub, digest[:], sig))
	}
}
