package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/blanketfish/port49/internal/hwkey"
)

// The token's own tries-left flags are said: fewer, or the last one with the
// way out.
func TestAPINTheTokenRefusedSaysTriesLeft(t *testing.T) {
	for _, tc := range []struct {
		e    hwkey.PINError
		want string
	}{
		{hwkey.PINError{}, "the token refused the PIN"},
		{hwkey.PINError{Low: true}, "the token refused the PIN; fewer tries are left"},
		{hwkey.PINError{Final: true, Low: true}, "one try is left before the key locks: unlock it with your token's own tool if it locks"},
	} {
		if got := pinRefusedWords(&tc.e); !strings.Contains(got, tc.want) {
			t.Errorf("%+v said %q, want %q", tc.e, got, tc.want)
		}
	}
}

// A blocked PIN is told with the way out and never as a refusal: whatever
// tries-left flags ride with it, the words do not invite another try.
func TestABlockedPINSaysHowToUnblockIt(t *testing.T) {
	for _, e := range []hwkey.PINError{{Blocked: true}, {Blocked: true, Low: true, Final: true}} {
		var stderr bytes.Buffer
		// As the signer wraps a CKR_PIN_LOCKED: the PINError under a message.
		pinFailure(fmt.Errorf("pkcs11: the token's PIN is locked: %w", &e), &stderr)
		got := stderr.String()
		if got != "port49 login: the key's PIN is blocked; unblock it with its PUK (ykman piv access unblock-pin) before trying again\n" {
			t.Errorf("%+v said %q", e, got)
		}
		if strings.Contains(got, "refused") || strings.Contains(got, "tries") {
			t.Errorf("%+v invites another try: %q", e, got)
		}
	}
}

// A locked key with no terminal and no pin-source is refused with the way
// out, and asks nothing.
func TestALockedKeyWithNoTerminalSaysWhatToDo(t *testing.T) {
	old := pinTerminal
	pinTerminal = func() (*os.File, error) { return nil, errors.New("no tty") }
	t.Cleanup(func() { pinTerminal = old })
	_, err := askPIN("tok")
	if err == nil || !strings.Contains(err.Error(), "there is no terminal to ask it on; run `port49 login` at a terminal, or give the key's URI a pin-source=file:///path if it has none") {
		t.Fatalf("%v", err)
	}
	// A file that is no terminal is no terminal either: /dev/null answers no TCGETS.
	pinTerminal = func() (*os.File, error) { return os.Open(os.DevNull) }
	if _, err := askPIN("tok"); !errors.Is(err, errNoPINTerminal) {
		t.Fatalf("/dev/null: %v", err)
	}
}

// The PIN comes on its descriptor, at most 64 bytes, and the descriptor is
// closed after.
func TestThePINDescriptorIsBounded(t *testing.T) {
	for _, tc := range []struct {
		pin string
		ok  bool
	}{{"123456", true}, {strings.Repeat("9", maxPIN), true}, {strings.Repeat("9", maxPIN+1), false}} {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.WriteString(tc.pin)
		w.Close()
		// readPINFD closes the descriptor it is given: give it a duplicate, so
		// r's finalizer does not close a number someone else holds by then.
		fd, err := syscall.Dup(int(r.Fd()))
		if err != nil {
			t.Fatal(err)
		}
		r.Close()
		s := sessionFlags{pinFD: fd}
		err = s.readPINFD()
		if (err == nil) != tc.ok || (tc.ok && !bytes.Equal(s.pin, []byte(tc.pin))) {
			t.Errorf("%d bytes: %v", len(tc.pin), err)
		}
		if err != nil && strings.Contains(err.Error(), tc.pin) {
			t.Errorf("the error holds the PIN")
		}
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err == nil {
			t.Errorf("the descriptor was left open")
		}
	}
}
