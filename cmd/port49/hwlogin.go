package main

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/clientkey"
	"github.com/rhwendt/port49/internal/hwkey"
	"github.com/rhwendt/port49/internal/hwkey/pkcs11"
)

// maxPIN is the longest PIN port49 takes: a token's own limit is lower.
const maxPIN = 64

// pinTerminal opens the controlling terminal a PIN is asked on; a var so a
// test supplies a pty. The caller closes the file.
var pinTerminal = func() (*os.File, error) { return os.OpenFile("/dev/tty", os.O_RDWR, 0) }

// loginStdinIsTerminal is whether `port49 login` has a person to type a PIN;
// a var so a test says it has.
var loginStdinIsTerminal = func() bool { return isTerminal(os.Stdin) }

// errNoPINTerminal is a login with a Locked key and no terminal. The way out
// is right whether or not the key has a pin-source: a key that has one is
// Locked only for a person to unlock, so naming one to set would mislead
// (re-review M17).
var errNoPINTerminal = errors.New("this key needs its PIN and there is no terminal to ask it on; " +
	"run `port49 login` at a terminal, or give the key's URI a pin-source=file:///path if it has none")

// askPIN asks for the PIN of the token named label on the controlling
// terminal, echo off, and returns it as bytes for the caller to zero. A
// signal while the prompt holds the terminal restores it first.
func askPIN(label string) ([]byte, error) {
	tty, err := pinTerminal()
	if err != nil || !isTerminal(tty) {
		if tty != nil {
			tty.Close()
		}
		return nil, errNoPINTerminal
	}
	defer tty.Close()
	fd := int(tty.Fd())
	if saved, err := term.GetState(fd); err == nil {
		restore := func() { _ = term.Restore(fd, saved) }
		defer restore()
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
		done := make(chan struct{})
		defer func() {
			signal.Stop(ch)
			close(done)
		}()
		go func() {
			select {
			case s := <-ch:
				restore()
				code := 1
				if n, ok := s.(syscall.Signal); ok {
					code = 128 + int(n)
				}
				os.Exit(code)
			case <-done:
			}
		}()
		// Echo goes off before the prompt is written, as readpassphrase does,
		// so nothing typed once the prompt shows is echoed.
		echoOff(fd)
	}
	fmt.Fprintf(tty, "PIN for %s: ", label)
	pin, err := term.ReadPassword(fd)
	fmt.Fprintln(tty)
	switch {
	case err != nil:
		clear(pin)
		return nil, fmt.Errorf("reading the PIN: %w", err)
	case len(pin) == 0:
		return nil, errors.New("no PIN was entered")
	case len(pin) > maxPIN:
		clear(pin)
		return nil, fmt.Errorf("a PIN is at most %d bytes", maxPIN)
	}
	return pin, nil
}

// pinBlockedWords is what a token whose PIN is blocked says to do.
const pinBlockedWords = hwkey.PINBlockedWords

// pinRefusedWords is what a PIN the token refused says, with the token's own
// tries-left flags.
func pinRefusedWords(pe *hwkey.PINError) string {
	if pe.Blocked {
		// Not a refusal that invites another try: the token takes no PIN.
		return pinBlockedWords
	}
	s := "the token refused the PIN"
	switch {
	case pe.Final:
		s += "; one try is left before the key locks: unlock it with your token's own tool if it locks"
	case pe.Low:
		s += "; fewer tries are left"
	}
	return s
}

// pinFailure says why a PIN did not unlock the key.
func pinFailure(err error, stderr io.Writer) {
	var pe *hwkey.PINError
	if errors.As(err, &pe) {
		fmt.Fprintln(stderr, "port49 login:", pinRefusedWords(pe))
		return
	}
	fmt.Fprintln(stderr, "port49 login:", unprefixed(err))
}

// tokenLabel names the token a Locked key is on, for the PIN prompt.
func tokenLabel(k hwkey.Key) string {
	if t, ok := k.(interface{ TokenLabel() string }); ok && t.TokenLabel() != "" {
		return t.TokenLabel()
	}
	return "your key"
}

// unlockForAgent asks a Locked key's PIN once and unlocks the key with it in
// this process, so a wrong PIN is found here and costs one try. The PIN is
// kept in sf.pin for the agent the login starts; the caller zeroes it. False
// is a login that has said why and ends.
func unlockForAgent(sf *sessionFlags, k hwkey.Key, stderr io.Writer) bool {
	switch k.State() {
	case hwkey.Absent:
		fmt.Fprintln(stderr, "port49 login: the key is not present: insert it and run `port49 login` again")
		return false
	case hwkey.Locked:
		pin, err := askPIN(tokenLabel(k))
		if err != nil {
			fmt.Fprintln(stderr, "port49 login:", err)
			return false
		}
		if err := k.Unlock(slices.Clone(pin)); err != nil {
			clear(pin)
			hwkey.MarkBlocked(k, err) // the token says whether this PIN can be tried again
			pinFailure(err, stderr)
			return false
		}
		sf.pin = pin
	}
	return true
}

// loginToHeldKey is `port49 login` with a key reference while an agent runs
// (pre-flight I15): the agent is asked, and the token is not opened, when it
// holds this login's key. done says the login is settled, with code.
//
// The agent holds the key when its certificate is the --cert file's, or, for
// the certificate on the token, when its key_ref is this key's canonical
// reference. Anything else is left to the ordinary login, which opens the
// token and names the mismatch.
func loginToHeldKey(ctx context.Context, sf *sessionFlags, stdout, stderr io.Writer) (code int, done bool) {
	if sf.broker == "" {
		return 0, false
	}
	c := agent.NewClient(sf.socket)
	st, err := c.Status(ctx)
	if err != nil || st.KeyState == "" || strings.TrimRight(sf.broker, "/") != st.Broker {
		return 0, false
	}
	var holds bool
	if sf.cert != "" {
		fp, err := certFileFingerprint(sf.cert)
		holds = err == nil && fp == st.CertFingerprint
	} else {
		holds = st.KeyRef != "" && st.KeyRef == clientkey.CanonicalRef(sf.key)
	}
	if !holds {
		return 0, false
	}
	return loginThroughAgent(ctx, sf, c, st, refLabel(sf.key), stdout, stderr), true
}

// loginThroughAgent is a login to the agent c, which holds this login's key
// in st.KeyState; the key is not opened here (ruling 8). A key that is out
// says to insert it; a Locked one is asked its PIN, under label, and unlocked
// through the agent; then the session is refreshed.
func loginThroughAgent(ctx context.Context, sf *sessionFlags, c *agent.Client, st agent.Status, label string,
	stdout, stderr io.Writer) int {
	switch st.KeyState {
	case hwkey.Absent.String():
		fmt.Fprintf(stderr, "port49 login: insert your key and run `port49 login` again; your session goes on until %s\n",
			st.SessionEndsAt)
		return 1
	case hwkey.Locked.String():
		pin, err := askPIN(label)
		if err != nil {
			fmt.Fprintln(stderr, "port49 login:", err)
			return 1
		}
		if err := c.Unlock(ctx, pin); err != nil {
			pinFailure(err, stderr)
			return 1
		}
	}
	return refreshRunning(ctx, sf, st, stdout, stderr)
}

// refLabel names the token a reference picks by its token= attribute, for a
// prompt made before the token is opened.
func refLabel(ref string) string {
	if u, err := pkcs11.ParseURI(ref); err == nil && u.Token != "" {
		return u.Token
	}
	return "your key"
}

// certFileFingerprint is agent.CertFingerprint of the first certificate in a
// PEM file.
func certFileFingerprint(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	for {
		var b *pem.Block
		if b, raw = pem.Decode(raw); b == nil {
			return "", fmt.Errorf("%s holds no PEM certificate", path)
		}
		if b.Type == "CERTIFICATE" {
			return agent.CertFingerprint(tls.Certificate{Certificate: [][]byte{b.Bytes}}), nil
		}
	}
}

// readPINFD reads the PIN the login passed on --pin-fd, at most maxPIN
// bytes, and closes the descriptor.
func (s *sessionFlags) readPINFD() error {
	if s.pinFD == 0 {
		return nil
	}
	f := os.NewFile(uintptr(s.pinFD), "pin")
	if f == nil {
		return fmt.Errorf("--pin-fd %d is not an open descriptor", s.pinFD)
	}
	defer f.Close()
	pin, err := io.ReadAll(io.LimitReader(f, maxPIN+1))
	if err != nil {
		clear(pin)
		return fmt.Errorf("reading the PIN from the login: %w", err)
	}
	if len(pin) > maxPIN {
		clear(pin)
		return fmt.Errorf("the PIN the login passed is over %d bytes", maxPIN)
	}
	s.pin = pin
	return nil
}
