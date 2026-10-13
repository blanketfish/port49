package main

import (
	"io"
	"os"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// Echo is off before the PIN prompt is written, as readpassphrase(3) does it,
// so nothing typed once the prompt can be seen is echoed. The terminal's
// ECHO flag is read from the pty the moment the prompt arrives; the window a
// prompt-first order leaves is microseconds, so it is tried many times.
func TestThePINPromptIsWrittenWithEchoAlreadyOff(t *testing.T) {
	old := pinTerminal
	t.Cleanup(func() { pinTerminal = old })
	echoed := 0
	const rounds = 300
	for range rounds {
		m, s := openPty(t)
		pinTerminal = func() (*os.File, error) { return os.OpenFile(s.Name(), os.O_RDWR|syscall.O_NOCTTY, 0) }
		seen := make(chan bool, 1)
		go func() {
			buf := make([]byte, 64)
			n, _ := m.Read(buf)
			if !strings.Contains(string(buf[:n]), "PIN for ") {
				seen <- true
				return
			}
			tio, err := unix.IoctlGetTermios(int(m.Fd()), unix.TCGETS)
			seen <- err != nil || tio.Lflag&unix.ECHO != 0
			_, _ = io.WriteString(m, "1234\n")
		}()
		pin, err := askPIN("tok")
		if err != nil || string(pin) != "1234" {
			t.Fatalf("askPIN: %v", err)
		}
		if <-seen {
			echoed++
		}
		m.Close()
		s.Close()
	}
	if echoed != 0 {
		t.Fatalf("echo was still on when the prompt arrived in %d of %d prompts", echoed, rounds)
	}
}
