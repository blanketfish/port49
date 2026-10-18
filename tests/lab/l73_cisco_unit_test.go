//go:build lab

package lab

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rhwendt/port49/tests/lab/labcreds"
)

// echoDevice is a fake IOS XE CLI: it echoes each typed line and answers a
// `key` line the way a parser that quotes the offending text does.
type echoDevice struct{ out *syncBuf }

func (d echoDevice) Write(p []byte) (int, error) {
	for _, ln := range strings.Split(strings.TrimSpace(string(p)), "\n") {
		d.out.Write([]byte(ln + "\n"))
		if strings.Contains(ln, " key ") {
			d.out.Write([]byte("% Invalid input detected near '" + ln + "'\n"))
		}
		if ln == "end" {
			d.out.Write([]byte("xe1#\n"))
		} else {
			d.out.Write([]byte("xe1(config)#\n"))
		}
	}
	return len(p), nil
}

// A device that echoes `key 0 <secret>`, in the line and in its refusal,
// must leave neither the error nor the returned screen holding the secret.
func TestL73CiscoRunMasksAnEchoedKey(t *testing.T) {
	out := &syncBuf{}
	c := &cliConn{name: "fake", prompt: "xe1#", in: echoDevice{out}, out: out}
	for _, lenient := range []bool{false, true} {
		screen, err := l73CiscoRun(c, l73Lines("tacacs-server host 192.0.2.71 key 0 "+labcreds.Key), nil, lenient)
		if err == nil {
			t.Fatalf("lenient=%v: the refusal returned no error", lenient)
		}
		if strings.Contains(err.Error(), labcreds.Key) {
			t.Errorf("lenient=%v: the error holds the lab key", lenient)
		}
		if strings.Contains(screen, labcreds.Key) || !strings.Contains(screen, "<key>") {
			t.Errorf("lenient=%v: the returned screen is not masked", lenient)
		}
	}
}

// The undo types the lab key back; the screen kept in the INVALID directory
// must not hold it, however the device echoed it.
func TestL73UndoScreenInTheInvalidDirHoldsNoLabKey(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PORT49_L73_INVALID_DIR", dir)
	out := &syncBuf{}
	c := &cliConn{name: "fake", prompt: "xe1#", in: echoDevice{out}, out: out}
	screen, _ := l73CiscoRun(c, l73Lines(l73CiscoRestoreAll("iosxe", nil)...), nil, true)
	e := &l73Env{l: &lab{p: platform{name: "x"}}}
	e.invalidScreen("restore", screen)
	b, err := os.ReadFile(filepath.Join(dir, "l73-invalid-x-restore.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), labcreds.Key) || !strings.Contains(string(b), "address ipv4 172.100.100.1") {
		t.Fatalf("restore screen:\n%s", b)
	}
	// And the key is among the secrets the leak gate compares against.
	all, err := l73SecretsFor(true, nil, nil)
	if err != nil || !slices.Contains(all, labcreds.Key) {
		t.Errorf("the lab key is not a gated secret: %v", err)
	}
}
