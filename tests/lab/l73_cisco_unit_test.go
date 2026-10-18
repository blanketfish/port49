//go:build lab

package lab

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

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

// execDevice is a fake IOS XE exec CLI: it echoes each line and answers with
// the prompt, `show tacacs` with a line holding the lab key.
type execDevice struct{ out *syncBuf }

func (d execDevice) Write(p []byte) (int, error) {
	for _, ln := range strings.Split(strings.TrimSpace(string(p)), "\n") {
		d.out.Write([]byte(ln + "\n"))
		if ln == "show tacacs" {
			d.out.Write([]byte("Server name: l73-tls key " + labcreds.Key + "\nSocket opens: 0\n"))
		}
		d.out.Write([]byte("xe1#\n"))
	}
	return len(p), nil
}

// A cell whose device never reached port49 keeps, in the INVALID directory,
// the configure screens, the dialect's device commands and the gaps measured.
func TestL73NoConnectionKeepsTheConfigureScreensTheDeviceViewAndTheGaps(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PORT49_L73_INVALID_DIR", dir)
	out := &syncBuf{}
	e := &l73Env{t: t, l: &lab{p: platform{name: "x"}}, d: l73Dialect{Family: "iosxe", HelpOnly: true, InvalidCmds: []string{"show tacacs"}},
		opener: func(*lab) (*cliConn, error) {
			return &cliConn{name: "fake", prompt: "xe1#", in: execDevice{out}, out: out}, nil
		}}
	e.noteConfigure("xe1(config-server-tacacs)#address ipv4 172.100.100.1\r\n")
	t0 := time.Now()
	e.gapFact("i-error", t0, t0.Add(31*time.Second+400*time.Millisecond))
	e.noConnectionLogs()
	for name, want := range map[string]string{"configure-typed": "address ipv4 172.100.100.1", "device-1": "Socket opens",
		"gaps": "i-error: 31.4s"} {
		b, err := os.ReadFile(filepath.Join(dir, "l73-invalid-x-"+name+".txt"))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !strings.Contains(string(b), want) || strings.Contains(string(b), labcreds.Key) {
			t.Errorf("%s:\n%s", name, b)
		}
	}
}

// The facts read from the device are logged and written to the INVALID
// directory as they are made, so an INVALID run still holds them.
func TestL73XEFactIsKeptAtOnce(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PORT49_L73_INVALID_DIR", dir)
	e := &l73Env{t: t, l: &lab{p: platform{name: "x"}}}
	e.xeFact("server object 1: `tacacs server l73-tls / address ipv4 172.100.100.1 / key " + labcreds.Key + "`")
	e.xeFact("a break-glass login ok true")
	b, err := os.ReadFile(filepath.Join(dir, "l73-invalid-x-iosxe-server.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "address ipv4 172.100.100.1") || !strings.Contains(string(b), "break-glass") || strings.Contains(string(b), labcreds.Key) || len(e.facts) != 2 {
		t.Fatalf("%s", b)
	}
}
