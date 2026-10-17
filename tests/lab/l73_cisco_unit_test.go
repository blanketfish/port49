//go:build lab

package lab

import (
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
