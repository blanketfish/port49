package main

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/tacacs/wire"
)

var testKey = []byte("fake-key-for-tests-only")

// fakeServer answers each authentication START with PASS (or FAIL for fail), on one connection or on
// each, and closes a connection after closeAfter replies (0: never).
func fakeServer(t *testing.T, closeAfter int, status uint8) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				for n := 0; closeAfter == 0 || n < closeAfter; n++ {
					hb := make([]byte, wire.HeaderLen)
					if _, err := io.ReadFull(c, hb); err != nil {
						return
					}
					h, _ := wire.DecodeHeader(hb)
					body := make([]byte, h.Length)
					if _, err := io.ReadFull(c, body); err != nil {
						return
					}
					reply := wire.AuthenReply{Status: status}.Encode()
					rh := wire.Header{MajorVersion: h.MajorVersion, Type: h.Type, SeqNo: h.SeqNo + 1, Flags: h.Flags, SessionID: h.SessionID, Length: uint32(len(reply))}
					c.Write(append(rh.Encode(), wire.Obfuscate(rh, testKey, reply)...))
				}
			}(c)
		}
	}()
	return l.Addr().String()
}

func creds() Creds { return Creds{Key: string(testKey), Token: "fake-token", User: "alice"} }

func TestProbeAnswersPassOrFail(t *testing.T) {
	if got := Probe(fakeServer(t, 0, wire.AuthenStatusPass), creds()); got != "pass" {
		t.Errorf("a PASS reply is %q", got)
	}
	if got := Probe(fakeServer(t, 0, wire.AuthenStatusFail), creds()); got != "fail:status_2" {
		t.Errorf("a FAIL reply is %q", got)
	}
}

func TestProbeNamesWhatWentWrong(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	if got := Probe(addr, creds()); got != "fail:refused" {
		t.Errorf("a closed port is %q", got)
	}
}

func TestKindIsAClosedAlphabet(t *testing.T) {
	for err, want := range map[error]string{
		io.EOF:                              "closed",
		syscall.ECONNRESET:                  "reset",
		syscall.ECONNREFUSED:                "refused",
		&net.OpError{Err: timeoutErr{}}:     "timeout",
		errors.New("anything with a token"): "error",
	} {
		if got := kind(err); got != want {
			t.Errorf("kind(%v) = %q, want %q", err, got, want)
		}
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestLoopPrintsOneClosedLinePerSecond(t *testing.T) {
	var out bytes.Buffer
	Loop(&out, fakeServer(t, 0, wire.AuthenStatusPass), creds(), 2500*time.Millisecond, 50*time.Millisecond)
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) < 3 {
		t.Fatalf("lines %q", lines)
	}
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) != 3 || f[1] != "pass" || f[2] != "-" {
			t.Errorf("line %q, want <second> pass -", l)
		}
	}
}

func TestLoopRetriesOnceAndSaysSo(t *testing.T) {
	var out bytes.Buffer
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	Loop(&out, addr, creds(), 1500*time.Millisecond, 50*time.Millisecond)
	for _, ln := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if f := strings.Fields(ln); len(f) != 3 || f[1] != "fail:refused" || f[2] != "fail:refused" {
			t.Errorf("line %q, want both attempts failed", ln)
		}
	}
}

func TestSessionKeepsOneConnectionAndSaysWhenItEnds(t *testing.T) {
	var out bytes.Buffer
	Session(&out, fakeServer(t, 3, wire.AuthenStatusPass), creds(), 30*time.Second, 20*time.Millisecond)
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 4 || !strings.HasPrefix(lines[0], "ok ") || !strings.HasPrefix(lines[2], "ok ") || !strings.HasPrefix(lines[3], "end ") || !strings.HasSuffix(lines[3], " closed") {
		t.Errorf("a connection the server closes after three replies: %q", lines)
	}
	out.Reset()
	Session(&out, fakeServer(t, 0, wire.AuthenStatusPass), creds(), 300*time.Millisecond, 20*time.Millisecond)
	if !strings.HasSuffix(strings.TrimSpace(out.String()), " deadline") {
		t.Errorf("a session that lasts: %q", out.String())
	}
}

func TestNothingPrintsTheKeyOrTheToken(t *testing.T) {
	var out bytes.Buffer
	c := creds()
	Loop(&out, fakeServer(t, 0, wire.AuthenStatusFail), c, time.Second, 50*time.Millisecond)
	Session(&out, fakeServer(t, 1, wire.AuthenStatusPass), c, time.Second, 20*time.Millisecond)
	fmt := Probe(fakeServer(t, 0, wire.AuthenStatusPass), c)
	for _, s := range []string{out.String(), fmt} {
		if strings.Contains(s, c.Key) || strings.Contains(s, c.Token) {
			t.Errorf("output holds a credential: %q", s)
		}
	}
}
