//go:build lab

package lab

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestL73TokenResult(t *testing.T) {
	var missed notObserved
	missed.add("show version", "deadline")
	for name, c := range map[string]struct {
		outs   []string
		err    error
		ok     bool
		out    string
		unseen bool
	}{
		"output":               {[]string{" NXOS: version 10.6(2)\r\n"}, nil, true, "NXOS: version 10.6(2)", false},
		"empty output":         {[]string{""}, nil, true, "", true},
		"exec never finished":  {[]string{""}, &missed, true, "", true},
		"refused at the dial":  {nil, errors.New("ssh: handshake failed: unable to authenticate"), false, "", false},
		"no output and no err": {nil, nil, false, "", false},
	} {
		ok, out, unseen := l73TokenResult(c.outs, c.err)
		if ok != c.ok || out != c.out || (unseen != "") != c.unseen {
			t.Errorf("%s: got ok %v out %q unseen %q", name, ok, out, unseen)
		}
	}
}

// An exec channel the device accepts and never answers (NX-OS does this) ends
// at the bound instead of hanging the run; the error names the command.
func TestL73LoginWithinEndsAtTheBoundOnAnExecThatNeverReturns(t *testing.T) {
	hk, err := ssh.NewSignerFromKey(l73TestKey(t))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return nil, nil }}
	cfg.AddHostKey(hk)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, chans, reqs, err := ssh.NewServerConn(nc, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for nch := range chans {
					ch, creqs, err := nch.Accept()
					if err != nil {
						continue
					}
					go func() {
						for r := range creqs {
							if r.Type == "exec" {
								r.Reply(true, nil) // accepted, then nothing: no output, no exit status
								continue
							}
							r.Reply(false, nil)
						}
					}()
					_ = ch
				}
			}()
		}
	}()
	l := &lab{p: platform{name: "cisco_nxos"}}
	start := time.Now()
	outs, err := l.loginWithinDial(ln.Addr().String(), "u", "p", 5*time.Second, 300*time.Millisecond, "show version")
	if took := time.Since(start); took > 15*time.Second {
		t.Fatalf("took %s", took)
	}
	var no *notObserved
	if !errors.As(err, &no) || !strings.Contains(err.Error(), "show version: deadline") || len(outs) != 1 {
		t.Fatalf("outs %q err %v", outs, err)
	}
	if ok, _, unseen := l73TokenResult(outs, err); !ok || unseen == "" {
		t.Errorf("an authenticated session whose exec never returned is %v / %q", ok, unseen)
	}
}

func l73TestKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}
