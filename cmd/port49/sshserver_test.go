package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// deviceSSH stands in for a device's SSH server. It takes the methods it is
// given, records every password or keyboard-interactive answer sent to it in
// order, accepts want, and answers an exec request with "ran: <command>"
// after hold, exit status 0.
type deviceSSH struct {
	port  int
	key   ssh.PublicKey
	mu    sync.Mutex
	tried []string
	conns int
}

func startDeviceSSH(t *testing.T, methods []string, want string, hold time.Duration) *deviceSSH {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	d := &deviceSSH{key: signer.PublicKey()}
	check := func(answer string) error {
		d.mu.Lock()
		d.tried = append(d.tried, answer)
		d.mu.Unlock()
		if want != "" && answer == want {
			return nil
		}
		return errors.New("refused")
	}
	cfg := &ssh.ServerConfig{}
	for _, m := range methods {
		switch m {
		case "password":
			cfg.PasswordCallback = func(_ ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
				return nil, check(string(p))
			}
		case "keyboard-interactive":
			cfg.KeyboardInteractiveCallback = func(_ ssh.ConnMetadata, ch ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
				a, err := ch("", "", []string{"Password: "}, []bool{false})
				if err != nil || len(a) != 1 {
					return nil, errors.New("no answer")
				}
				return nil, check(a[0])
			}
		}
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	d.port = ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			d.mu.Lock()
			d.conns++
			d.mu.Unlock()
			go d.serve(c, cfg, hold)
		}
	}()
	return d
}

func (d *deviceSSH) serve(c net.Conn, cfg *ssh.ServerConfig, hold time.Duration) {
	defer c.Close()
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "session only")
			continue
		}
		ch, rq, err := nc.Accept()
		if err != nil {
			return
		}
		go func() {
			defer ch.Close()
			for r := range rq {
				if r.Type != "exec" {
					_ = r.Reply(r.Type == "pty-req" || r.Type == "env", nil)
					continue
				}
				_ = r.Reply(true, nil)
				var p struct{ Command string }
				_ = ssh.Unmarshal(r.Payload, &p)
				time.Sleep(hold)
				_, _ = fmt.Fprintf(ch, "ran: %s\n", p.Command)
				_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
				return
			}
		}()
	}
}

// attempts is every answer the device was sent, in order.
func (d *deviceSSH) attempts() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.tried)
}

func (d *deviceSSH) connections() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.conns
}
