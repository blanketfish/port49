//go:build lab

package lab

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"
)

// labScan reads the key the server presents and offers no credential: no
// authentication callback of the server's ever runs (moved from
// internal/hostkeys by plan 9d).
func TestLabScanReadsTheKeyAndSendsNoCredential(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	var auths atomic.Int32
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			auths.Add(1)
			return nil, errors.New("no")
		},
		KeyboardInteractiveCallback: func(ssh.ConnMetadata, ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			auths.Add(1)
			return nil, errors.New("no")
		},
		AuthLogCallback: func(ssh.ConnMetadata, string, error) { auths.Add(1) },
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_, _, _, _ = ssh.NewServerConn(c, cfg)
		c.Close()
	}()
	got, err := labScan(context.Background(), ln.Addr().String())
	<-done
	if err != nil || string(got.Marshal()) != string(signer.PublicKey().Marshal()) || auths.Load() != 0 {
		t.Fatalf("key %v err %v, %d auth attempts", got, err, auths.Load())
	}
}
