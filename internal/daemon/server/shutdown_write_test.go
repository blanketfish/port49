package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// A shutdown never hangs behind a reply write to a peer that stopped reading:
// its send buffer is full, the write holds the connection's write lock, and
// closeTLSAtShutdown breaks it with a write deadline after shutdownWriteBound
// (the 3am case: a dead device must not hold port49d's stop).
func TestShutdownIsNotHeldByAWriteToAPeerThatStoppedReading(t *testing.T) {
	was := shutdownWriteBound
	shutdownWriteBound = 300 * time.Millisecond
	t.Cleanup(func() { shutdownWriteBound = was })
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(1),
		Subject: pkix.Name{CommonName: "write-test"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour)}, &x509.Certificate{SerialNumber: big.NewInt(1),
		Subject: pkix.Name{CommonName: "write-test"}}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	peerDone := make(chan struct{})
	t.Cleanup(func() { close(peerDone) })
	go func() { // the peer: handshakes, then never reads
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			return
		}
		defer c.Close()
		tc := tls.Client(c, &tls.Config{InsecureSkipVerify: true})
		if tc.Handshake() != nil {
			return
		}
		<-peerDone
	}()
	raw, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	tc := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	s := &conn{raw: raw, c: tc}
	writing := make(chan struct{})
	written := make(chan error, 1)
	go func() { // a reply write that fills the buffer and blocks, as write() does
		s.wmu.Lock()
		defer s.wmu.Unlock()
		close(writing)
		tc.SetWriteDeadline(time.Now().Add(time.Hour))
		_, err := tc.Write(make([]byte, 64<<20))
		written <- err
	}()
	<-writing
	time.Sleep(100 * time.Millisecond) // the write is blocked on the full buffer
	began := time.Now()
	closed := make(chan struct{})
	go func() { s.closeTLSAtShutdown(tc); close(closed) }()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the shutdown is held behind a write to a peer that stopped reading")
	}
	if d := time.Since(began); d > 2*time.Second {
		t.Fatalf("the shutdown took %v with a 300ms write bound", d)
	}
	if err := <-written; err == nil {
		t.Fatal("the blocked write finished without error")
	}
}
