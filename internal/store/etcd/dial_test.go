package etcd

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/store"
)

// blackhole is an endpoint that accepts TCP and never speaks: the shape of a
// region cut off from its directory.
func blackhole(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { <-done; c.Close() }()
		}
	}()
	t.Cleanup(func() { close(done); l.Close() })
	return l.Addr().String()
}

// An endpoint set that does not answer within DialTimeout is an outage, not
// a configuration fault: a start that meets it serves from its snapshot (R19).
func TestOpenNoEndpointAnswersIsUnavailable(t *testing.T) {
	ep := blackhole(t)
	s, err := Open(Config{Endpoints: []string{ep}, DialTimeout: 300 * time.Millisecond})
	if err == nil {
		s.Close()
		t.Fatal("Open returned no error against an endpoint that never answers")
	}
	if !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("err = %v, want it to wrap store.ErrUnavailable", err)
	}
	if !strings.Contains(err.Error(), ep) {
		t.Fatalf("err = %q, want it to name the endpoints", err)
	}
}

// No endpoints is a configuration fault, never an outage.
func TestOpenNoEndpointsIsNotUnavailable(t *testing.T) {
	_, err := Open(Config{})
	if err == nil || errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("err = %v, want a non-ErrUnavailable error", err)
	}
}
