package etcd

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
)

// blackhole is an endpoint that accepts TCP and never speaks: a member cut
// off from this process.
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

func ping(s *Store) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return s.Ping(ctx)
}

// One member that does not answer is not an outage while another does: Open
// does not wait for it, and the store works (L74 cell (f) shape). clientv3's
// RejectOldCluster asks every endpoint and fails New when any one is down.
func TestOpenWithADeadMemberListedSecondIsLive(t *testing.T) {
	srv := etcdtest.Start(t, etcdtest.Options{})
	start := time.Now()
	s, err := Open(Config{Endpoints: []string{srv.Endpoint, blackhole(t)}, DialTimeout: 300 * time.Millisecond})
	if err != nil {
		t.Fatalf("Open with one live and one silent member: %v", err)
	}
	defer s.Close()
	if d := time.Since(start); d > 250*time.Millisecond {
		t.Fatalf("Open waited %v", d)
	}
	for i := 0; i < 3; i++ {
		if err := ping(s); err != nil {
			t.Fatalf("Ping %d: %v", i, err)
		}
	}
}

// When no member answers Open still returns at once, and the outage is
// Ping's to say.
func TestOpenWithNoMemberAnsweringIsPingsOutage(t *testing.T) {
	s, err := Open(Config{Endpoints: []string{blackhole(t)}, DialTimeout: 300 * time.Millisecond})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	if err := ping(s); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("Ping = %v, want store.ErrUnavailable", err)
	}
}

// A server this CA does not verify is not Open's to call an outage: it is
// never store.ErrUnavailable from Open (port49d's TLS probe names it).
func TestOpenWithAWrongCAIsNotUnavailable(t *testing.T) {
	srv := etcdtest.Start(t, etcdtest.Options{TLS: true})
	tc := srv.TLS(t, "root").Clone()
	tc.RootCAs = nil
	s, err := Open(Config{Endpoints: []string{srv.Endpoint}, TLS: tc, DialTimeout: 300 * time.Millisecond})
	if err != nil {
		if errors.Is(err, store.ErrUnavailable) {
			t.Fatalf("Open = %v, a certificate fault read as an outage", err)
		}
		return
	}
	s.Close()
}

// No endpoints is a configuration fault, never an outage.
func TestOpenNoEndpointsIsNotUnavailable(t *testing.T) {
	_, err := Open(Config{})
	if err == nil || errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("err = %v, want a non-ErrUnavailable error", err)
	}
}
