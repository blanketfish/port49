package etcd

import (
	"context"
	"errors"
	"net"
	"strings"
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

// threeBehindProxies is a three-member cluster each of whose members the
// store reaches through a proxy of its own, so a test can make one member
// dark the way a dropped link does: its open connection stalls.
func threeBehindProxies(t *testing.T) (*Store, *etcdtest.Cluster, []*etcdtest.Proxy) {
	t.Helper()
	c := etcdtest.StartCluster(t)
	var ps []*etcdtest.Proxy
	var eps []string
	for _, e := range c.Endpoints {
		p := etcdtest.NewProxy(t, strings.TrimPrefix(e, "http://"))
		ps, eps = append(ps, p), append(eps, "http://"+p.Addr())
	}
	s, err := Open(Config{Endpoints: eps, Prefix: etcdtest.Prefix()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, c, ps
}

// pingsFor pings every 100ms for d, each within 500ms (the broker's
// call_timeout), and returns how many failed and the slowest answer.
func pingsFor(s *Store, d time.Duration) (failed int, slowest time.Duration) {
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(100 * time.Millisecond) {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		start := time.Now()
		if err := s.Ping(ctx); err != nil {
			failed++
		}
		slowest = max(slowest, time.Since(start))
		cancel()
	}
	return failed, slowest
}

// One member of three going dark leaves the store answering (L74): a read
// that round-robin sends to the stalled connection is tried on another
// member within its own deadline, not failed at it until keepalive notices.
func TestAReadAnswersWhileOneMemberIsDark(t *testing.T) {
	s, _, ps := threeBehindProxies(t)
	if failed, _ := pingsFor(s, time.Second); failed != 0 {
		t.Fatalf("%d ping(s) failed before the member went dark", failed)
	}
	ps[2].Hang(true)
	if failed, slowest := pingsFor(s, 12*time.Second); failed != 0 {
		t.Fatalf("%d ping(s) failed with one of three members dark (slowest %v)", failed, slowest)
	}
}

// A member that refuses connections is no outage either.
func TestAReadAnswersWhileOneMemberIsDown(t *testing.T) {
	s, c, _ := threeBehindProxies(t)
	c.Stop(2)
	if failed, slowest := pingsFor(s, 5*time.Second); failed != 0 {
		t.Fatalf("%d ping(s) failed with one of three members down (slowest %v)", failed, slowest)
	}
}

// Two of three down is an outage: Ping says so.
func TestAReadFailsWhenQuorumIsLost(t *testing.T) {
	s, c, _ := threeBehindProxies(t)
	c.Stop(1)
	c.Stop(2)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	for i := 0; i < 3; i++ {
		if err := s.Ping(ctx); err != nil {
			if !errors.Is(err, store.ErrUnavailable) {
				t.Fatalf("Ping = %v, want store.ErrUnavailable", err)
			}
			return
		}
	}
	t.Fatal("Ping answered with two of three members down")
}

// A write is not sent twice, so one that round-robin sends to the stalled
// connection fails at its deadline until keepalive fails that connection
// (5s + 2s). The blip is bounded: a revocation written every 100ms is
// accepted again by the tenth second, and stays so.
func TestAWriteBlipsOnlyUntilKeepaliveFailsTheDarkMember(t *testing.T) {
	s, _, ps := threeBehindProxies(t)
	ps[2].Hang(true)
	start, lastFail := time.Now(), time.Duration(0)
	for time.Since(start) < 14*time.Second {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		if err := s.PutRevocation(ctx, store.Revocation{Kind: store.RevocationPrincipal, Key: "user:bob", At: time.Now()}); err != nil {
			lastFail = time.Since(start)
		}
		cancel()
		time.Sleep(100 * time.Millisecond)
	}
	if lastFail > 10*time.Second {
		t.Fatalf("a write still failed %v after the member went dark", lastFail)
	}
	t.Logf("last failed write %v after the member went dark", lastFail.Round(100*time.Millisecond))
}

// Reported, not ruled: a member whose server certificate this CA does not
// verify, listed after a good one. The balancer fails that member's
// connection at its handshake and sends every call to the good one, so Open
// and Ping succeed and nothing says the member is unusable (port49d's TLS
// probe stops at the first member that completes a handshake). It is no
// outage, and no snapshot is served for it.
func TestABadCertificateOnALaterMemberLeavesTheStoreAnswering(t *testing.T) {
	good := etcdtest.Start(t, etcdtest.Options{TLS: true})
	bad := etcdtest.Start(t, etcdtest.Options{TLS: true}) // a CA of its own
	tc := good.TLS(t, "root")
	s, err := Open(Config{Endpoints: []string{good.Endpoint, bad.Endpoint}, TLS: tc, Prefix: etcdtest.Prefix()})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if failed, slowest := pingsFor(s, 10*time.Second); failed != 0 {
		t.Fatalf("%d ping(s) failed with a good member and one this CA does not verify (slowest %v)", failed, slowest)
	}
}
