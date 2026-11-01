package etcd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/store"
	"github.com/blanketfish/port49/internal/store/etcd/etcdtest"
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

// writesDuringADarkMember warms every connection of s's token client with
// writes, hangs one member, then writes a revocation every 100ms, each within
// 500ms, for 15s (past keepalive's 10s + 2s). It returns how many failed.
func writesDuringADarkMember(t *testing.T) (failed, total int) {
	t.Helper()
	s, _, ps := threeBehindProxies(t)
	for i := 0; i < 60; i++ { // round-robin: every connection has carried a write
		if err := s.PutRevocation(context.Background(), store.Revocation{Kind: store.RevocationPrincipal,
			Key: fmt.Sprintf("user:warm%d", i), At: time.Now()}); err != nil {
			t.Fatalf("warming write %d: %v", i, err)
		}
	}
	ps[2].Hang(true)
	for start := time.Now(); time.Since(start) < 15*time.Second; time.Sleep(100 * time.Millisecond) {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		if err := s.PutRevocation(ctx, store.Revocation{Kind: store.RevocationPrincipal, Key: "user:bob", At: time.Now()}); err != nil {
			failed++
		}
		total++
		cancel()
	}
	return failed, total
}

// L74 (d): a revocation written while one of three members is dark is
// accepted: PutRevocation is create-if-absent, so a second copy sent on
// another connection changes nothing, and it is sent when the first is still
// unanswered at a quarter of the deadline.
func TestARevocationIsAcceptedWhileOneMemberIsDark(t *testing.T) {
	if failed, total := writesDuringADarkMember(t); failed != 0 {
		t.Fatalf("%d of %d revocations failed with one of three members dark", failed, total)
	}
}

// A lift is a delete conditional on the mark it read: accepted while a member
// is dark as well. Each lift has a mark to lift, so each sends its delete.
func TestALiftIsAcceptedWhileOneMemberIsDark(t *testing.T) {
	s, _, ps := threeBehindProxies(t)
	bob := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:bob", At: time.Now()}
	for i := 0; i < 60; i++ { // round-robin: every connection has carried a lift
		if err := s.PutRevocation(context.Background(), bob); err != nil {
			t.Fatalf("warming revocation %d: %v", i, err)
		}
		if err := s.DeleteRevocation(context.Background(), bob.Kind, bob.Key, store.Lift{}); err != nil {
			t.Fatalf("warming lift %d: %v", i, err)
		}
	}
	ps[2].Hang(true)
	failed, total := 0, 0
	for start := time.Now(); time.Since(start) < 15*time.Second; time.Sleep(100 * time.Millisecond) {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		err := s.PutRevocation(ctx, bob)
		cancel()
		if err != nil {
			t.Fatalf("the revocation before lift %d: %v", total, err)
		}
		ctx, cancel = context.WithTimeout(context.Background(), 500*time.Millisecond)
		if err := s.DeleteRevocation(ctx, bob.Kind, bob.Key, store.Lift{}); err != nil {
			failed++
		}
		total++
		cancel()
	}
	if failed != 0 {
		t.Fatalf("%d of %d lifts failed with one of three members dark", failed, total)
	}
}

// A lift whose record needs a fresh lease, as almost every production lift
// does (lifts are rare, a pool lease lives a bucket), is accepted while a
// member is dark: the grant is hedged, a second copy harmless (task 3
// review, the flake). The pool is reset before each lift, so every lift
// grants, and round-robin puts every third grant on the dark connection.
func TestALiftsLeaseGrantIsAcceptedWhileOneMemberIsDark(t *testing.T) {
	s, _, ps := threeBehindProxies(t)
	bob := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:bob", At: time.Now()}
	for i := 0; i < 30; i++ { // round-robin: every connection has carried a grant and a lift
		if err := s.PutRevocation(context.Background(), bob); err != nil {
			t.Fatalf("warming revocation %d: %v", i, err)
		}
		s.tokLeases.Reset()
		if err := s.DeleteRevocation(context.Background(), bob.Kind, bob.Key, store.Lift{}); err != nil {
			t.Fatalf("warming lift %d: %v", i, err)
		}
	}
	ps[2].Hang(true)
	failed := 0
	const lifts = 12 // well inside keepalive's 10s + 2s, which would drop the dark connection
	for i := 0; i < lifts; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		err := s.PutRevocation(ctx, bob)
		cancel()
		if err != nil {
			t.Fatalf("the revocation before lift %d: %v", i, err)
		}
		// 0, 1 or 2 reads first, so the grant meets each connection in turn:
		// a lift's own calls alone can fall into step with round-robin.
		for range i % 3 {
			ctx, cancel = context.WithTimeout(context.Background(), 500*time.Millisecond)
			if _, err := s.tok.Get(ctx, "rotate"); err != nil {
				t.Fatalf("a hedged read failed: %v", err)
			}
			cancel()
		}
		s.tokLeases.Reset()
		ctx, cancel = context.WithTimeout(context.Background(), 500*time.Millisecond)
		if err := s.DeleteRevocation(ctx, bob.Kind, bob.Key, store.Lift{}); err != nil {
			failed++
		}
		cancel()
	}
	if failed != 0 {
		t.Fatalf("%d of %d lifts that granted a lease failed with one of three members dark", failed, lifts)
	}
}

// A mint whose token needs a fresh lease, as every mint at a bucket's
// rollover does, gets its lease while a member is dark: the grant alone is
// hedged. The token's own Txn is not (a second copy would write a second
// token), so a Txn sent to the dark connection may still fail: the test
// counts only the mints that failed before their Txn (beforeTokenTxn), and
// checks the Txn's ctx is never marked idempotent.
func TestAMintsLeaseGrantIsAcceptedWhileOneMemberIsDark(t *testing.T) {
	s, _, ps := threeBehindProxies(t)
	k := store.TokenKey{NAS: "leaf-01", Username: "alice"}
	var reached, marked atomic.Int32
	beforeTokenTxn = func(ctx context.Context) {
		reached.Add(1)
		if ctx.Value(idempotentKey{}) != nil {
			marked.Add(1)
		}
	}
	t.Cleanup(func() { beforeTokenTxn = nil })
	mint := func(ctx context.Context, i int) error {
		_, err := s.PutToken(ctx, k, store.Token{ID: fmt.Sprintf("t%d", i), Secret: []byte("x"), Kind: store.KindLogin,
			ExpiresAt: time.Now().Add(time.Minute)})
		return err
	}
	for i := 0; i < 30; i++ { // round-robin: every connection has carried a grant and a mint
		s.tokLeases.Reset()
		if err := mint(context.Background(), i); err != nil {
			t.Fatalf("warming mint %d: %v", i, err)
		}
	}
	ps[2].Hang(true)
	grantFailed := 0
	const mints = 12 // well inside keepalive's 10s + 2s, which would drop the dark connection
	for i := 0; i < mints; i++ {
		// 0, 1 or 2 reads first, so the grant meets each connection in turn.
		for range i % 3 {
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			if _, err := s.tok.Get(ctx, "rotate"); err != nil {
				t.Fatalf("a hedged read failed: %v", err)
			}
			cancel()
		}
		s.tokLeases.Reset()
		before := reached.Load()
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		if err := mint(ctx, 100+i); err != nil && reached.Load() == before {
			grantFailed++
		}
		cancel()
	}
	if grantFailed != 0 {
		t.Fatalf("%d of %d mints failed at their lease grant with one of three members dark", grantFailed, mints)
	}
	if n := marked.Load(); n != 0 {
		t.Fatalf("%d token Txns were sent with an idempotent ctx: a second copy would write a second token", n)
	}
}

// A lift's copy that a stalled connection delivers late, once the member is
// back, lifts nothing made after it: a principal revoked again while one
// member was dark stays revoked, and every lift and revocation said so.
// This is evidence, not the gate: whether a lift's delete lands on the dark
// connection is round-robin's luck, so a regression may pass a run.
// TestALiftLeavesAMarkMadeAfterItsRead is the deterministic gate.
func TestALateLiftLeavesALaterRevocationStanding(t *testing.T) {
	s, _, ps := threeBehindProxies(t)
	bob := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:bob", At: time.Now()}
	for i := 0; i < 60; i++ { // round-robin: every connection has carried a lift
		if err := s.PutRevocation(context.Background(), bob); err != nil {
			t.Fatalf("warming revocation %d: %v", i, err)
		}
		if err := s.DeleteRevocation(context.Background(), bob.Kind, bob.Key, store.Lift{}); err != nil {
			t.Fatalf("warming lift %d: %v", i, err)
		}
	}
	if err := s.PutRevocation(context.Background(), bob); err != nil {
		t.Fatal(err)
	}
	ps[2].Hang(true)
	// Twenty rounds, inside keepalive's 10s + 2s, so the stalled connection
	// still holds what was sent on it when the member is back.
	start := time.Now()
	for i := 0; i < 20; i++ {
		// i%3 extra reads rotate which connection round-robin gives the
		// lift's delete, so rounds put it on the dark one in turn.
		for j := 0; j < i%3; j++ {
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			if _, err := s.GetRevocation(ctx, bob.Kind, bob.Key); err != nil {
				t.Fatalf("read %d.%d: %v", i, j, err)
			}
			cancel()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		if err := s.DeleteRevocation(ctx, bob.Kind, bob.Key, store.Lift{}); err != nil {
			t.Fatalf("lift %d: %v", i, err)
		}
		cancel()
		ctx, cancel = context.WithTimeout(context.Background(), 500*time.Millisecond)
		if err := s.PutRevocation(ctx, bob); err != nil {
			t.Fatalf("revocation %d: %v", i, err)
		}
		cancel()
		time.Sleep(100 * time.Millisecond)
	}
	if took := time.Since(start); took > 9*time.Second {
		t.Fatalf("the rounds took %v, so keepalive may have closed the dark connection: evidence of nothing", took)
	}
	ps[2].Hang(false)
	time.Sleep(3 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := s.GetRevocation(ctx, bob.Kind, bob.Key); err != nil {
		t.Fatalf("the last revocation, reported made, is gone once the member is back: %v", err)
	}
}

// Without the opt-in the write goes to the stalled connection once in three,
// and fails at its deadline until keepalive fails the connection.
func TestARevocationFailsOnTheDarkMemberWithoutTheOptIn(t *testing.T) {
	was := hedgeWrites
	hedgeWrites = false
	t.Cleanup(func() { hedgeWrites = was })
	failed, total := writesDuringADarkMember(t)
	if failed == 0 {
		t.Fatalf("no revocation of %d failed: the dark member was never picked, so the test proves nothing", total)
	}
	t.Logf("%d of %d revocations failed without the opt-in", failed, total)
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
