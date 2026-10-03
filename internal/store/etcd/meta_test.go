package etcd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
)

// One port49d per keyspace: a second Hold waits, saying who holds it,
// until the first lets go; and a hold whose store stops answering is lost
// at least a sixth of its TTL before etcd can expire the lease and the
// second take it (Ruling 11; pre-flight I15; re-check R-I4; Review Focus
// 4). That margin, 1.67s at a 10s TTL (the floor; a shorter one can drop
// a healthy hold, 8b re-review 2 R2-I1), plus etcd's own lease-expiry
// granularity, is what keeps the ordering assertion below from racing.
func TestHoldIsOnePerKeyspaceAndLapses(t *testing.T) {
	srv := etcdtest.Start(t, etcdtest.Options{})
	proxy := etcdtest.NewProxy(t, strings.TrimPrefix(srv.Endpoint, "http://"))
	prefix := etcdtest.Prefix()
	open := func(ep string) *Store {
		s, err := Open(Config{Endpoints: []string{ep}, Prefix: prefix})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		return s
	}
	first, second := open("http://"+proxy.Addr()), open(srv.Endpoint)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lost, release, err := first.Hold(ctx, 10*time.Second, "port49d one", func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	waited := make(chan string, 4)
	got := make(chan error, 1)
	tookAt := make(chan time.Time, 1)
	go func() {
		_, rel, err := second.Hold(ctx, 10*time.Second, "port49d two", func(h string) { waited <- h })
		tookAt <- time.Now()
		if err == nil {
			defer rel()
		}
		got <- err
	}()
	select {
	case h := <-waited:
		if h != "port49d one" {
			t.Fatalf("waiting on %q", h)
		}
	case err := <-got:
		t.Fatalf("the second took a held keyspace: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("the second never said it was waiting")
	}
	proxy.Hang(true) // the first's store stops answering
	var lostAt time.Time
	select {
	case <-lost:
		lostAt = time.Now()
	case <-time.After(20 * time.Second):
		t.Fatal("the first's hold did not lapse")
	}
	select { // pre-flight M38: never an unbounded receive
	case err := <-got:
		if err != nil {
			t.Fatalf("the second, once the first lapsed: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the second never took the keyspace")
	}
	if took := <-tookAt; took.Before(lostAt) {
		t.Fatalf("the second took the keyspace at %v, before the first knew it had lost it at %v", took, lostAt)
	}
	proxy.Hang(false)
	release()
}

// A hold whose lock key is deleted (an operator "unsticking" it, or
// etcdctl del --prefix) is lost at the next read, never left serving
// beside another (pre-flight I15).
func TestTheHoldIsLostWhenItsKeyIsDeleted(t *testing.T) {
	s := onShared(t, func() time.Time { return t0 })
	ctx := context.Background()
	lost, release, err := s.Hold(ctx, 10*time.Second, "port49d one", func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err := s.ctx.Delete(ctx, s.k.meta("hold"), clientv3.WithPrefix()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-lost:
	case <-time.After(5 * time.Second):
		t.Fatal("a hold whose key was deleted was not lost")
	}
}

// A meta/hold deleted under a live holder never leaves two holders at
// once (Ruling T12-e): the next takes the lock at once, but its Hold
// returns only ttl/3 later, by when the first has seen the key gone. The
// delete lands just after the first's Hold returns, a whole tick before
// its next read.
func TestADeletedHoldNeverServesTwo(t *testing.T) {
	s := onShared(t, func() time.Time { return t0 })
	ctx := context.Background()
	lost, release, err := s.Hold(ctx, 10*time.Second, "port49d one", func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err := s.ctx.Delete(ctx, s.k.meta("hold"), clientv3.WithPrefix()); err != nil {
		t.Fatal(err)
	}
	_, release2, err := s.Hold(ctx, 10*time.Second, "port49d two", func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	defer release2()
	select {
	case <-lost:
	default:
		t.Fatal("the second holds the keyspace while the first still does")
	}
}

// Hold honours its ctx while the store hangs, before the lease is granted,
// after it, or after the lock is taken, and with no deadline of its own it
// gives up after ttl/3 as the store unavailable, so a start says it is
// trying again and a SIGTERM stops it; letting go of the lease it was
// granted waits at most a second on the hung store, never hold_ttl, and
// says the lease was left to expire (Task 12 review I-2; re-review m-6,
// re-review 2 m-7, m-8).
func TestHoldOnAHungStoreReturns(t *testing.T) {
	srv := etcdtest.Start(t, etcdtest.Options{})
	proxy := etcdtest.NewProxy(t, strings.TrimPrefix(srv.Endpoint, "http://"))
	var said syncLines
	defer func() { holdGranted, holdLocked = func() {}, func() {} }()
	hold := func(s *Store, ctx context.Context) (time.Duration, error) {
		start := time.Now()
		done := make(chan error, 1)
		go func() {
			_, release, err := s.Hold(ctx, 10*time.Second, "port49d one", func(string) {})
			if err == nil {
				release()
			}
			done <- err
		}()
		select {
		case err := <-done:
			return time.Since(start), err
		case <-time.After(15 * time.Second):
			t.Fatal("Hold on a hung store did not return")
			return 0, nil
		}
	}
	const slack = 1500 * time.Millisecond
	for _, c := range []struct {
		name   string
		hangAt *func() // the step the store hangs after; nil: at once
	}{{"before the grant", nil}, {"after the grant", &holdGranted}, {"after the lock", &holdLocked}} {
		for _, deadline := range []time.Duration{2 * time.Second, 0} {
			// A keyspace of its own: a lease the last let expire would hold
			// the lock here until it did.
			s, err := Open(Config{Endpoints: []string{"http://" + proxy.Addr()}, Prefix: etcdtest.Prefix(),
				Logf: said.logf})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if err := s.Ping(context.Background()); err != nil {
				t.Fatal(err)
			}
			holdGranted, holdLocked = func() {}, func() {}
			if c.hangAt != nil {
				*c.hangAt = func() { proxy.Hang(true) }
			} else {
				proxy.Hang(true)
			}
			n := said.count("left to expire")
			ctx, cancel := context.Background(), context.CancelFunc(func() {})
			if deadline > 0 {
				ctx, cancel = context.WithTimeout(ctx, deadline)
			}
			took, err := hold(s, ctx)
			cancel()
			switch {
			case deadline > 0 && (err == nil || took > deadline+slack):
				t.Errorf("%s, with a %v ctx: %v after %v", c.name, deadline, err, took)
			case deadline == 0 && (!errors.Is(err, store.ErrUnavailable) || took > 10*time.Second/3+slack):
				t.Errorf("%s, with no deadline: %v after %v, want unavailable within ttl/3", c.name, err, took)
			}
			if c.hangAt != nil && said.count("left to expire") != n+1 {
				t.Errorf("%s: letting go of the lease on a hung store said nothing: %q", c.name, said.String())
			}
			proxy.Hang(false)
		}
	}
}

// A slow but healthy store keeps the hold at the 10s floor for 60s: each
// fence read answers late, well inside its ttl/6 deadline, and the
// lease's keepalives land late too (8b re-review R-M2; round 3b). This
// is a smoke check of the whole fence; TestTheFenceJudgesEachRead is what
// pins each decision (8b re-review 3 R3-M1).
func TestASlowAnsweredReadKeepsTheHold(t *testing.T) {
	srv := etcdtest.Start(t, etcdtest.Options{})
	proxy := etcdtest.NewProxy(t, strings.TrimPrefix(srv.Endpoint, "http://"))
	s, err := Open(Config{Endpoints: []string{"http://" + proxy.Addr()}, Prefix: etcdtest.Prefix()})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lost, release, err := s.Hold(ctx, 10*time.Second, "port49d one", func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	// Each fence read (a Get and a TimeToLive) then answers in about 0.6s
	// to 0.9s, with headroom under the read's 1.67s deadline, and a
	// keepalive's round trip is 0.6s or less, so a healthy lease reports 5s
	// or more at its lowest (floor(6.67 - 0.5 - 0.6)). Measured at 100ms a
	// chunk: a read 0.70s to 0.81s, a keepalive about 0.4s.
	proxy.Delay(100 * time.Millisecond)
	select {
	case <-lost:
		t.Fatal("a slow but healthy store lost the hold")
	case <-time.After(60 * time.Second):
	}
}

// The fence's keep-or-lose decision, read by read (8b re-review 3
// R3-M1). An answered read is judged at its send, by the TTL it reported,
// and lost only under half of ttl; a failed read is judged by the last
// answer's estimate at now.
func TestTheFenceJudgesEachRead(t *testing.T) {
	sent := time.Unix(1000, 0)
	n := func(v int64) *int64 { return &v }
	for _, c := range []struct {
		name     string
		ttl      time.Duration
		reported *int64
		now      time.Time
		expires  time.Time
		lose     bool
	}{
		{"an answered read reporting exactly half keeps it", 10 * time.Second, n(5),
			sent.Add(100 * time.Millisecond), time.Time{}, false},
		{"a slow answered read is judged at its send", 10 * time.Second, n(6),
			sent.Add(1500 * time.Millisecond), time.Time{}, false},
		{"an answered read under half loses it", 10 * time.Second, n(4),
			sent.Add(100 * time.Millisecond), time.Time{}, true},
		{"at 15s, 8s keeps it", 15 * time.Second, n(8), sent.Add(100 * time.Millisecond), time.Time{}, false},
		{"at 15s, 7s loses it", 15 * time.Second, n(7), sent.Add(100 * time.Millisecond), time.Time{}, true},
		{"a failed read with half or less left loses it", 10 * time.Second, nil,
			sent, sent.Add(5 * time.Second), true},
		{"a failed read with more left keeps it", 10 * time.Second, nil,
			sent, sent.Add(5*time.Second + time.Millisecond), false},
	} {
		lose, next := judge(c.ttl, sent, c.reported, c.now, c.expires)
		if lose != c.lose {
			t.Errorf("%s: lose %v, want %v", c.name, lose, c.lose)
		}
		want := c.expires
		if c.reported != nil {
			want = sent.Add(time.Duration(*c.reported) * time.Second)
		}
		if !next.Equal(want) {
			t.Errorf("%s: expires %v, want %v", c.name, next, want)
		}
	}
}

// The daemon's identity cannot take the hold: meta/ is the broker's to
// write (Ruling 10; pre-flight I15).
func TestTheDaemonCannotTakeTheHold(t *testing.T) {
	const prefix = "/port49/"
	srv := provisioned(t, prefix)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, _, err := openAs(t, srv, "port49-daemon", prefix).Hold(ctx, 10*time.Second, "x", func(string) {}); !errors.Is(err, ErrRefused) {
		t.Fatalf("the daemon took the hold: %v", err)
	}
	lost, release, err := openAs(t, srv, "port49-broker", prefix).Hold(ctx, 10*time.Second, "x", func(string) {})
	if err != nil {
		t.Fatalf("the broker could not take the hold: %v", err)
	}
	_ = lost
	release()
}

// syncLines collects what a store says through Logf.
type syncLines struct {
	mu    sync.Mutex
	lines []string
}

func (l *syncLines) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *syncLines) count(s string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, line := range l.lines {
		if strings.Contains(line, s) {
			n++
		}
	}
	return n
}

func (l *syncLines) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}
