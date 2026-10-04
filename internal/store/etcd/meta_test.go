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

func TestSealKeysRoundTrip(t *testing.T) {
	ctx := context.Background()
	s, err := Open(Config{Endpoints: []string{etcdtest.Endpoint()}, Prefix: etcdtest.Prefix()})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, ok, err := s.SealKeys(ctx); ok || err != nil {
		t.Fatalf("a new keyspace has seal keys: %v %v", ok, err)
	}
	want := SealKeys{Current: "enc3", Previous: "enc2", WrittenAt: t0}
	if err := s.PutSealKeys(ctx, want); err != nil {
		t.Fatal(err)
	}
	if got, ok, err := s.SealKeys(ctx); !ok || err != nil || got.Current != "enc3" || got.Previous != "enc2" {
		t.Fatalf("%+v %v %v", got, ok, err)
	}
}

// A window that does not decode is ErrSealKeysUndecodable, apart from an
// outage, so a start can go on past it.
func TestSealKeysUndecodable(t *testing.T) {
	ctx := context.Background()
	prefix := etcdtest.Prefix()
	s, err := Open(Config{Endpoints: []string{etcdtest.Endpoint()}, Prefix: prefix})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.ctx.Put(ctx, s.k.meta("seal_keys"), "not json"); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.SealKeys(ctx); ok || !errors.Is(err, ErrSealKeysUndecodable) ||
		errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("%v %v", ok, err)
	}
}

// meta/judged reads back what was put: the bundle and its policy, or the
// bundle alone when the policy was over maxJudgedPolicy. An absent record
// is ok false with no error, and so is one that does not decode, said by
// its key alone, so a takeover purges (plan 7e, Rulings 7, 17).
func TestJudgedIsReadBackAndAbsentIsNotFound(t *testing.T) {
	ctx := context.Background()
	var said syncLines
	s, err := Open(Config{Endpoints: []string{etcdtest.Endpoint()}, Prefix: etcdtest.Prefix(), Logf: said.logf})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if got, ok, err := s.Judged(ctx); ok || err != nil || got.Bundle != "" {
		t.Fatalf("a new keyspace has a judged bundle: %+v %v %v", got, ok, err)
	}
	if err := s.PutJudged(ctx, "b1", []byte("grants: []\n")); err != nil {
		t.Fatal(err)
	}
	if got, ok, err := s.Judged(ctx); !ok || err != nil || got.Bundle != "b1" || string(got.Policy) != "grants: []\n" {
		t.Fatalf("%+v %v %v", got, ok, err)
	}
	big := []byte(strings.Repeat("#", maxJudgedPolicy+1))
	if err := s.PutJudged(ctx, "b2", big); err != nil {
		t.Fatal(err)
	}
	if got, ok, err := s.Judged(ctx); !ok || err != nil || got.Bundle != "b2" || got.Policy != nil {
		t.Fatalf("a policy over maxJudgedPolicy is left out: %v %v %v %d", got.Bundle, ok, err, len(got.Policy))
	}
	if _, err := s.ctx.Put(ctx, s.k.meta("judged"), "not json"); err != nil {
		t.Fatal(err)
	}
	if got, ok, err := s.Judged(ctx); ok || err != nil || got.Bundle != "" {
		t.Fatalf("a record that does not decode: %+v %v %v", got, ok, err)
	}
	if said.count(s.k.meta("judged")+" does not decode") != 1 || strings.Contains(said.String(), "not json") {
		t.Fatalf("said: %q", said.String())
	}
}

// Each replica's record of the bundle it serves is listed while its ttl
// lasts, and lapses by its own expiry; a who of any spelling round-trips,
// and a graceful stop deletes it at once (plan 7e, Ruling 8; pre-flight
// I3, 7e-2 P-5).
func TestBundlesAreLeasedAndListed(t *testing.T) {
	ctx := context.Background()
	s := onShared(t, time.Now)
	who := "port49-broker on host a (pid 7, since 2026-10-04T00:00:00Z)"
	if err := s.PutBundle(ctx, who, "b1", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := s.PutBundle(ctx, "replica-b", "b2", 2*time.Second); err != nil {
		t.Fatal(err)
	}
	recs, err := s.Bundles(ctx)
	if err != nil || len(recs) != 2 {
		t.Fatalf("two records: %+v %v", recs, err)
	}
	got := map[string]string{}
	for _, r := range recs {
		got[r.Who] = r.Bundle
		if !r.ExpiresAt.After(r.At) {
			t.Fatalf("a record expiring at %v, written at %v", r.ExpiresAt, r.At)
		}
	}
	if got[who] != "b1" || got["replica-b"] != "b2" {
		t.Fatalf("listed %v", got)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		recs, err := s.Bundles(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(recs) == 1 && recs[0].Who == who {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("a record past its 2s ttl is still listed after 5s: %+v", recs)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := s.DeleteBundle(ctx, who); err != nil {
		t.Fatal(err)
	}
	if recs, err := s.Bundles(ctx); err != nil || len(recs) != 0 {
		t.Fatalf("a deleted record is listed: %+v %v", recs, err)
	}
	if _, err := s.ctx.Put(ctx, s.k.meta("bundles/")+esc("bad"), "not json"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Bundles(ctx); err == nil || !strings.Contains(err.Error(), s.k.meta("bundles/")+"bad") ||
		strings.Contains(err.Error(), "not json") {
		t.Fatalf("a record that does not decode: %v", err)
	}
}

// The ask for a full context pass is cleared only at the revision the
// pass read: an ask written during the pass stays (pre-flight I3).
func TestRefreshOwedIsClearedOnlyAtItsRevision(t *testing.T) {
	ctx := context.Background()
	s := onShared(t, time.Now)
	if _, _, ok, err := s.RefreshOwed(ctx); ok || err != nil {
		t.Fatalf("a new keyspace owes a pass: %v %v", ok, err)
	}
	if err := s.PutRefreshOwed(ctx, "replica-b", "b1"); err != nil {
		t.Fatal(err)
	}
	rev1, rec, ok, err := s.RefreshOwed(ctx)
	if !ok || err != nil || rec.Who != "replica-b" || rec.Bundle != "b1" {
		t.Fatalf("%+v %v %v", rec, ok, err)
	}
	if err := s.PutRefreshOwed(ctx, "replica-c", "b2"); err != nil {
		t.Fatal(err)
	}
	rev2, rec, ok, err := s.RefreshOwed(ctx)
	if !ok || err != nil || rev2 <= rev1 || rec.Who != "replica-c" {
		t.Fatalf("the second ask: %d after %d, %+v %v %v", rev2, rev1, rec, ok, err)
	}
	if err := s.ClearRefreshOwed(ctx, rev1); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, err := s.RefreshOwed(ctx); !ok || err != nil {
		t.Fatalf("a clear at the first ask's revision took the second: %v %v", ok, err)
	}
	if err := s.ClearRefreshOwed(ctx, rev2); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, err := s.RefreshOwed(ctx); ok || err != nil {
		t.Fatalf("a clear at its revision left the ask: %v %v", ok, err)
	}
}

// meta/judged is withdrawn, not deleted, while a replica serves another
// bundle: marked in doubt with its bundle and policy kept for the reload
// guard at a start, so the next takeover purges (Task 15a review I-1). A
// runner's record replaces it only while no replica's record and no mark
// was written after the replicas' records it judged were read; a record
// deleted since mints nothing more.
func TestAJudgedRecordGoesInDoubtAndIsReplacedOnlyWhenNothingMoved(t *testing.T) {
	ctx := context.Background()
	s := onShared(t, time.Now)
	if b, marked, err := s.JudgeInDoubt(ctx, ""); b != "" || marked || err != nil {
		t.Fatalf("no record to mark: %q %v %v", b, marked, err)
	}
	if _, ok, err := s.Judged(ctx); ok || err != nil {
		t.Fatalf("a mark with no record wrote one: %v %v", ok, err)
	}
	pol := []byte("grants: []\n")
	if err := s.PutJudged(ctx, "b1", pol); err != nil {
		t.Fatal(err)
	}
	if got, ok, err := s.Judged(ctx); !ok || err != nil || got.InDoubt {
		t.Fatalf("a record just put is in doubt: %+v %v %v", got, ok, err)
	}
	if b, marked, err := s.JudgeInDoubt(ctx, "b1"); b != "b1" || marked || err != nil {
		t.Fatalf("a replica on the bundle judged marked it: %q %v %v", b, marked, err)
	}
	if got, _, _ := s.Judged(ctx); got.InDoubt {
		t.Fatal("a replica on the bundle judged marked it in doubt")
	}
	if b, marked, err := s.JudgeInDoubt(ctx, "b9"); b != "b1" || !marked || err != nil {
		t.Fatalf("the mark: %q %v %v", b, marked, err)
	}
	if got, ok, err := s.Judged(ctx); !ok || err != nil || !got.InDoubt || got.Bundle != "b1" ||
		string(got.Policy) != string(pol) {
		t.Fatalf("a record marked in doubt: %+v %v %v", got, ok, err)
	}
	if b, marked, err := s.JudgeInDoubt(ctx, ""); b != "b1" || marked || err != nil {
		t.Fatalf("a record already in doubt is marked again: %q %v %v", b, marked, err)
	}
	_, rev, err := s.BundlesAt(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutBundle(ctx, "replica-c", "b2", time.Minute); err != nil {
		t.Fatal(err)
	}
	if put, err := s.PutJudgedSince(ctx, "b1", pol, rev); put || err != nil {
		t.Fatalf("recorded over a replica's record written since: %v %v", put, err)
	}
	if got, _, _ := s.Judged(ctx); !got.InDoubt {
		t.Fatal("a refused record cleared the mark")
	}
	if _, rev, err = s.BundlesAt(ctx); err != nil {
		t.Fatal(err)
	}
	if put, err := s.PutJudgedSince(ctx, "b1", pol, rev); !put || err != nil {
		t.Fatalf("nothing moved since: %v %v", put, err)
	}
	if got, ok, err := s.Judged(ctx); !ok || err != nil || got.InDoubt || got.Bundle != "b1" {
		t.Fatalf("a record put clears the mark: %+v %v %v", got, ok, err)
	}
	if _, rev, err = s.BundlesAt(ctx); err != nil {
		t.Fatal(err)
	}
	if _, marked, err := s.JudgeInDoubt(ctx, ""); !marked || err != nil {
		t.Fatalf("the mark: %v %v", marked, err)
	}
	if put, err := s.PutJudgedSince(ctx, "b1", pol, rev); put || err != nil {
		t.Fatalf("recorded over a mark written since: %v %v", put, err)
	}
	if _, rev, err = s.BundlesAt(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteBundle(ctx, "replica-c"); err != nil {
		t.Fatal(err)
	}
	if put, err := s.PutJudgedSince(ctx, "b1", pol, rev); !put || err != nil {
		t.Fatalf("refused over a record deleted since: %v %v", put, err)
	}
}

// A witness lands only over the revision it was given, so two runners
// for a moment cannot write one over the other, and a read says both
// its revision and the store's (Ruling 18).
func TestAWitnessLandsOnlyOverTheOneRead(t *testing.T) {
	ctx := context.Background()
	s := onShared(t, time.Now)
	if w, err := s.Witness(ctx); err != nil || w.ModRevision != 0 || w.Header == 0 {
		t.Fatalf("no witness yet: %+v %v", w, err)
	}
	first, err := s.PutWitness(ctx, "runner-a", 0)
	if err != nil || first == 0 {
		t.Fatalf("the first witness: %d %v", first, err)
	}
	if got, err := s.PutWitness(ctx, "runner-b", 0); err != nil || got != 0 {
		t.Fatalf("a witness over an absent one that is there now: %d %v", got, err)
	}
	if w, err := s.Witness(ctx); err != nil || w.ModRevision != first || w.Header < first {
		t.Fatalf("the witness read back: %+v %v", w, err)
	}
	if got, err := s.PutWitness(ctx, "runner-a", first); err != nil || got <= first {
		t.Fatalf("a witness over the one read: %d %v", got, err)
	}
}

// FollowWitness tells every ModRevision the witness is written at, from
// its first read on, until ctx ends (Ruling 18).
func TestFollowWitnessTellsEachWrite(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s := onShared(t, time.Now)
	first, err := s.PutWitness(ctx, "runner-a", 0)
	if err != nil || first == 0 {
		t.Fatalf("the first witness: %d %v", first, err)
	}
	var mu sync.Mutex
	var saw []uint64
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.FollowWitness(ctx, func(rev uint64) { mu.Lock(); saw = append(saw, rev); mu.Unlock() })
	}()
	next, err := s.PutWitness(ctx, "runner-a", first)
	if err != nil || next == 0 {
		t.Fatalf("the next witness: %d %v", next, err)
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		mu.Lock()
		got := append([]uint64(nil), saw...)
		mu.Unlock()
		if len(got) > 0 && got[len(got)-1] == next {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("followed %v; the witness is at %d", got, next)
		}
	}
	cancel()
	<-done
}
