package store

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Marks is the daemon's copy of the standing marks (plan 7d; Ruling 17):
// a context its principal or certificate names stands revoked at the
// later of its own mark and the record's; a lifted mark names nothing; a
// blank certificate key names no certificate; nil names nothing.
func TestMarksNameAContextByPrincipalOrCertificate(t *testing.T) {
	at := time.Unix(1_000_000, 0).UTC()
	m := NewMarks()
	alice := Context{Principal: "user:alice@example.com", Credential: Credential{Issuer: "CN=Corp CA", Serial: "0a"}}
	if !m.RevokedAt(alice).IsZero() {
		t.Fatal("no mark, revoked")
	}
	m.Set(Revocation{Kind: RevocationPrincipal, Key: alice.Principal, At: at}, true)
	if !m.RevokedAt(alice).Equal(at) {
		t.Fatal("a principal's mark")
	}
	m.Set(Revocation{Kind: RevocationPrincipal, Key: alice.Principal, At: at.Add(time.Hour)}, true)
	if !m.RevokedAt(alice).Equal(at) {
		t.Fatal("a repeated mark moved the first one's time")
	}
	m.Set(Revocation{Kind: RevocationPrincipal, Key: alice.Principal}, false)
	if !m.RevokedAt(alice).IsZero() || m.Len() != 0 {
		t.Fatal("a lifted mark")
	}
	m.Set(Revocation{Kind: RevocationCert, Key: CertKey("CN=Corp CA", "0a"), At: at}, true)
	if !m.RevokedAt(alice).Equal(at) {
		t.Fatal("a certificate's mark")
	}
	oidc := Context{Principal: "user:bob@example.com"}
	m.Set(Revocation{Kind: RevocationCert, Key: "|", At: at}, true)
	if !m.RevokedAt(oidc).IsZero() {
		t.Fatal("a blank certificate key named an OIDC login")
	}
	later := alice
	later.RevokedAt = at.Add(time.Minute)
	if !m.RevokedAt(later).Equal(later.RevokedAt) {
		t.Fatal("the record's own later revocation")
	}
	var none *Marks
	if !none.RevokedAt(alice).IsZero() {
		t.Fatal("a nil Marks named a mark")
	}
}

// markFeed serves a set of marks at rev 7, and a watch that delivers what
// the test sends. The set is read on FollowMarks's goroutine at a reload,
// so it is behind a lock (pre-flight M4, the race). Each watch's after is
// sent on afters when afters is set, and a send on fail ends the watch
// with that error.
type markFeed struct {
	mu      sync.Mutex
	marks   []Revocation
	events  chan markEvent
	compact chan struct{}
	fail    chan error
	afters  chan uint64
}

type markEvent struct {
	r      Revocation
	lifted bool
	rev    uint64
}

func (f *markFeed) setMarks(rs []Revocation) { f.mu.Lock(); f.marks = rs; f.mu.Unlock() }

func (f *markFeed) Revocations(context.Context) (uint64, []Revocation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return 7, append([]Revocation(nil), f.marks...), nil
}

// told renders a change for the assertions: key, standing, reloaded.
func told(c MarkChange) string { return fmt.Sprintf("%s %v %v", c.Key, c.Standing, c.Reloaded) }
func (f *markFeed) WatchRevocations(ctx context.Context, after uint64, fn func(Revocation, bool, uint64)) error {
	if f.afters != nil {
		f.afters <- after
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e := <-f.events:
			fn(e.r, e.lifted, e.rev)
		case <-f.compact:
			return ErrCompacted
		case err := <-f.fail:
			return err
		}
	}
}

// waitFor polls cond for up to 5s.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("not within 5s")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// LoadMarks puts every stored mark in, takes out one the store lacks, and
// tells on of each change, each as Reloaded: a mark missing from a load
// may be a restore's loss, not a lift (Ruling 12).
func TestLoadMarksMakesTheCopyTheStores(t *testing.T) {
	alice := Revocation{Kind: RevocationPrincipal, Key: "user:alice@example.com", At: time.Unix(10, 0)}
	gone := Revocation{Kind: RevocationPrincipal, Key: "user:bob@example.com", At: time.Unix(5, 0)}
	m := NewMarks()
	m.Set(gone, true)
	var got []string
	rev, err := LoadMarks(context.Background(), &markFeed{marks: []Revocation{alice}}, m,
		func(c MarkChange) { got = append(got, told(c)) })
	if err != nil || rev != 7 || !m.Holds(alice.Kind, alice.Key) || m.Holds(gone.Kind, gone.Key) {
		t.Fatalf("rev %d: %v; marks %v", rev, err, m.All())
	}
	sort.Strings(got)
	if fmt.Sprint(got) != "[user:alice@example.com true true user:bob@example.com false true]" {
		t.Fatalf("told %v", got)
	}
}

// FollowMarks applies each put and lift, told as events; a compacted
// watch loads them again and applies the difference, telling on of it
// alone, as reloaded.
func TestACompactedMarkFeedReloadsTheDifference(t *testing.T) {
	alice := Revocation{Kind: RevocationPrincipal, Key: "user:alice@example.com", At: time.Unix(10, 0)}
	carol := Revocation{Kind: RevocationPrincipal, Key: "user:carol@example.com", At: time.Unix(11, 0)}
	dave := Revocation{Kind: RevocationPrincipal, Key: "user:dave@example.com", At: time.Unix(12, 0)}
	f := &markFeed{events: make(chan markEvent, 1), compact: make(chan struct{}, 1)}
	m := NewMarks()
	var mu sync.Mutex
	var got []string
	on := func(c MarkChange) { mu.Lock(); got = append(got, told(c)); mu.Unlock() }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go FollowMarks(ctx, f, m, 7, on, func(bool) {}, func() {}, t.Logf)
	f.events <- markEvent{r: alice}
	f.events <- markEvent{r: dave}
	f.events <- markEvent{r: dave, lifted: true}
	waitFor(t, func() bool { return m.Holds(alice.Kind, alice.Key) && !m.Holds(dave.Kind, dave.Key) })
	f.setMarks([]Revocation{carol}) // alice lifted and carol marked while the watch was compacted away
	f.compact <- struct{}{}
	waitFor(t, func() bool { return m.Holds(carol.Kind, carol.Key) && !m.Holds(alice.Kind, alice.Key) })
	mu.Lock()
	defer mu.Unlock()
	want := []string{
		"user:alice@example.com true false", "user:dave@example.com true false",
		"user:dave@example.com false false", // a lift the watch delivered: not reloaded
	}
	if len(got) != 5 || fmt.Sprint(got[:3]) != fmt.Sprint(want) {
		t.Fatalf("told %v", got)
	}
	rest := append([]string(nil), got[3:]...)
	sort.Strings(rest)
	if fmt.Sprint(rest) != "[user:alice@example.com false true user:carol@example.com true true]" {
		t.Fatalf("the reload told %v", rest)
	}
}

// A watch that fails is watched again from the last event it delivered,
// never from where the follow began: re-delivering a put whose lift came
// after would stand the mark again, and close the held connections of a
// principal already let back in. A compacted watch's reload never takes
// the follow back either: it goes on from the later of the load's
// revision and the last event. A put of a mark already standing tells
// nothing, and keeps the mark's first time.
func TestAMarkFeedResumesWhereItWas(t *testing.T) {
	alice := Revocation{Kind: RevocationPrincipal, Key: "user:alice@example.com", At: time.Unix(10, 0)}
	f := &markFeed{events: make(chan markEvent), compact: make(chan struct{}), fail: make(chan error),
		afters: make(chan uint64, 4)}
	f.setMarks([]Revocation{alice})
	m := NewMarks()
	var mu sync.Mutex
	var got []string
	on := func(c MarkChange) { mu.Lock(); got = append(got, told(c)); mu.Unlock() }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var rescans atomic.Int32
	go FollowMarks(ctx, f, m, 3, on, func(bool) {}, func() { rescans.Add(1) }, t.Logf)
	after := func() uint64 {
		select {
		case a := <-f.afters:
			return a
		case <-time.After(5 * time.Second):
			t.Fatal("no watch")
			return 0
		}
	}
	if a := after(); a != 3 {
		t.Fatalf("the first watch is after %d, want 3", a)
	}
	f.events <- markEvent{r: alice, rev: 20}
	f.events <- markEvent{r: Revocation{Kind: alice.Kind, Key: alice.Key, At: time.Unix(99, 0)}, rev: 21}
	// A lift of a mark that does not stand tells nothing; the watch has
	// applied the repeat once this send is taken.
	f.events <- markEvent{r: Revocation{Kind: alice.Kind, Key: "user:zed@example.com"}, lifted: true, rev: 22}
	if all := m.All(); len(all) != 1 || !all[0].At.Equal(alice.At) {
		t.Fatalf("a repeated put: marks %v", all)
	}
	f.events <- markEvent{r: Revocation{Kind: alice.Kind, Key: alice.Key}, lifted: true, rev: 23}
	f.fail <- fmt.Errorf("%w: the watch ended", ErrUnavailable)
	if a := after(); a != 23 {
		t.Fatalf("the watch after a failure is after %d, want 23", a)
	}
	f.compact <- struct{}{} // the load is at 7, below what was delivered
	if a := after(); a != 23 {
		t.Fatalf("the watch after a reload at 7 is after %d, want 23", a)
	}
	if !m.Holds(alice.Kind, alice.Key) || rescans.Load() != 1 {
		t.Fatalf("marks %v, %d rescans", m.All(), rescans.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	if fmt.Sprint(got) != "[user:alice@example.com true false user:alice@example.com false false "+
		"user:alice@example.com true true]" {
		t.Fatalf("told %v", got)
	}
}

// A load that fails changes nothing and tells nothing.
func TestALoadThatFailsChangesNoMark(t *testing.T) {
	alice := Revocation{Kind: RevocationPrincipal, Key: "user:alice@example.com", At: time.Unix(10, 0)}
	m := NewMarks()
	m.Set(alice, true)
	_, err := LoadMarks(context.Background(), failingFeed{}, m, func(MarkChange) { t.Fatal("told") })
	if !errors.Is(err, ErrUnavailable) || !m.Holds(alice.Kind, alice.Key) {
		t.Fatalf("%v; marks %v", err, m.All())
	}
}

type failingFeed struct{}

func (failingFeed) Revocations(context.Context) (uint64, []Revocation, error) {
	return 0, nil, ErrUnavailable
}

func (failingFeed) WatchRevocations(context.Context, uint64, func(Revocation, bool, uint64)) error {
	return ErrUnavailable
}

// All is every mark in force, sorted by kind and key, each with its time.
func TestAllIsEveryMarkSorted(t *testing.T) {
	m := NewMarks()
	m.Set(Revocation{Kind: RevocationPrincipal, Key: "user:b", At: time.Unix(2, 0)}, true)
	m.Set(Revocation{Kind: RevocationPrincipal, Key: "user:a", At: time.Unix(1, 0)}, true)
	m.Set(Revocation{Kind: RevocationCert, Key: "CN=x|0a", At: time.Unix(3, 0)}, true)
	got := ""
	for _, r := range m.All() {
		got += fmt.Sprintf("%s/%s@%d ", r.Kind, r.Key, r.At.Unix())
	}
	if got != "cert/CN=x|0a@3 principal/user:a@1 principal/user:b@2 " {
		t.Fatalf("All %q", got)
	}
	var none *Marks
	if none.All() != nil {
		t.Fatal("a nil Marks has marks")
	}
}

// A mark put in force before its store write has landed (Pend) is never
// lifted by a load the store lacks it in (Ruling T9-b): its write failed,
// or has not committed yet, and a reload is not a lift. Once a load or a
// watch shows the store holds it, or the broker's correction (Put) says
// so, it is the store's like any other, and a load without it lifts it. A
// lift the watch brings, or the broker's own (Set false), lifts it at once.
func TestAReloadKeepsAMarkStillUnwritten(t *testing.T) {
	alice := Revocation{Kind: RevocationPrincipal, Key: "user:alice@example.com", At: time.Unix(10, 0)}
	ctx := context.Background()
	var got []string
	on := func(c MarkChange) { got = append(got, told(c)) }
	empty, holding := &markFeed{}, &markFeed{marks: []Revocation{alice}}

	m := NewMarks()
	m.Pend(alice)
	if _, err := LoadMarks(ctx, empty, m, on); err != nil || !m.Holds(alice.Kind, alice.Key) || len(got) != 0 {
		t.Fatalf("an unwritten mark after a load without it: %v, holds %v, told %v", err,
			m.Holds(alice.Kind, alice.Key), got)
	}
	LoadMarks(ctx, holding, m, on) // the store has it now
	LoadMarks(ctx, empty, m, on)
	if m.Holds(alice.Kind, alice.Key) || fmt.Sprint(got) != "[user:alice@example.com false true]" {
		t.Fatalf("a mark the store held, then lacked: holds %v, told %v", m.Holds(alice.Kind, alice.Key), got)
	}

	m.Pend(alice)
	m.Put(alice) // the broker's correction: the store holds it
	LoadMarks(ctx, empty, m, nil)
	if m.Holds(alice.Kind, alice.Key) {
		t.Fatal("a mark Put said the store held outlived a load without it")
	}

	m.Pend(alice)
	m.Set(alice, false) // the broker's own lift
	m.Set(alice, true)  // marked again, written
	LoadMarks(ctx, empty, m, nil)
	if m.Holds(alice.Kind, alice.Key) {
		t.Fatal("a lifted unwritten mark stayed unwritten")
	}

	// The watch: a put shows the store holds it; a lift lifts it.
	f := &markFeed{events: make(chan markEvent), compact: make(chan struct{})}
	m.Pend(alice)
	fctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go FollowMarks(fctx, f, m, 7, nil, func(bool) {}, func() {}, t.Logf)
	f.events <- markEvent{r: alice, rev: 8}
	f.compact <- struct{}{} // the load is empty: the watched put made it the store's
	waitFor(t, func() bool { return !m.Holds(alice.Kind, alice.Key) })
	m.Pend(alice)
	f.events <- markEvent{r: Revocation{Kind: alice.Kind, Key: alice.Key}, lifted: true, rev: 9}
	waitFor(t, func() bool { return !m.Holds(alice.Kind, alice.Key) })
}

// Put is a correction only: it moves the time of a mark in force, and
// never puts back one lifted meanwhile (review M2).
func TestPutCorrectsOnlyAMarkInForce(t *testing.T) {
	alice := Revocation{Kind: RevocationPrincipal, Key: "user:alice@example.com", At: time.Unix(10, 0)}
	m := NewMarks()
	if m.Put(alice) || m.Holds(alice.Kind, alice.Key) {
		t.Fatal("Put put back a mark not in force")
	}
	m.Set(Revocation{Kind: alice.Kind, Key: alice.Key, At: time.Unix(20, 0)}, true)
	if !m.Put(alice) || !m.All()[0].At.Equal(alice.At) {
		t.Fatalf("Put did not correct the time: %v", m.All())
	}
}
