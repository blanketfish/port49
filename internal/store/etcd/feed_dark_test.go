package etcd

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/store"
	"github.com/blanketfish/port49/internal/store/etcd/etcdtest"
)

// legTrace records, for a test that logs it only on a failure, where each leg
// of a watch was placed and reopened, when it delivered, and what the test
// noted (members hung, writes and their durations). It holds revisions and
// members, no keys or values.
type legTrace_ struct {
	begun  time.Time
	mu     sync.Mutex
	lines  []string
	apart  bool         // the last placement put the legs on different members
	last   string       // the last placement's detail, for a failure message
	placed [2]placement // each leg's latest opening
}

// placement is a leg's latest opening as the trace saw it: how many it has
// had (across the watch's restarts, whose openings count from 1 again), its
// member, and the other leg's member at its pick.
type placement struct {
	n         int
	on, other string
}

func traceLegs(t *testing.T) *legTrace_ {
	tr := &legTrace_{begun: time.Now()}
	hook := func(ev string, leg, gen int, detail string) {
		tr.note("leg %d opening %d: %s %s", leg, gen, ev, detail)
		tr.mu.Lock()
		defer tr.mu.Unlock()
		switch ev {
		case "together":
			tr.apart, tr.last = false, detail
		case "open": // "on A, the other on B"
			if a, b, ok := strings.Cut(strings.TrimPrefix(detail, "on "), ", the other on "); ok {
				tr.apart, tr.last = a != "" && b != "" && a != b, detail
				tr.placed[leg] = placement{n: tr.placed[leg].n + 1, on: a, other: b}
			}
		}
	}
	legTrace.Store(&hook)
	t.Cleanup(func() { legTrace.Store(nil) })
	return tr
}

func (tr *legTrace_) note(format string, args ...any) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.lines = append(tr.lines, fmt.Sprintf("+%v ", time.Since(tr.begun).Round(time.Millisecond))+fmt.Sprintf(format, args...))
}

// waitApart waits up to d for the legs to be placed on different members, and
// fails the test naming where they are if they are not: a test of a member
// going dark needs the legs apart, which a watch that began with one member
// ready reaches only after its relocation wait.
func (tr *legTrace_) waitApart(t *testing.T, d time.Duration) {
	t.Helper()
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		tr.mu.Lock()
		ok := tr.apart
		tr.mu.Unlock()
		if ok {
			tr.note("legs apart")
			return
		}
	}
	tr.mu.Lock()
	last := tr.last
	tr.mu.Unlock()
	tr.dump(t)
	t.Fatalf("the legs were not on different members within %v (last placement: %s)", d, last)
}

func (tr *legTrace_) at(leg int) placement {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return tr.placed[leg]
}

// waitPlaced waits up to d for leg's opening number after+1 or later, and
// returns it, or fails the test with the trace.
func (tr *legTrace_) waitPlaced(t *testing.T, leg, after int, d time.Duration) placement {
	t.Helper()
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if p := tr.at(leg); p.n > after {
			return p
		}
	}
	p := tr.at(leg)
	tr.dump(t)
	t.Fatalf("leg %d was not opened again within %v (latest: opening %d, on %q)", leg, d, p.n, p.on)
	return placement{}
}

func (tr *legTrace_) dump(t *testing.T) {
	t.Helper()
	tr.mu.Lock()
	defer tr.mu.Unlock()
	t.Logf("placement and delivery since the test began:\n  %s", strings.Join(tr.lines, "\n  "))
}

// contextWatch runs FollowContexts's loop over s.WatchContexts until the test
// ends. put writes a context named name, trying again past a dark member;
// delivered reports whether the feed brought it within d.
func contextWatch(t *testing.T, s *Store) (put func(name string), delivered func(name string, within time.Duration) bool) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	var mu sync.Mutex
	seen := map[string]bool{}
	from := uint64(0)
	go func() {
		for ctx.Err() == nil {
			mu.Lock()
			after := from
			mu.Unlock()
			s.WatchContexts(ctx, after, func(c store.ContextChange) {
				mu.Lock()
				seen[c.Key.Username] = true
				from = max(from, c.Rev)
				mu.Unlock()
			}, func(rev uint64) { mu.Lock(); from = max(from, rev); mu.Unlock() }, nil)
			time.Sleep(time.Second)
		}
	}()
	put = func(name string) {
		k := store.ContextKey{NAS: "leaf-01", Username: name}
		for i := 0; i < 20; i++ { // a write may meet the dark member: try again
			c, cc := context.WithTimeout(ctx, 500*time.Millisecond)
			err := s.PutContext(c, k, store.Context{CtxID: name, Principal: "user:x", Username: name}, time.Hour)
			cc()
			if err == nil {
				return
			}
		}
		t.Fatalf("could not write %s", name)
	}
	delivered = func(name string, within time.Duration) bool {
		for end := time.Now().Add(within); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
			mu.Lock()
			ok := seen[name]
			mu.Unlock()
			if ok {
				return true
			}
		}
		return false
	}
	return put, delivered
}

// The context feed has a leg on two of the three members, so one going dark
// leaves it following: the fence holds a login behind the feed, and a feed on
// a paused member (its connection stays up until keepalive fails it, 10 to 12
// s on) refused logins for that long. Each member goes dark in turn, so one is
// a leg's; the change written after must still arrive at once. The loop is
// FollowContexts's.
func TestAContextFeedFollowsWhicheverMemberGoesDark(t *testing.T) {
	s, _, ps := threeBehindProxies(t)
	tr := traceLegs(t) // logged only when a round fails
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	seen := map[string]bool{}
	from := uint64(0)
	go func() {
		for ctx.Err() == nil {
			mu.Lock()
			after := from
			mu.Unlock()
			s.WatchContexts(ctx, after, func(c store.ContextChange) {
				mu.Lock()
				seen[c.Key.Username] = true
				from = max(from, c.Rev)
				mu.Unlock()
			}, func(rev uint64) { mu.Lock(); from = max(from, rev); mu.Unlock() }, nil)
			time.Sleep(time.Second)
		}
	}()
	put := func(name string) {
		k := store.ContextKey{NAS: "leaf-01", Username: name}
		for i := 0; i < 20; i++ { // a write may meet the dark member: try again
			c, cc := context.WithTimeout(ctx, 500*time.Millisecond)
			err := s.PutContext(c, k, store.Context{CtxID: name, Principal: "user:x", Username: name}, time.Hour)
			cc()
			if err == nil {
				return
			}
		}
		t.Fatalf("could not write %s", name)
	}
	delivered := func(name string, within time.Duration) bool {
		for end := time.Now().Add(within); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
			mu.Lock()
			ok := seen[name]
			mu.Unlock()
			if ok {
				return true
			}
		}
		return false
	}
	put("warm")
	if !delivered("warm", 5*time.Second) {
		t.Fatal("the watch delivered nothing on a healthy cluster")
	}
	for i, p := range ps {
		name := fmt.Sprintf("dark%d", i)
		p.Hang(true)
		tr.note("member %d hung", i)
		putStart := time.Now()
		put(name)
		tr.note("%s written in %v", name, time.Since(putStart).Round(time.Millisecond))
		if !delivered(name, 1500*time.Millisecond) {
			t.Errorf("member %d dark: the feed had not brought a change written after it went dark in 1.5s", i)
			tr.dump(t)
		} else {
			tr.note("%s delivered", name)
		}
		p.Hang(false)
		time.Sleep(3 * time.Second) // reconnect settles
	}
}

// The second leg is never placed on the first leg's member while another
// member's connection is still being made: it waits for that member. Members
// 1 and 2 are hung before the store dials, so their connections stay
// connecting while member 0 is ready. The old picker put the second leg on
// member 0 at once, and member 0 then going dark stalled the feed until a leg moved,
// 2 s or more (#64, CI 42563304174).
func TestTheSecondLegWaitsForAMemberStillConnectingRatherThanShareTheFirsts(t *testing.T) {
	s, _, ps := threeBehindProxiesWith(t, func(ps []*etcdtest.Proxy) { ps[1].Hang(true); ps[2].Hang(true) })
	tr := traceLegs(t)
	put, delivered := contextWatch(t, s)
	// The legs open in either order: whichever is placed first is the first.
	fl := -1
	for end := time.Now().Add(5 * time.Second); fl < 0 && time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		if tr.at(0).n > 0 {
			fl = 0
		} else if tr.at(1).n > 0 {
			fl = 1
		}
	}
	if fl < 0 {
		tr.dump(t)
		t.Fatal("neither leg was placed within 5s")
	}
	ol := 1 - fl
	first := tr.at(fl)
	if first.on != ps[0].Addr() {
		tr.dump(t)
		t.Fatalf("leg %d was placed on %q with only member 0 (%s) ready", fl, first.on, ps[0].Addr())
	}
	time.Sleep(time.Second) // the old picker placed the other leg within milliseconds
	if p := tr.at(ol); p.n > 0 {
		tr.dump(t)
		t.Fatalf("leg %d was placed on %s, the first leg's member, while members 1 and 2 were still connecting", ol, p.on)
	}
	ps[1].Hang(false)
	ps[2].Hang(false)
	second := tr.waitPlaced(t, ol, 0, 5*time.Second)
	if second.on == "" || second.on == first.on {
		tr.dump(t)
		t.Fatalf("leg %d was placed on %q once members 1 and 2 were ready, leg %d on %s", ol, second.on, fl, first.on)
	}
	ps[0].Hang(true) // the first leg's member going dark now costs nothing
	tr.note("member 0 hung")
	put("dark")
	if !delivered("dark", 1500*time.Millisecond) {
		tr.dump(t)
		t.Fatal("member 0 dark, the legs apart: the feed had not brought a change written after it went dark in 1.5s")
	}
	ps[0].Hang(false)
}

// A hung member (its connection up, nothing coming back) is left by the leg
// on it within the stall decision 37 names: silent for feedStall while a read
// is answered, seen on a tick (feedIdle/2), the probe (at most feedStall/2),
// and the new opening's Created. It goes to a member neither leg is on. Each
// leg in turn, so both are shown leaving one.
func TestEachLegLeavesAHungMemberForOneTheOtherIsNotOn(t *testing.T) {
	s, _, ps := threeBehindProxies(t)
	tr := traceLegs(t)
	put, delivered := contextWatch(t, s)
	put("warm")
	if !delivered("warm", 5*time.Second) {
		t.Fatal("the watch delivered nothing on a healthy cluster")
	}
	tr.waitApart(t, 6*time.Second)
	byAddr := map[string]*etcdtest.Proxy{}
	for _, p := range ps {
		byAddr[p.Addr()] = p
	}
	bound := feedStall + feedIdle/2 + feedStall/2 + 500*time.Millisecond
	for _, leg := range []int{0, 1} {
		was := tr.at(leg)
		p := byAddr[was.on]
		if p == nil {
			tr.dump(t)
			t.Fatalf("leg %d is on %q, which is no member's proxy", leg, was.on)
		}
		p.Hang(true)
		tr.note("leg %d's member %s hung", leg, was.on)
		hungAt := time.Now()
		now := tr.waitPlaced(t, leg, was.n, bound)
		tr.note("leg %d left it in %v", leg, time.Since(hungAt).Round(time.Millisecond))
		p.Hang(false)
		if now.on == was.on || now.on == now.other {
			tr.dump(t)
			t.Fatalf("leg %d was opened again on %s (it was on %s, the other leg on %s)", leg, now.on, was.on, now.other)
		}
		time.Sleep(3 * time.Second) // reconnect settles
	}
}

// With every member dark the watch is left alone: it revives when the store
// returns, and ending it would only add the retry's second to the recovery
// (CI 41736080508: store_hangs, two of three members paused, took longer to
// open the listener again).
func TestAContextWatchIsLeftAloneWhileEveryMemberIsDark(t *testing.T) {
	s, _, ps := threeBehindProxies(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var opens int
	var mu sync.Mutex
	go func() {
		for ctx.Err() == nil {
			mu.Lock()
			opens++
			mu.Unlock()
			s.WatchContexts(ctx, 0, func(store.ContextChange) {}, func(uint64) {}, nil)
			time.Sleep(time.Second)
		}
	}()
	time.Sleep(2 * time.Second)
	mu.Lock()
	before := opens
	mu.Unlock()
	for _, p := range ps {
		p.Hang(true)
	}
	time.Sleep(8 * time.Second)
	mu.Lock()
	n := opens - before
	mu.Unlock()
	for _, p := range ps {
		p.Hang(false)
	}
	if n != 0 {
		t.Fatalf("the watch was ended and opened %d times in 8s with every member dark", n)
	}
}

// The marks feed carries revocations, so a mark written with a member dark
// reaches the process at once, whichever member the feed's legs were on.
func TestTheMarksFeedFollowsWhicheverMemberGoesDark(t *testing.T) {
	s, _, ps := threeBehindProxies(t)
	tr := traceLegs(t) // logged only when a round fails
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	seen := map[string]bool{}
	from := uint64(0)
	go func() {
		for ctx.Err() == nil {
			mu.Lock()
			after := from
			mu.Unlock()
			s.WatchRevocations(ctx, after, func(r store.Revocation, lifted bool, rev uint64) {
				mu.Lock()
				seen[r.Key] = true
				from = max(from, rev)
				mu.Unlock()
			}, func(rev uint64) { mu.Lock(); from = max(from, rev); mu.Unlock() })
			time.Sleep(time.Second)
		}
	}()
	put := func(name string) {
		for i := 0; i < 20; i++ {
			c, cc := context.WithTimeout(ctx, 500*time.Millisecond)
			err := s.PutRevocation(c, store.Revocation{Kind: store.RevocationPrincipal, Key: name, At: time.Now(), Origin: "test"})
			cc()
			if err == nil {
				return
			}
		}
		t.Fatalf("could not write %s", name)
	}
	delivered := func(name string, within time.Duration) bool {
		for end := time.Now().Add(within); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
			mu.Lock()
			ok := seen[name]
			mu.Unlock()
			if ok {
				return true
			}
		}
		return false
	}
	put("warm")
	if !delivered("warm", 5*time.Second) {
		t.Fatal("the marks feed delivered nothing on a healthy cluster")
	}
	for i, p := range ps {
		name := fmt.Sprintf("dark%d", i)
		p.Hang(true)
		tr.note("member %d hung", i)
		putStart := time.Now()
		put(name)
		tr.note("%s written in %v", name, time.Since(putStart).Round(time.Millisecond))
		if !delivered(name, 1500*time.Millisecond) {
			t.Errorf("member %d dark: the marks feed had not brought a mark written after it went dark in 1.5s", i)
			tr.dump(t)
		} else {
			tr.note("%s delivered", name)
		}
		p.Hang(false)
		time.Sleep(3 * time.Second)
	}
}

// Two members that timed out a moment ago are suspect for 15 s, though they
// answer again; the third then going dark must still leave the feed following.
// Suspicion must never steer a leg, its reopen or the read that gates the
// reopen onto the one member known hung while the others answer.
func TestAFeedFollowsTheLastTrustedMemberGoingDarkWhileTheOthersAreSuspect(t *testing.T) {
	s, _, ps := threeBehindProxies(t)
	tr := traceLegs(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	seen := map[string]bool{}
	from := uint64(0)
	go func() {
		for ctx.Err() == nil {
			mu.Lock()
			after := from
			mu.Unlock()
			s.WatchContexts(ctx, after, func(c store.ContextChange) {
				mu.Lock()
				seen[c.Key.Username] = true
				from = max(from, c.Rev)
				mu.Unlock()
			}, func(rev uint64) { mu.Lock(); from = max(from, rev); mu.Unlock() }, nil)
			time.Sleep(time.Second)
		}
	}()
	put := func(name string) {
		k := store.ContextKey{NAS: "leaf-01", Username: name}
		for i := 0; i < 20; i++ {
			c, cc := context.WithTimeout(ctx, 500*time.Millisecond)
			err := s.PutContext(c, k, store.Context{CtxID: name, Principal: "user:x", Username: name}, time.Hour)
			cc()
			if err == nil {
				return
			}
		}
		t.Fatalf("could not write %s", name)
	}
	delivered := func(name string, within time.Duration) bool {
		for end := time.Now().Add(within); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
			mu.Lock()
			ok := seen[name]
			mu.Unlock()
			if ok {
				return true
			}
		}
		return false
	}
	put("warm")
	if !delivered("warm", 5*time.Second) {
		t.Fatal("the watch delivered nothing on a healthy cluster")
	}
	tr.waitApart(t, 6*time.Second)
	for _, i := range []int{0, 1} { // each is hung until a call on it has timed out, then answers again
		ps[i].Hang(true)
		for n := 0; n < 30; n++ {
			c, cc := context.WithTimeout(ctx, 500*time.Millisecond)
			_, err := s.PutToken(c, store.TokenKey{NAS: "leaf-01", Username: fmt.Sprint("probe", i, n)},
				store.Token{ID: fmt.Sprint("p", i, n), Secret: []byte("x"), Kind: store.KindLogin, ExpiresAt: time.Now().Add(time.Minute)})
			cc()
			if err != nil {
				break
			}
		}
		ps[i].Hang(false)
		tr.note("member %d made suspect", i)
	}
	ps[2].Hang(true)
	tr.note("member 2 hung")
	putStart := time.Now()
	put("last")
	tr.note("last written in %v", time.Since(putStart).Round(time.Millisecond))
	if !delivered("last", 1500*time.Millisecond) {
		t.Errorf("member 2 dark with members 0 and 1 suspect: the feed had not brought a change written after it went dark in 1.5s")
		tr.dump(t)
	}
	ps[2].Hang(false)
}
