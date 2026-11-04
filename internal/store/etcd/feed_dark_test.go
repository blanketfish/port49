package etcd

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/store"
)

// legTrace records, for a test that logs it only on a failure, where each leg
// of a watch was placed and reopened, when it delivered, and what the test
// noted (members hung, writes and their durations). It holds revisions and
// members, no keys or values.
type legTrace_ struct {
	begun time.Time
	mu    sync.Mutex
	lines []string
}

func traceLegs(t *testing.T) *legTrace_ {
	tr := &legTrace_{begun: time.Now()}
	hook := func(ev string, leg, gen int, detail string) {
		tr.note("leg %d opening %d: %s %s", leg, gen, ev, detail)
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

func (tr *legTrace_) dump(t *testing.T) {
	t.Helper()
	tr.mu.Lock()
	defer tr.mu.Unlock()
	t.Logf("placement and delivery since the test began:\n  %s", strings.Join(tr.lines, "\n  "))
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
