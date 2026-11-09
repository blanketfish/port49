package etcd

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/balancer"
	"google.golang.org/grpc/balancer/endpointsharding"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/status"
)

type okPicker struct{ addr string }

func (p okPicker) Pick(balancer.PickInfo) (balancer.PickResult, error) {
	return balancer.PickResult{Metadata: metadata.Pairs("addr", p.addr)}, nil
}

func readyPicker(addrs ...string) *picker {
	p := &picker{next: new(atomic.Uint32)}
	for _, a := range addrs {
		p.ready = append(p.ready, endpointsharding.ChildState{
			Endpoint: resolver.Endpoint{Addresses: []resolver.Address{{Addr: a}}},
			State:    balancer.State{ConnectivityState: connectivity.Ready, Picker: okPicker{a}},
		})
	}
	return p
}

// The copies of one hedged call land on three different members, and a
// fourth begins the round again; a call with no tried-set takes the rotation.
func TestAHedgedCallsCopiesAreEachPlacedOnAMemberNotYetUsed(t *testing.T) {
	p := readyPicker("a", "b", "c")
	for round := 0; round < 5; round++ {
		ctx := withTried(context.Background())
		seen := map[string]bool{}
		for i := 0; i < 3; i++ {
			if _, err := p.Pick(balancer.PickInfo{Ctx: ctx}); err != nil {
				t.Fatal(err)
			}
			tr := ctx.Value(triedKey{}).(*tried)
			if seen[tr.lastMember()] {
				t.Fatalf("round %d: copy %d went to %s again", round, i+1, tr.lastMember())
			}
			seen[tr.lastMember()] = true
		}
		if _, err := p.Pick(balancer.PickInfo{Ctx: ctx}); err != nil { // all used: begin again
			t.Fatal(err)
		}
	}
	// The legs of a watch avoid each other's member, and a leg reopened avoids
	// the member it was on.
	a, b := &tried{}, &tried{}
	a.peer.Store(b)
	b.peer.Store(a)
	ca, cb := withTriedSet(context.Background(), a), withTriedSet(context.Background(), b)
	for i := 0; i < 12; i++ {
		p.Pick(balancer.PickInfo{Ctx: ca})
		p.Pick(balancer.PickInfo{Ctx: cb})
		if a.lastMember() == b.lastMember() {
			t.Fatalf("both legs went to %s", a.lastMember())
		}
		a.used, b.used = nil, nil
	}
	was := a.lastMember()
	re := &tried{used: map[string]bool{was: true}}
	re.peer.Store(b)
	for i := 0; i < 6; i++ {
		p.Pick(balancer.PickInfo{Ctx: withTriedSet(context.Background(), re)})
		if m := re.lastMember(); m == was || m == b.lastMember() {
			t.Fatalf("a leg reopened went to %s (was on %s, the other on %s)", m, was, b.lastMember())
		}
		re.used = map[string]bool{was: true}
	}
}

// The channel's picker is ours once a connection is ready. Were a grpc
// release to change what endpointsharding hands UpdateState so that
// ChildStatesFromPicker came back empty, UpdateState would quietly leave
// plain round-robin in place and the hedged copies would share one rotation
// again; this fails then instead.
func TestTheChannelsPickerIsThePlacingOneOnceAConnectionIsUp(t *testing.T) {
	s, _, _ := threeBehindProxies(t)
	if err := s.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := placingPickers.Load(); n == 0 {
		t.Fatal("the balancer never installed its picker: endpointsharding's child states were not read (a grpc upgrade?)")
	}
}

func clocked(p *picker, now *time.Time) *picker {
	p.now = func() time.Time { return *now }
	p.sus = &suspects{}
	return p
}

func pick(t *testing.T, p *picker, ctx context.Context) (string, func(balancer.DoneInfo)) {
	t.Helper()
	res, err := p.Pick(balancer.PickInfo{Ctx: ctx})
	if err != nil {
		t.Fatal(err)
	}
	return res.Metadata.Get("addr")[0], res.Done
}

func picksOver(t *testing.T, p *picker, n int) map[string]int {
	t.Helper()
	seen := map[string]int{}
	for i := 0; i < n; i++ {
		a, _ := pick(t, p, context.Background())
		seen[a]++
	}
	return seen
}

// A member whose call hit its deadline is skipped for suspectFor and chosen
// again after; a hedged copy cancelled after waiting suspectAfter is the same,
// but one cancelled at once is not, nor is a call that was not hedged.
func TestASuspectMemberIsSkippedUntilForgiven(t *testing.T) {
	now := time.Unix(1000, 0)
	p := clocked(readyPicker("a", "b", "c"), &now)
	var marks int
	f := func() { marks++ }
	onSuspect.Store(&f)
	defer onSuspect.Store(nil)

	hedged := withTried(context.Background())
	deadline := status.Error(codes.DeadlineExceeded, "")
	canceled := status.Error(codes.Canceled, "")

	// a cancelled hedged copy, at once: nothing
	_, done := pick(t, p, hedged)
	done(balancer.DoneInfo{Err: canceled})
	// a plain call cancelled after a long wait: nothing (the caller gave up)
	_, done = pick(t, p, context.Background())
	now = now.Add(time.Second)
	done(balancer.DoneInfo{Err: canceled})
	if marks != 0 || len(picksOver(t, p, 30)) != 3 {
		t.Fatalf("a member became suspect on a cancel that says nothing (%d marks)", marks)
	}

	// a deadline after 500 ms on whichever member was picked
	addr, done := pick(t, p, context.Background())
	now = now.Add(500 * time.Millisecond)
	done(balancer.DoneInfo{Err: deadline})
	if marks != 1 {
		t.Fatalf("a deadline did not make %s suspect (%d marks)", addr, marks)
	}
	if got := picksOver(t, p, 30); got[addr] != 0 || len(got) != 2 {
		t.Fatalf("picks after %s went suspect: %v", addr, got)
	}
	// still suspect just before it is forgiven, chosen again after
	now = now.Add(suspectFor - 600*time.Millisecond)
	if got := picksOver(t, p, 30); got[addr] != 0 {
		t.Fatalf("%s chosen before it was forgiven: %v", addr, got)
	}
	now = now.Add(time.Second)
	if got := picksOver(t, p, 30); got[addr] == 0 {
		t.Fatalf("%s not chosen after it was forgiven: %v", addr, got)
	}

	// a hedged copy cancelled after suspectAfter makes its member suspect
	addr, done = pick(t, p, hedged)
	now = now.Add(suspectAfter)
	done(balancer.DoneInfo{Err: canceled})
	if marks != 2 {
		t.Fatalf("a hedged copy cancelled after waiting did not make %s suspect (%d marks)", addr, marks)
	}
}

// With every member suspect there is no better choice: all are used. A single
// endpoint is never skipped.
func TestWhenEveryMemberIsSuspectAllAreUsed(t *testing.T) {
	now := time.Unix(1000, 0)
	for _, addrs := range [][]string{{"a", "b", "c"}, {"a"}} {
		p := clocked(readyPicker(addrs...), &now)
		for _, a := range addrs {
			p.sus.mark(a, now)
		}
		if got := picksOver(t, p, 30); len(got) != len(addrs) {
			t.Fatalf("%v all suspect: picks %v", addrs, got)
		}
	}
}

// During an election every member is suspect, and the picker falls back to all
// of them. The members that then answer are forgiven on their first success;
// the one still hung stays skipped, instead of keeping one call in three until
// its mark expires (the leader_dark tail, 17.5 s).
func TestAMemberThatAnswersIsForgivenAndTheHungOneStaysSkipped(t *testing.T) {
	now := time.Unix(1000, 0)
	p := clocked(readyPicker("a", "b", "c"), &now)
	deadline := status.Error(codes.DeadlineExceeded, "")
	for _, a := range []string{"a", "b", "c"} { // all three time out: an election
		p.sus.mark(a, now)
	}
	if got := picksOver(t, p, 30); len(got) != 3 {
		t.Fatalf("with every member suspect all are used: %v", got)
	}
	// a and b answer (the first to be picked is forgiven and then takes the
	// calls; the other stays suspect until it is picked again or its mark
	// expires); c is still hung (its calls time out)
	for i := 0; i < 60; i++ {
		addr, done := pick(t, p, context.Background())
		if addr == "c" {
			now = now.Add(500 * time.Millisecond)
			done(balancer.DoneInfo{Err: deadline})
			continue
		}
		done(balancer.DoneInfo{})
	}
	if got := picksOver(t, p, 60); got["c"] != 0 || got["a"]+got["b"] != 60 {
		t.Fatalf("after a and b answered: %v, want c skipped and every call on a or b", got)
	}
}

// The two legs of a watch sit on different members even when the others are
// suspect: with two members recently timed out, the second leg goes to one of
// them rather than to the member the first is on, or one member going dark
// stalls both legs (TestTheMarksFeedFollowsWhicheverMemberGoesDark, CI).
func TestTheSecondLegIsNotPlacedOnTheFirstsMemberWhenTheOthersAreSuspect(t *testing.T) {
	now := time.Unix(1000, 0)
	p := clocked(readyPicker("a", "b", "c"), &now)
	p.sus.mark("a", now)
	p.sus.mark("b", now)
	first := &tried{used: map[string]bool{}}
	first.last.Store("c")
	second := &tried{used: map[string]bool{}}
	second.peer.Store(first)
	for i := 0; i < 20; i++ {
		if addr, _ := pick(t, p, withTriedSet(context.Background(), second)); addr == "c" {
			t.Fatalf("pick %d put the second leg on the first leg's member", i)
		}
	}
}

// While another member is still connecting, the second leg does not take the
// first's member: its pick waits, and gRPC picks again with the next picker,
// once that member is ready or has failed (#64). A leg with nothing to
// avoid, a hedged copy and a plain call still take the ready member.
func TestTheSecondLegWaitsForAMemberStillConnectingRatherThanShare(t *testing.T) {
	p := readyPicker("a")
	p.pending = 1
	first := &tried{used: map[string]bool{}}
	first.last.Store("a")
	second := &tried{used: map[string]bool{}}
	second.peer.Store(first)
	if _, err := p.Pick(balancer.PickInfo{Ctx: withTriedSet(context.Background(), second)}); err != balancer.ErrNoSubConnAvailable {
		t.Fatalf("the second leg's pick returned %v with another member connecting, want ErrNoSubConnAvailable", err)
	}
	if m := second.lastMember(); m != "" {
		t.Fatalf("a pick that waits recorded member %q", m)
	}
	for name, ctx := range map[string]context.Context{
		"a leg with no peer": withTriedSet(context.Background(), &tried{used: map[string]bool{}}),
		"a hedged copy":      withTried(context.Background()),
		"a plain call":       context.Background(),
	} {
		if addr, _ := pick(t, p, ctx); addr != "a" {
			t.Fatalf("%s was placed on %q, want a", name, addr)
		}
	}
}

// fakeChild is a child balancer whose connectivity the test sets.
type fakeChild struct {
	cc   balancer.ClientConn
	addr string // its endpoint's address, learnt at its first update
}

func (c *fakeChild) UpdateClientConnState(s balancer.ClientConnState) error {
	c.addr = s.ResolverState.Endpoints[0].Addresses[0].Addr
	return nil
}
func (*fakeChild) ResolverError(error)                                        {}
func (*fakeChild) UpdateSubConnState(balancer.SubConn, balancer.SubConnState) {}
func (*fakeChild) Close()                                                     {}
func (*fakeChild) ExitIdle()                                                  {}

// latestPicker is the ClientConn the hedge balancer reports to: it keeps the
// newest picker, as the channel does.
type latestPicker struct {
	balancer.ClientConn
	p atomic.Pointer[balancer.Picker]
}

func (l *latestPicker) UpdateState(s balancer.State) { l.p.Store(&s.Picker) }

// members builds the real hedge balancer (endpointsharding under hedgeCC) over
// children the test drives: set moves a member to a connectivity state, which
// publishes a new picker through hedgeCC.UpdateState as a channel's would.
func members(t *testing.T, addrs ...string) (set func(addr string, st connectivity.State), pickerNow func() balancer.Picker) {
	t.Helper()
	cur := &latestPicker{}
	var eps []resolver.Endpoint
	for _, a := range addrs {
		eps = append(eps, resolver.Endpoint{Addresses: []resolver.Address{{Addr: a}}})
	}
	var built []*fakeChild
	b := endpointsharding.NewBalancer(&hedgeCC{ClientConn: cur}, balancer.BuildOptions{},
		func(cc balancer.ClientConn, _ balancer.BuildOptions) balancer.Balancer {
			c := &fakeChild{cc: cc}
			built = append(built, c)
			return c
		}, endpointsharding.Options{})
	t.Cleanup(b.Close)
	if err := b.UpdateClientConnState(balancer.ClientConnState{ResolverState: resolver.State{Endpoints: eps}}); err != nil {
		t.Fatal(err)
	}
	if len(built) != len(addrs) {
		t.Fatalf("%d children built for %d endpoints", len(built), len(addrs))
	}
	// endpointsharding rotates the endpoints it builds in: tell the children
	// apart by the address each is given at its first update.
	byAddr := map[string]*fakeChild{}
	for _, c := range built {
		byAddr[c.addr] = c
	}
	return func(addr string, st connectivity.State) {
			c := byAddr[addr]
			if c == nil {
				t.Fatalf("no child for %q", addr)
			}
			c.cc.UpdateState(balancer.State{ConnectivityState: st, Picker: okPicker{addr}})
		}, func() balancer.Picker {
			p := cur.p.Load()
			if p == nil {
				t.Fatal("the balancer published no picker")
			}
			return *p
		}
}

// A failed member is not one to wait for. The peer holds the only ready member
// and the others are refusing (TransientFailure): the second leg takes the
// peer's member at once, rather than wait for a member that may not come back
// for hours. Counting a failed member as pending would stall it (#64).
func TestTheSecondLegSharesWhenTheOtherMembersHaveFailed(t *testing.T) {
	set, now := members(t, "a", "b", "c")
	set("a", connectivity.Ready)
	set("b", connectivity.TransientFailure)
	set("c", connectivity.TransientFailure)
	first := &tried{used: map[string]bool{}}
	first.last.Store("a")
	second := &tried{used: map[string]bool{}}
	second.peer.Store(first)
	res, err := now().Pick(balancer.PickInfo{Ctx: withTriedSet(context.Background(), second)})
	if err != nil {
		t.Fatalf("the second leg's pick returned %v with every other member failed, want the peer's member", err)
	}
	if got := res.Metadata.Get("addr"); len(got) != 1 || got[0] != "a" {
		t.Fatalf("placed on %v, want a", got)
	}
}

// Members that are connecting are waited for, and once they have failed the
// leg no longer waits: the picker the failure publishes lets it share.
func TestTheSecondLegStopsWaitingOnceTheConnectingMembersHaveFailed(t *testing.T) {
	set, now := members(t, "a", "b", "c")
	set("a", connectivity.Ready)
	set("b", connectivity.Connecting)
	set("c", connectivity.Connecting)
	first := &tried{used: map[string]bool{}}
	first.last.Store("a")
	second := &tried{used: map[string]bool{}}
	second.peer.Store(first)
	info := balancer.PickInfo{Ctx: withTriedSet(context.Background(), second)}
	if _, err := now().Pick(info); err != balancer.ErrNoSubConnAvailable {
		t.Fatalf("with b and c connecting the pick returned %v, want ErrNoSubConnAvailable", err)
	}
	set("b", connectivity.TransientFailure)
	if _, err := now().Pick(info); err != balancer.ErrNoSubConnAvailable {
		t.Fatalf("with c still connecting the pick returned %v, want ErrNoSubConnAvailable", err)
	}
	set("c", connectivity.TransientFailure)
	res, err := now().Pick(info)
	if err != nil {
		t.Fatalf("with b and c failed the pick returned %v, want the peer's member", err)
	}
	if got := res.Metadata.Get("addr"); len(got) != 1 || got[0] != "a" {
		t.Fatalf("placed on %v, want a", got)
	}
}

// pairOf returns the two tried-sets of a watch's legs, as clientLegs.open
// makes them: peers of each other, sharing one placement lock.
func pairOf() (a, b *tried, pm *sync.Mutex) {
	a, b, pm = &tried{used: map[string]bool{}}, &tried{used: map[string]bool{}}, new(sync.Mutex)
	a.peer.Store(b)
	b.peer.Store(a)
	a.pair.Store(pm)
	b.pair.Store(pm)
	return a, b, pm
}

// The pair's legs place one at a time: a pick holds the pair's lock for its
// decision, so a peer's choice is never read before it is recorded.
func TestALegsPlacementTakesThePairsLock(t *testing.T) {
	p := readyPicker("a", "b")
	a, _, pm := pairOf()
	pm.Lock()
	done := make(chan struct{})
	go func() {
		p.Pick(balancer.PickInfo{Ctx: withTriedSet(context.Background(), a)})
		close(done)
	}()
	select {
	case <-done:
		pm.Unlock()
		t.Fatal("a leg was placed while the pair's lock was held by the other")
	case <-time.After(100 * time.Millisecond):
	}
	pm.Unlock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the pick did not finish once the pair's lock was let go")
	}
}

// Two blocked legs run again together on the one picker that has a member
// ready, with another member still connecting: exactly one takes it and the
// other waits, never both. Many rounds (the unlocked race showed 1.3% of them
// sharing), and meant for -race.
func TestTwoBlockedLegsRepickedTogetherNeverShareTheOneReadyMember(t *testing.T) {
	p := readyPicker("a")
	p.pending = 2
	for round := 0; round < 3000; round++ {
		a, b, _ := pairOf()
		var placed atomic.Int32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for _, tr := range []*tried{a, b} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if _, err := p.Pick(balancer.PickInfo{Ctx: withTriedSet(context.Background(), tr)}); err == nil {
					placed.Add(1)
				} else if err != balancer.ErrNoSubConnAvailable {
					t.Errorf("pick returned %v", err)
				}
			}()
		}
		close(start)
		wg.Wait()
		if n := placed.Load(); n != 1 {
			t.Fatalf("round %d: %d legs were placed on the one ready member with another connecting, want exactly 1", round, n)
		}
	}
}

// With one member ready and every other failed (none connecting) the second
// leg shares the first's: there is nothing to wait for, and watchLegs moves
// a leg apart once another member is ready.
func TestTheSecondLegSharesTheOnlyReadyMember(t *testing.T) {
	first := &tried{used: map[string]bool{}}
	first.last.Store("a")
	second := &tried{used: map[string]bool{}}
	second.peer.Store(first)
	addr, _ := pick(t, readyPicker("a"), withTriedSet(context.Background(), second))
	if addr != "a" {
		t.Fatalf("placed on %q, want the only member a", addr)
	}
}
