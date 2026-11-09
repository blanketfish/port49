package etcd

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/balancer"
	"google.golang.org/grpc/balancer/endpointsharding"
	"google.golang.org/grpc/balancer/pickfirst"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/status"
)

// balancerName is the load-balancing policy the client dials with: round-robin
// over the ready connections, except that the copies of one hedged call
// (hedgeReads) are placed on connections none of its earlier copies used.
//
// gRPC's round_robin shares one rotation among every call on the client. A
// hedged call's copies are sent 100s of ms apart, and calls from other
// goroutines move the rotation between them, so with one member dark all of a
// call's copies could land on it (8 to 10 percent of reads with four callers,
// internal/store/etcd hedge_concurrent_test.go).
const balancerName = "port49_hedge_rr"

// hedgeDialOptions are the dial options that put the policy in force. The
// resolver's own service config (round_robin) is ignored for the default.
var hedgeDialOptions = []grpc.DialOption{
	grpc.WithDisableServiceConfig(),
	grpc.WithDefaultServiceConfig(`{"loadBalancingPolicy":"` + balancerName + `"}`),
}

func init() {
	balancer.Register(hedgeBuilder{})
}

// triedKey carries a *tried through a hedged call's copies.
type triedKey struct{}

// tried is the members (by address) a hedged call's copies, or a long-lived
// stream's openings, have been placed on.
type tried struct {
	mu   sync.Mutex
	used map[string]bool
	// peer is another tried whose latest member this one also avoids: the
	// two legs of a watch (twoleg.go) sit on different members.
	peer atomic.Pointer[tried]
	last atomic.Value // string: the member the latest pick chose
	// pickedAt is when that pick chose it (unix nanoseconds, 0 before any): a
	// pick can wait for a connection, and the leg's stall is measured from
	// the placement, not from the wait's start (twoleg.go).
	pickedAt atomic.Int64
	// pair is held by each of a watch's two legs while it decides its member
	// (placed), so both see the other's choice: blocked picks run again
	// together on one picker. Shared by the pair, nil for a hedged call.
	pair atomic.Pointer[sync.Mutex]
	// hedged marks the copies of a hedged call (withTried): a copy of it
	// cancelled after waiting is a suspect member. A leg of a watch, ended by
	// the watch itself, is not.
	hedged bool
}

// place records addr as the member the latest pick chose, and when. The time
// is stored first: a member seen is a time seen.
func (t *tried) place(addr string) {
	t.pickedAt.Store(time.Now().UnixNano())
	t.last.Store(addr)
}

// lastMember is the member the latest pick chose, "" before any.
func (t *tried) lastMember() string {
	s, _ := t.last.Load().(string)
	return s
}

// withTried marks ctx as one hedged call's: its copies are placed apart.
func withTried(ctx context.Context) context.Context {
	return context.WithValue(ctx, triedKey{}, &tried{used: map[string]bool{}, hedged: true})
}

// withTriedSet places ctx's calls apart by t, which outlives them: a
// long-lived stream that is opened again after it stalls avoids the members
// it has just been on.
func withTriedSet(ctx context.Context, t *tried) context.Context {
	return context.WithValue(ctx, triedKey{}, t)
}

// hedgeBuilder is round_robin (gRPC's endpointsharding over pick_first
// children) with its picker replaced.
type hedgeBuilder struct{}

func (hedgeBuilder) Name() string { return balancerName }

func (hedgeBuilder) Build(cc balancer.ClientConn, opts balancer.BuildOptions) balancer.Balancer {
	return &hedgeBalancer{Balancer: endpointsharding.NewBalancer(&hedgeCC{ClientConn: cc}, opts,
		balancer.Get(pickfirst.Name).Build, endpointsharding.Options{})}
}

type hedgeBalancer struct{ balancer.Balancer }

func (b *hedgeBalancer) UpdateClientConnState(ccs balancer.ClientConnState) error {
	return b.Balancer.UpdateClientConnState(balancer.ClientConnState{
		ResolverState: pickfirst.EnableHealthListener(ccs.ResolverState),
	})
}

// hedgeCC replaces the picker endpointsharding hands the channel with one that
// places a hedged call's copies apart.
type hedgeCC struct {
	balancer.ClientConn
	next atomic.Uint32
	sus  suspects
}

func (c *hedgeCC) UpdateState(s balancer.State) {
	if kids := endpointsharding.ChildStatesFromPicker(s.Picker); len(kids) > 0 {
		var ready []endpointsharding.ChildState
		pending := 0
		for _, k := range kids {
			switch st := k.State.ConnectivityState; {
			case st == connectivity.Ready && len(k.Endpoint.Addresses) > 0:
				ready = append(ready, k)
			case st == connectivity.Connecting || st == connectivity.Idle:
				pending++
			}
		}
		if len(ready) > 0 {
			s.Picker = &picker{ready: ready, pending: pending, next: &c.next, sus: &c.sus}
			placingPickers.Add(1)
		}
	}
	c.ClientConn.UpdateState(s)
}

// placingPickers counts the pickers installed, for the test that fails loudly
// if a grpc upgrade stops them being.
var placingPickers atomic.Int64

// A member is suspect for suspectFor after a call on it hit its deadline, or a
// hedged copy on it was cancelled after waiting suspectAfter (another copy
// had answered): its connection is up and its answers are not coming, and
// stays so until keepalive fails it, 10 to 12 s on, or until a call on it
// succeeds. The picker skips a suspect member unless that would leave none, so
// a call that is not re-sent (a mint, a lease call) does not keep landing on
// it, one call in three, for those seconds.
const (
	suspectFor   = 15 * time.Second
	suspectAfter = 100 * time.Millisecond
)

// suspects is the channel's suspect members, by address, and when each is
// forgiven.
type suspects struct {
	mu    sync.Mutex
	until map[string]time.Time
}

func (s *suspects) is(addr string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return now.Before(s.until[addr])
}

// forgive ends addr's suspicion: it answered.
func (s *suspects) forgive(addr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.until, addr)
}

// mark reports whether addr was not already suspect.
func (s *suspects) mark(addr string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.until == nil {
		s.until = map[string]time.Time{}
	}
	fresh := !now.Before(s.until[addr])
	s.until[addr] = now.Add(suspectFor)
	return fresh
}

// onSuspect is told each time a member becomes suspect
// (port49_store_member_suspect_total). It is the process's: stores opened in
// one process share the last one set.
var onSuspect atomic.Pointer[func()]

type picker struct {
	ready []endpointsharding.ChildState
	// pending is how many of the channel's other members are connecting, or
	// idle and about to: not ready yet, and not failed. A leg waits for one
	// rather than share its peer's member (placed).
	pending int
	next    *atomic.Uint32 // the rotation, kept across the pickers of one channel
	sus     *suspects
	now     func() time.Time
}

func (p *picker) clock() time.Time {
	if p.now != nil {
		return p.now()
	}
	return time.Now()
}

func (p *picker) Pick(info balancer.PickInfo) (balancer.PickResult, error) {
	now := p.clock()
	cands := p.ready
	if p.sus != nil {
		cands = make([]endpointsharding.ChildState, 0, len(p.ready))
		for _, k := range p.ready {
			if !p.sus.is(k.Endpoint.Addresses[0].Addr, now) {
				cands = append(cands, k)
			}
		}
		if len(cands) == 0 {
			cands = p.ready // every member suspect: no better choice
		}
	}
	n := len(cands)
	start := int(p.next.Add(1) % uint32(n))
	t, _ := info.Ctx.Value(triedKey{}).(*tried)
	k := cands[start]
	if t != nil {
		var ok bool
		if k, ok = p.placed(cands, start, t); !ok {
			// gRPC holds the call and picks again with the channel's next
			// picker: once a member connecting now is ready, or has failed.
			return balancer.PickResult{}, balancer.ErrNoSubConnAvailable
		}
	}
	res, err := k.State.Picker.Pick(info)
	if err != nil || p.sus == nil {
		return res, err
	}
	addr, hedgedCopy, t0, inner := k.Endpoint.Addresses[0].Addr, t != nil && t.hedged, now, res.Done
	res.Done = func(di balancer.DoneInfo) {
		if inner != nil {
			inner(di)
		}
		if di.Err == nil {
			// It answered: during an election every member is suspect, and the
			// ones that come back must not stay skipped (or the one still hung
			// keeps a call in three) until the marks expire.
			p.sus.forgive(addr)
			return
		}
		waited := p.clock().Sub(t0)
		switch status.Code(di.Err) {
		case codes.DeadlineExceeded:
		case codes.Canceled:
			if !hedgedCopy {
				return
			}
		default:
			return
		}
		if waited >= suspectAfter && p.sus.mark(addr, p.clock()) {
			if f := onSuspect.Load(); f != nil {
				(*f)()
			}
		}
	}
	return res, nil
}

// placed is the member among cands for a call with a tried-set: the first
// from start that no earlier copy (or peer) has used, and false when the
// call is to wait. Only a leg of a watch waits, and only when its peer's
// member is the one ready and another member is still connecting: two legs
// on one member go dark together (#64, CI 42563304174). With every other
// member failed the legs share it, and watchLegs moves one apart once
// another is ready (twoleg.go).
func (p *picker) placed(cands []endpointsharding.ChildState, start int, t *tried) (endpointsharding.ChildState, bool) {
	n := len(cands)
	// The two legs of a watch decide in turn: each must see the other's
	// placement. Nothing below blocks, so the pair's lock is held only for the
	// decision, which includes recording the member.
	if pm := t.pair.Load(); pm != nil {
		pm.Lock()
		defer pm.Unlock()
	}
	avoid := ""
	if peer := t.peer.Load(); peer != nil {
		avoid = peer.lastMember()
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.used == nil {
		t.used = map[string]bool{}
	}
	for j := 0; j < n; j++ {
		k := cands[(start+j)%n]
		if addr := k.Endpoint.Addresses[0].Addr; !t.used[addr] && addr != avoid {
			t.used[addr] = true
			t.place(addr)
			return k, true
		}
	}
	// No candidate is free of the other leg and of this one's earlier members:
	// suspect members were left out of cands, but two legs on one member go
	// dark together, so a suspect member (it may have come back) is better than
	// the peer's.
	if avoid != "" {
		for _, k := range p.ready {
			if addr := k.Endpoint.Addresses[0].Addr; !t.used[addr] && addr != avoid {
				t.used[addr] = true
				t.place(addr)
				return k, true
			}
		}
		for _, k := range p.ready {
			if addr := k.Endpoint.Addresses[0].Addr; addr != avoid {
				t.place(addr)
				t.used = map[string]bool{addr: true}
				return k, true
			}
		}
	}
	// Here every ready member is the peer's (the loops above take any other).
	if avoid != "" && p.pending > 0 {
		return endpointsharding.ChildState{}, false
	}
	// Every candidate has had a copy: begin again.
	k := cands[start]
	addr := k.Endpoint.Addresses[0].Addr
	t.place(addr)
	t.used = map[string]bool{addr: true}
	return k, true
}
