package etcd

import (
	"context"
	"sync"
	"sync/atomic"

	"google.golang.org/grpc"
	"google.golang.org/grpc/balancer"
	"google.golang.org/grpc/balancer/endpointsharding"
	"google.golang.org/grpc/balancer/pickfirst"
	"google.golang.org/grpc/connectivity"
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

// tried is the members (by address) a hedged call's copies have been placed on.
type tried struct {
	mu   sync.Mutex
	used map[string]bool
	last string // the member the latest pick chose
}

// keepLast forgets every member but the latest pick: that one answered, so
// the next placement made with t goes elsewhere and the rest are fair game.
func (t *tried) keepLast() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.used = map[string]bool{t.last: t.last != ""}
}

// withTried marks ctx as one hedged call's: its copies are placed apart.
func withTried(ctx context.Context) context.Context {
	return context.WithValue(ctx, triedKey{}, &tried{used: map[string]bool{}})
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
}

func (c *hedgeCC) UpdateState(s balancer.State) {
	if kids := endpointsharding.ChildStatesFromPicker(s.Picker); len(kids) > 0 {
		var ready []endpointsharding.ChildState
		for _, k := range kids {
			if k.State.ConnectivityState == connectivity.Ready && len(k.Endpoint.Addresses) > 0 {
				ready = append(ready, k)
			}
		}
		if len(ready) > 0 {
			s.Picker = &picker{ready: ready, next: &c.next}
		}
	}
	c.ClientConn.UpdateState(s)
}

type picker struct {
	ready []endpointsharding.ChildState
	next  *atomic.Uint32 // the rotation, kept across the pickers of one channel
}

func (p *picker) Pick(info balancer.PickInfo) (balancer.PickResult, error) {
	n := len(p.ready)
	start := int(p.next.Add(1) % uint32(n))
	t, _ := info.Ctx.Value(triedKey{}).(*tried)
	if t == nil {
		return p.ready[start].State.Picker.Pick(info)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.used == nil {
		t.used = map[string]bool{}
	}
	for j := 0; j < n; j++ {
		k := p.ready[(start+j)%n]
		if addr := k.Endpoint.Addresses[0].Addr; !t.used[addr] {
			t.used[addr] = true
			t.last = addr
			return k.State.Picker.Pick(info)
		}
	}
	// Every ready member has had a copy: begin again.
	k := p.ready[start]
	t.last = k.Endpoint.Addresses[0].Addr
	t.used = map[string]bool{t.last: true}
	return k.State.Picker.Pick(info)
}
