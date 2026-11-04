package etcd

import (
	"context"
	"sync/atomic"
	"testing"

	"google.golang.org/grpc/balancer"
	"google.golang.org/grpc/balancer/endpointsharding"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/resolver"
)

type okPicker struct{ addr string }

func (p okPicker) Pick(balancer.PickInfo) (balancer.PickResult, error) {
	return balancer.PickResult{}, nil
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
	a.peer, b.peer = b, a
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
	re := &tried{used: map[string]bool{was: true}, peer: b}
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
