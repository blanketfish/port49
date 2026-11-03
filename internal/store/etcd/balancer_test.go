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
			if seen[tr.last] {
				t.Fatalf("round %d: copy %d went to %s again", round, i+1, tr.last)
			}
			seen[tr.last] = true
		}
		if _, err := p.Pick(balancer.PickInfo{Ctx: ctx}); err != nil { // all used: begin again
			t.Fatal(err)
		}
	}
	// A stream reopened after a stall (keepLast) avoids the member it was on.
	tr := &tried{}
	ctx := withTriedSet(context.Background(), tr)
	p.Pick(balancer.PickInfo{Ctx: ctx})
	first := tr.last
	tr.keepLast()
	for i := 0; i < 6; i++ {
		tr.keepLast()
		p.Pick(balancer.PickInfo{Ctx: ctx})
		if tr.last == first {
			t.Fatalf("a reopened stream went back to %s", first)
		}
		first = tr.last
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
