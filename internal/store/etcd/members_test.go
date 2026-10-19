package etcd

import (
	"context"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
)

// Members counts the members etcd lists and those answering at their
// client URL (R21): 3/3, then 2/3 with one stopped.
func TestMembersCountsTheAnswering(t *testing.T) {
	c := etcdtest.StartCluster(t)
	s, err := Open(Config{Endpoints: c.Endpoints, Prefix: etcdtest.Prefix()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	ctx := context.Background()
	if a, l, err := s.Members(ctx, 2*time.Second); err != nil || a != 3 || l != 3 {
		t.Fatalf("%d/%d %v", a, l, err)
	}
	c.Stop(2)
	deadline := time.Now().Add(15 * time.Second)
	for {
		a, l, err := s.Members(ctx, 500*time.Millisecond)
		if err == nil && a == 2 && l == 3 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d/%d %v with one of three stopped", a, l, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// With the quorum lost the count still answers: one of three, not an error
// (R21; the review's I1), and in about one timeout, not one per member.
func TestMembersWithTheQuorumLost(t *testing.T) {
	c := etcdtest.StartCluster(t)
	s, err := Open(Config{Endpoints: c.Endpoints, Prefix: etcdtest.Prefix()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	c.Stop(1)
	c.Stop(2)
	deadline := time.Now().Add(20 * time.Second)
	for {
		start := time.Now()
		cctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		a, l, err := s.Members(cctx, time.Second)
		cancel()
		if err == nil && a == 1 && l == 3 {
			if took := time.Since(start); took > 1700*time.Millisecond {
				t.Fatalf("the count took %v, one timeout of 1s expected", took)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d/%d %v with two of three stopped", a, l, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
