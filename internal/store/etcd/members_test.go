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
