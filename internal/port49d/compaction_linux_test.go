package port49d

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/store"
)

// The broker start's marks and logouts loads go through pagedLoad: a
// compaction in front of each is read again and the broker starts
// (pre-flight I11). The logouts are loaded on two stores only.
func TestTheBrokerStartRetriesACompactionInItsMarksAndLogouts(t *testing.T) {
	was, wasWait := pagedLoadFault, startRetryWait
	t.Cleanup(func() { pagedLoadFault, startRetryWait = was, wasWait })
	startRetryWait = time.Millisecond
	var mu sync.Mutex
	hit := map[string]int{}
	pagedLoadFault = func(name string) error {
		mu.Lock()
		defer mu.Unlock()
		if hit[name]++; hit[name] == 1 && (name == "marks" || name == "logouts") {
			return store.ErrCompacted
		}
		return nil
	}
	f := splitFleet(t)
	f.twoStores(t)
	var out syncBuffer
	openBrokerFor(t, context.Background(), f.broker, metrics.New(prometheus.NewRegistry()), &out)
	mu.Lock()
	defer mu.Unlock()
	if hit["marks"] != 2 || hit["logouts"] != 2 || hit["ledger"] != 1 {
		t.Fatalf("marks %d, logouts %d, ledger %d tries; want 2, 2, 1\n%s", hit["marks"], hit["logouts"], hit["ledger"],
			out.String())
	}
}

// A logout recorded in the directory is never lost to a compaction: the
// directory is compacted after the write, a start's logouts load meets a
// compaction, reads again, and the logout is in the broker's set.
func TestALogoutIsNotLostAcrossACompaction(t *testing.T) {
	was, wasWait := pagedLoadFault, startRetryWait
	t.Cleanup(func() { pagedLoadFault, startRetryWait = was, wasWait })
	startRetryWait = time.Millisecond
	f := splitFleet(t)
	f.twoStores(t)
	ctx := context.Background()
	m := metrics.New(prometheus.NewRegistry())
	first, _ := openBrokerFor(t, ctx, f.broker, m, io.Discard)
	key := store.OIDCKey(store.OIDCSub, "https://idp.example", "sub-alice")
	if err := first.dir.get().PutLogout(ctx, store.Logout{Key: key, At: time.Now(), Origin: "origin-alice"},
		time.Hour); err != nil {
		t.Fatal(err)
	}
	root := f.dsrv.Client(t, "root")
	resp, err := root.Get(ctx, "/port49/", clientv3.WithCountOnly())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := root.Compact(ctx, resp.Header.Revision); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	hit := 0
	pagedLoadFault = func(name string) error {
		mu.Lock()
		defer mu.Unlock()
		if name == "logouts" {
			if hit++; hit == 1 {
				return store.ErrCompacted
			}
		}
		return nil
	}
	second, _ := openBrokerFor(t, ctx, f.broker, m, io.Discard)
	mu.Lock()
	tries := hit
	mu.Unlock()
	if _, ok := second.logouts.Get(key); !ok || tries != 2 {
		t.Fatalf("the logout is in the set: %v, after %d tries", ok, tries)
	}
}
