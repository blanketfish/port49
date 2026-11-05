package port49d

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/blanketfish/port49/internal/daemon/metrics"
	"github.com/blanketfish/port49/internal/store"
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

// A burst of logouts from the directory, larger than the runner's queue, is
// reached in full through the broker's own wiring (runBroker): the queue and
// its wake are made where the broker makes them, so a runner built without
// them fails here (Task 9 review I1).
func TestABurstOfDirectoryLogoutsPastTheQueueIsAllReachedByTheBroker(t *testing.T) {
	var out syncBuffer
	was, e := logoutQueueSize, stderr
	logoutQueueSize, stderr = 1, &out
	t.Cleanup(func() { logoutQueueSize, stderr = was, e })
	f := splitFleet(t)
	f.twoStores(t)
	f.judged(t)
	_, stop := startBroker(t, f.broker, &out, 1)
	defer stop()
	waitWithin(t, &out, "port49-broker: runner: took keyspace", 30*time.Second)
	waitWithin(t, &out, "mints open", 30*time.Second)
	ctx := context.Background()
	writer, _ := openBrokerFor(t, ctx, f.broker, metrics.New(prometheus.NewRegistry()), io.Discard)
	const n = 40
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l := store.Logout{Key: store.OIDCKey(store.OIDCSub, "https://idp.example", fmt.Sprintf("sub-%d", i)),
				At: time.Now(), Origin: fmt.Sprintf("origin-burst-%d", i)}
			if err := writer.dir.get().PutLogout(ctx, l, time.Hour); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	for i := 0; i < n; i++ {
		waitWithin(t, &out, fmt.Sprintf("a logout made elsewhere (origin-burst-%d) reached", i), 30*time.Second)
	}
	if !strings.Contains(out.String(), "the logout queue is full") {
		t.Fatal("the burst never found the queue full, so it proved nothing about the rescan")
	}
}
