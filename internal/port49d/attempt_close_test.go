package port49d

import (
	"context"
	"io"
	"runtime"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/blanketfish/port49/internal/config"
	"github.com/blanketfish/port49/internal/daemon/metrics"
	etcdstore "github.com/blanketfish/port49/internal/store/etcd"
)

// An attempt that fails after it has opened the store's clients (here at the
// version floor, after the TLS probe, the clients and the ping) closes them:
// with the wait for the store making an attempt a second, a leak per attempt
// is thousands of goroutines and connections in an outage.
func TestAFailedAttemptClosesTheClientsItOpened(t *testing.T) {
	was := endpointVersions
	t.Cleanup(func() { endpointVersions = was })
	endpointVersions = func(s *etcdstore.Store, ctx context.Context, eps []string, per time.Duration) []etcdstore.EndpointVersion {
		vs := was(s, ctx, eps, per)
		for i := range vs {
			vs[i].Version, vs[i].Err = "3.5.2", nil // below the floor
		}
		return vs
	}
	cfgPath, _ := etcdSplit(t)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	m := metrics.New(prometheus.NewRegistry())
	try := func() {
		s, err := attempt(context.Background(), cfg, sessionRef(cfg), m, io.Discard, true)
		if err == nil {
			s.Close()
			t.Fatal("an attempt against a member below the floor succeeded")
		}
	}
	for i := 0; i < 5; i++ { // warm: pools and the runtime's own goroutines settle
		try()
	}
	settle := func() int {
		for i := 0; i < 20; i++ {
			runtime.GC()
			time.Sleep(20 * time.Millisecond)
		}
		return runtime.NumGoroutine()
	}
	before := settle()
	const attempts = 60
	for i := 0; i < attempts; i++ {
		try()
	}
	if after := settle(); after > before+10 {
		t.Fatalf("goroutines %d before, %d after %d failed attempts", before, after, attempts)
	}
}

// An attempt against an endpoint that answers nothing fails at the TLS probe,
// before any client is opened: a few hundred of them leave nothing running.
func TestAnAttemptAgainstADeadEndpointLeavesNothingRunning(t *testing.T) {
	cfgPath, _ := etcdSplit(t)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	dead := *cfg.Stores.Session.Etcd
	dead.Endpoints = []string{"https://127.0.0.1:1"}
	cfg.Stores.Session.Etcd = &dead
	m := metrics.New(prometheus.NewRegistry())
	try := func() {
		if s, err := attempt(context.Background(), cfg, sessionRef(cfg), m, io.Discard, true); err == nil {
			s.Close()
			t.Fatal("an attempt against a dead endpoint succeeded")
		}
	}
	for i := 0; i < 5; i++ {
		try()
	}
	settle := func() int {
		for i := 0; i < 20; i++ {
			runtime.GC()
			time.Sleep(20 * time.Millisecond)
		}
		return runtime.NumGoroutine()
	}
	before := settle()
	for i := 0; i < 300; i++ {
		try()
	}
	if after := settle(); after > before+10 {
		t.Fatalf("goroutines %d before, %d after 300 attempts on a dead endpoint", before, after)
	}
}
