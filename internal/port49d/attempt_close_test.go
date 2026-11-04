package port49d

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/blanketfish/port49/internal/config"
	"github.com/blanketfish/port49/internal/daemon/metrics"
	"github.com/blanketfish/port49/internal/store"
	etcdstore "github.com/blanketfish/port49/internal/store/etcd"
	"github.com/blanketfish/port49/internal/store/etcd/etcdtest"
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
func TestAnAttemptAgainstAStalledTLSListenerLeavesNothingRunning(t *testing.T) {
	cfgPath, _ := etcdSplit(t)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	// A half-dead etcd: the port accepts and the handshake never answers.
	// The test's own side of each connection ends when the client hangs up,
	// so every fd still open afterwards is the attempt's.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(io.Discard, c) // returns when the client closes
			}()
		}
	}()
	stalled := *cfg.Stores.Session.Etcd
	stalled.Endpoints = []string{"https://" + ln.Addr().String()}
	stalled.CallTimeout = 50 * time.Millisecond
	cfg.Stores.Session.Etcd = &stalled
	budget := 4*stalled.CallTimeout + 500*time.Millisecond
	m := metrics.New(prometheus.NewRegistry())
	try := func() {
		start := time.Now()
		s, err := attempt(context.Background(), cfg, sessionRef(cfg), m, io.Discard, true)
		if err == nil {
			s.Close()
			t.Fatal("an attempt against a listener that never completes TLS succeeded")
		}
		if !errors.Is(err, store.ErrUnavailable) {
			t.Fatalf("attempt error = %v, want store.ErrUnavailable", err)
		}
		if d := time.Since(start); d > budget {
			t.Fatalf("an attempt took %s, over its %s budget", d, budget)
		}
	}
	fds := func() int {
		es, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Skipf("no /proc/self/fd: %v", err)
		}
		return len(es)
	}
	settle := func() (int, int) {
		for i := 0; i < 20; i++ {
			runtime.GC()
			time.Sleep(20 * time.Millisecond)
		}
		return runtime.NumGoroutine(), fds()
	}
	for i := 0; i < 3; i++ {
		try()
	}
	gBefore, fBefore := settle()
	const attempts = 40
	for i := 0; i < attempts; i++ {
		try()
	}
	gAfter, fAfter := settle()
	t.Logf("goroutines %d -> %d, fds %d -> %d over %d attempts", gBefore, gAfter, fBefore, fAfter, attempts)
	if gAfter > gBefore+5 {
		t.Fatalf("goroutines %d before, %d after %d attempts on a stalled listener", gBefore, gAfter, attempts)
	}
	if fAfter > fBefore+5 {
		t.Fatalf("open fds %d before, %d after %d attempts on a stalled listener", fBefore, fAfter, attempts)
	}
}

// The probe's own connection, once the handshake has completed, is closed:
// an attempt a second for a night is otherwise a descriptor a second.
func TestProbeTLSLeavesNoConnectionOpen(t *testing.T) {
	srv := etcdtest.Start(t, etcdtest.Options{TLS: true})
	tc := srv.TLS(t, "port49-daemon")
	fds := func() int {
		es, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Skipf("no /proc/self/fd: %v", err)
		}
		return len(es)
	}
	probe := func() {
		if err := probeTLS(context.Background(), "stores.directory.etcd", []string{srv.Endpoint}, tc, time.Second); err != nil {
			t.Fatal(err)
		}
	}
	probe()
	time.Sleep(200 * time.Millisecond)
	before := fds()
	for i := 0; i < 50; i++ {
		probe()
	}
	time.Sleep(200 * time.Millisecond)
	if after := fds(); after > before+5 {
		t.Fatalf("open fds %d before, %d after 50 probes", before, after)
	}
}
