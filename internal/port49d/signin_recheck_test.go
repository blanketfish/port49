package port49d

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/blanketfish/port49/internal/broker"
	"github.com/blanketfish/port49/internal/config"
	"github.com/blanketfish/port49/internal/daemon/metrics"
	"github.com/blanketfish/port49/internal/store"
	"github.com/blanketfish/port49/internal/store/crypt"
	"github.com/blanketfish/port49/internal/store/enrollfile"
	"github.com/blanketfish/port49/internal/store/memory"
)

// A replica that is not the runner leaves enrollment_store_lost by itself
// once the mark exists, however it was made, without a restart (D7): two
// brokers on one global enrollment store, both lost, the mark made through a
// third handle; both leave the state within one interval and the gauge reads 1.
func TestAReplicaLeavesTheLostStateWhenTheMarkAppears(t *testing.T) {
	old := broker.EnrollmentRecheckEvery
	broker.EnrollmentRecheckEvery = 20 * time.Millisecond
	t.Cleanup(func() { broker.EnrollmentRecheckEvery = old })

	cfg, _ := signInConfig(t, "127.0.0.1:0")
	es := &cfg.Broker.Directory.EnrollmentStore
	es.Backend, es.File = config.BackendEtcd, ""
	etcd := &config.EtcdConfig{Endpoints: []string{"https://etcd-0:2379"}, CallTimeout: time.Second, BulkTimeout: time.Second}
	etcd.Breaker.Failures = 5
	cfg.Stores.Session.Etcd, cfg.Stores.Directory.Etcd, cfg.Stores.Shared = etcd, etcd, true
	shared := memory.NewEnrollments(time.Now)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var ms []*metrics.Metrics
	var bs []interface{ EnrollmentStoreLost() string }
	for i := 0; i < 2; i++ {
		m := metrics.New(prometheus.NewRegistry())
		b := builtSignInBroker(t, cfg, m)
		b.Say = func(string, ...any) {}
		wireSignIn(ctx, cfg, b, signInTestKeys, m, func() store.Enrollments { return shared }, io.Discard)
		if b.EnrollmentStoreLost() == "" {
			t.Fatalf("replica %d is not lost before the mark", i)
		}
		if v := testutil.ToFloat64(m.DirectoryEnrollmentStoreOK); v != 0 {
			t.Fatalf("replica %d: gauge %v before the mark", i, v)
		}
		ms, bs = append(ms, m), append(bs, b)
	}
	mine := crypt.WrapEnrollments(shared, signInTestKeys, metrics.New(prometheus.NewRegistry()).CryptOpenFailures)
	if err := mine.CreateEnrollmentMark(ctx, store.EnrollmentMark{CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	for i, b := range bs {
		deadline := time.Now().Add(5 * time.Second)
		for b.EnrollmentStoreLost() != "" {
			if time.Now().After(deadline) {
				t.Fatalf("replica %d is still lost: %q", i, b.EnrollmentStoreLost())
			}
			time.Sleep(10 * time.Millisecond)
		}
		if v := testutil.ToFloat64(ms[i].DirectoryEnrollmentStoreOK); v != 1 {
			t.Fatalf("replica %d: gauge %v after the mark", i, v)
		}
	}
}

// downStore is a shared enrollment store that does not answer while down is set.
type downStore struct {
	store.Enrollments
	down atomic.Bool
}

func (d *downStore) GetEnrollmentMark(ctx context.Context) (store.EnrollmentMark, error) {
	if d.down.Load() {
		return store.EnrollmentMark{}, store.ErrUnavailable
	}
	return d.Enrollments.GetEnrollmentMark(ctx)
}

// A replica whose enrollment store did not answer at start is not lost, but it
// has no gauge either; it looks again by itself and the gauge appears once the
// store answers (N1), so an absent() alert clears without a restart.
func TestAReplicaWhoseStoreDidNotAnswerAtStartSetsTheGaugeWhenItDoes(t *testing.T) {
	old := broker.EnrollmentRecheckEvery
	broker.EnrollmentRecheckEvery = 20 * time.Millisecond
	t.Cleanup(func() { broker.EnrollmentRecheckEvery = old })

	cfg, _ := signInConfig(t, "127.0.0.1:0")
	es := &cfg.Broker.Directory.EnrollmentStore
	es.Backend, es.File = config.BackendEtcd, ""
	etcd := &config.EtcdConfig{Endpoints: []string{"https://etcd-0:2379"}, CallTimeout: time.Second, BulkTimeout: time.Second}
	etcd.Breaker.Failures = 5
	cfg.Stores.Session.Etcd, cfg.Stores.Directory.Etcd, cfg.Stores.Shared = etcd, etcd, true
	shared := &downStore{Enrollments: memory.NewEnrollments(time.Now)}
	shared.down.Store(true)
	mine := crypt.WrapEnrollments(shared.Enrollments, signInTestKeys, metrics.New(prometheus.NewRegistry()).CryptOpenFailures)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := mine.CreateEnrollmentMark(ctx, store.EnrollmentMark{CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	m := metrics.New(prometheus.NewRegistry())
	b := builtSignInBroker(t, cfg, m)
	b.Say = func(string, ...any) {}
	var out strings.Builder
	wireSignIn(ctx, cfg, b, signInTestKeys, m, func() store.Enrollments { return shared }, &out)
	if n := testutil.CollectAndCount(m.DirectoryEnrollmentStoreOK); n != 0 {
		t.Fatalf("the gauge has %d series before the store answered", n)
	}

	shared.down.Store(false)
	deadline := time.Now().Add(5 * time.Second)
	for testutil.CollectAndCount(m.DirectoryEnrollmentStoreOK) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the gauge never appeared after the store answered")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if v := testutil.ToFloat64(m.DirectoryEnrollmentStoreOK); v != 1 {
		t.Fatalf("gauge %v after the store answered with a mark", v)
	}
	if strings.Contains(out.String(), "scheduled pass") {
		t.Fatalf("the start line promises a scheduled pass: %q", out.String())
	}
}

// The recheck goroutine is joined: once ctx is cancelled, the channel the
// wiring returns closes after the loop and the store's closer have returned,
// so brokerd's wait group can hold the store open for them (N3).
func TestTheWiringsGoroutinesEndWithTheContext(t *testing.T) {
	cfg, _ := signInConfig(t, "127.0.0.1:0")
	m := metrics.New(prometheus.NewRegistry())
	b := builtSignInBroker(t, cfg, m)
	b.Say = func(string, ...any) {}
	ctx, cancel := context.WithCancel(context.Background())
	done := wireSignIn(ctx, cfg, b, signInTestKeys, m, nil, io.Discard)
	select {
	case <-done:
		t.Fatal("the goroutines ended before the context did")
	default:
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the goroutines did not end with the context")
	}
}

// A broker running on the sealed file, which found no file at start, leaves enrollment_store_lost
// within one interval of an offline init-enrollments, which another process runs: without a restart.
func TestARunningBrokerOnTheFileFollowsAnOfflineInit(t *testing.T) {
	old := broker.EnrollmentRecheckEvery
	broker.EnrollmentRecheckEvery = 20 * time.Millisecond
	t.Cleanup(func() { broker.EnrollmentRecheckEvery = old })

	cfg, file := signInConfig(t, "127.0.0.1:0")
	m := metrics.New(prometheus.NewRegistry())
	b := builtSignInBroker(t, cfg, m)
	b.Say = func(string, ...any) {}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wirePasswordSignIn(ctx, cfg, b, signInTestKeys, m, nil, io.Discard)
	if b.EnrollmentStoreLost() == "" {
		t.Fatal("the broker is not lost before the init")
	}
	other, err := enrollfile.Open(file, signInTestKeys, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	mine := crypt.WrapEnrollments(other, signInTestKeys, metrics.New(prometheus.NewRegistry()).CryptOpenFailures)
	if err := mine.CreateEnrollmentMark(ctx, store.EnrollmentMark{CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for b.EnrollmentStoreLost() != "" {
		if time.Now().After(deadline) {
			t.Fatalf("the running broker is still lost after an offline init: %q", b.EnrollmentStoreLost())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if v := testutil.ToFloat64(m.DirectoryEnrollmentStoreOK); v != 1 {
		t.Errorf("the gauge reads %v after the init", v)
	}
}

// A link planted at the path of a running broker's enrollment store is said once with the fence's
// reason, not at every recheck, and the broker follows the store when the link is replaced by the file.
func TestARunningBrokerSaysALateUnreadableFileOnceAndFollowsTheFix(t *testing.T) {
	old := broker.EnrollmentRecheckEvery
	broker.EnrollmentRecheckEvery = 10 * time.Millisecond
	t.Cleanup(func() { broker.EnrollmentRecheckEvery = old })

	cfg, file := signInConfig(t, "127.0.0.1:0")
	m := metrics.New(prometheus.NewRegistry())
	b := builtSignInBroker(t, cfg, m)
	var said syncBuffer
	b.Say = func(format string, args ...any) { fmt.Fprintf(&said, format+"\n", args...) }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wirePasswordSignIn(ctx, cfg, b, signInTestKeys, m, nil, io.Discard)

	real := file + ".real"
	other, err := enrollfile.Open(real, signInTestKeys, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	mine := crypt.WrapEnrollments(other, signInTestKeys, metrics.New(prometheus.NewRegistry()).CryptOpenFailures)
	if err := mine.CreateEnrollmentMark(ctx, store.EnrollmentMark{CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, file); err != nil {
		t.Fatal(err)
	}
	time.Sleep(400 * time.Millisecond) // about forty rechecks
	if n := strings.Count(said.String(), "symbolic link"); n != 1 {
		t.Errorf("the link was said %d times in forty rechecks, want once:\n%s", n, said.String())
	}
	if b.EnrollmentStoreLost() == "" || !strings.Contains(b.EnrollmentStoreLost(), "symbolic link") {
		t.Errorf("the broker's lost reason is %q, want the link's", b.EnrollmentStoreLost())
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(real, file); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for b.EnrollmentStoreLost() != "" {
		if time.Now().After(deadline) {
			t.Fatalf("still lost after the link was replaced: %q", b.EnrollmentStoreLost())
		}
		time.Sleep(10 * time.Millisecond)
	}
}
