package port49d

import (
	"context"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/crypt"
	"github.com/rhwendt/port49/internal/store/memory"
)

// A replica that is not the runner leaves enrollment_store_lost by itself
// once the mark exists, however it was made, without a restart (D7): two
// brokers on one global enrollment store, both lost, the mark made through a
// third handle; both leave the state within one interval and the gauge reads 1.
func TestAReplicaLeavesTheLostStateWhenTheMarkAppears(t *testing.T) {
	old := enrollmentRecheckEvery
	enrollmentRecheckEvery = 20 * time.Millisecond
	t.Cleanup(func() { enrollmentRecheckEvery = old })

	cfg, _ := signInConfig(t, "127.0.0.1:0")
	es := &cfg.Broker.Directory.EnrollmentStore
	es.Backend, es.File = config.BackendEtcd, ""
	cfg.Store.Etcd = &config.EtcdConfig{Endpoints: []string{"https://etcd-0:2379"}, CallTimeout: time.Second, BulkTimeout: time.Second}
	cfg.Store.Etcd.Breaker.Failures = 5
	shared := memory.NewEnrollments(time.Now)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var ms []*metrics.Metrics
	var bs []interface{ EnrollmentStoreLost() string }
	for i := 0; i < 2; i++ {
		m := metrics.New(prometheus.NewRegistry())
		b := builtSignInBroker(t, cfg, m)
		b.Say = func(string, ...any) {}
		wireSignIn(ctx, cfg, b, signInTestKeys, m, shared, io.Discard)
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
	old := enrollmentRecheckEvery
	enrollmentRecheckEvery = 20 * time.Millisecond
	t.Cleanup(func() { enrollmentRecheckEvery = old })

	cfg, _ := signInConfig(t, "127.0.0.1:0")
	es := &cfg.Broker.Directory.EnrollmentStore
	es.Backend, es.File = config.BackendEtcd, ""
	cfg.Store.Etcd = &config.EtcdConfig{Endpoints: []string{"https://etcd-0:2379"}, CallTimeout: time.Second, BulkTimeout: time.Second}
	cfg.Store.Etcd.Breaker.Failures = 5
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
	wireSignIn(ctx, cfg, b, signInTestKeys, m, shared, &out)
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
