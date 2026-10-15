package port49d

import (
	"context"
	"io"
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
