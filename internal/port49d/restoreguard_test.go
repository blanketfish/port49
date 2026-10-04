package port49d

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/store"
	etcdstore "github.com/rhwendt/port49/internal/store/etcd"
)

// The guard's states (Task 15d): it enters when a read shows the witness
// below the highest followed, or gone after one was seen; a read that
// fails leaves it where it is, said once per run of failures; a plain
// witness write, or a purge from before the drop, does not lift it; a
// purge written after the drop does.
func TestTheRestoreGuardEntersOnADropAndLeavesOnlyOnAPurge(t *testing.T) {
	var out bytes.Buffer
	gauge := prometheus.NewGauge(prometheus.GaugeOpts{Name: "g"})
	g := newRestoreGuard(&out)
	g.begin(gauge)
	unavailable := errors.Join(store.ErrUnavailable, errors.New("down"))
	g.judge(etcdstore.RestoreRead{Witness: 10, Header: 12}, nil)
	g.Saw(20) // a witness followed
	g.judge(etcdstore.RestoreRead{Witness: 20, Purged: 5, Header: 25}, nil)
	if !g.Allows() || testutil.ToFloat64(gauge) != 0 {
		t.Fatalf("guarded with nothing restored: %q", out.String())
	}
	g.judge(etcdstore.RestoreRead{}, unavailable)
	g.judge(etcdstore.RestoreRead{}, unavailable)
	if !g.Allows() || strings.Count(out.String(), "reading meta/witness") != 1 {
		t.Fatalf("a failed read entered, or was said per read: %q", out.String())
	}
	g.judge(etcdstore.RestoreRead{Witness: 12, Purged: 5, Header: 30}, nil) // the drop
	if g.Allows() || testutil.ToFloat64(gauge) != 1 ||
		!strings.Contains(out.String(), "meta/witness is at revision 12, below the 20 this port49d followed") {
		t.Fatalf("a drop did not guard: %v %q", g.Allows(), out.String())
	}
	for name, step := range map[string]func(){
		"a failed read":           func() { g.judge(etcdstore.RestoreRead{}, unavailable) },
		"a plain witness write":   func() { g.judge(etcdstore.RestoreRead{Witness: 31, Purged: 5, Header: 31}, nil) },
		"a witness followed":      func() { g.Saw(40) },
		"a purge before the drop": func() { g.judge(etcdstore.RestoreRead{Witness: 41, Purged: 29, Header: 42}, nil) },
	} {
		step()
		if g.Allows() || testutil.ToFloat64(gauge) != 1 {
			t.Fatalf("%s lifted the guard", name)
		}
	}
	g.judge(etcdstore.RestoreRead{Witness: 45, Purged: 44, Header: 46}, nil) // the runner's purge
	if !g.Allows() || testutil.ToFloat64(gauge) != 0 || !strings.Contains(out.String(), "redemptions are served again") {
		t.Fatalf("a purge after the drop did not lift the guard: %q", out.String())
	}
	g.judge(etcdstore.RestoreRead{Witness: 46, Purged: 44, Header: 47}, nil)
	if !g.Allows() {
		t.Fatal("the witness after the purge guarded again")
	}

	// Gone after one was seen guards too; gone before any was seen does not.
	fresh := newRestoreGuard(&out)
	fresh.begin(gauge)
	fresh.judge(etcdstore.RestoreRead{Header: 3}, nil)
	if !fresh.Allows() {
		t.Fatal("no witness on a new keyspace guarded")
	}
	fresh.Saw(7)
	fresh.judge(etcdstore.RestoreRead{Header: 50}, nil)
	if fresh.Allows() || !strings.Contains(out.String(), "meta/witness is absent, below the 7 this port49d followed") {
		t.Fatalf("a witness gone after one was seen did not guard: %q", out.String())
	}
}

// A run after a store gone refuses redemptions until its first read
// judges the store: the outage may have been the restore (Task 15d).
func TestARunAfterAStoreGoneRedeemsOnlyOnceTheStoreIsJudged(t *testing.T) {
	gauge := prometheus.NewGauge(prometheus.GaugeOpts{Name: "g"})
	g := newRestoreGuard(&bytes.Buffer{})
	g.begin(gauge)
	if !g.Allows() {
		t.Fatal("a cold start with nothing followed refused")
	}
	g.Saw(20)
	g.begin(gauge) // the next run
	if g.Allows() {
		t.Fatal("a run after one that followed a witness redeemed before judging the store")
	}
	g.judge(etcdstore.RestoreRead{}, errors.New("down"))
	if g.Allows() {
		t.Fatal("a failed first read opened redemptions")
	}
	g.judge(etcdstore.RestoreRead{Witness: 20, Header: 21}, nil)
	if !g.Allows() {
		t.Fatal("the first read that found nothing restored left redemptions refused")
	}
}
