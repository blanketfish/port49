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

// judgeNow is one read as keep takes it: the record, then the read.
func judgeNow(g *restoreGuard, r etcdstore.RestoreRead, err error) {
	high, seen := g.recorded()
	g.judge(r, err, high, seen)
}

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
	judgeNow(g, etcdstore.RestoreRead{Witness: 10, Header: 12}, nil)
	g.Saw(20) // a witness followed
	judgeNow(g, etcdstore.RestoreRead{Witness: 20, Purged: 5, Header: 25}, nil)
	if !g.Allows() || testutil.ToFloat64(gauge) != 0 {
		t.Fatalf("guarded with nothing restored: %q", out.String())
	}
	judgeNow(g, etcdstore.RestoreRead{}, unavailable)
	judgeNow(g, etcdstore.RestoreRead{}, unavailable)
	if g.Allows() || testutil.ToFloat64(gauge) != 0 || strings.Count(out.String(), "reading meta/witness") != 1 ||
		strings.Contains(out.String(), "was restored from a snapshot") {
		t.Fatalf("a failed read guarded, left redemptions open, or was said per read: %q", out.String())
	}
	judgeNow(g, etcdstore.RestoreRead{Witness: 12, Purged: 5, Header: 30}, nil) // the drop
	if g.Allows() || testutil.ToFloat64(gauge) != 1 ||
		!strings.Contains(out.String(), "meta/witness is at revision 12, below the 20 this port49d followed") {
		t.Fatalf("a drop did not guard: %v %q", g.Allows(), out.String())
	}
	for name, step := range map[string]func(){
		"a failed read":           func() { judgeNow(g, etcdstore.RestoreRead{}, unavailable) },
		"a plain witness write":   func() { judgeNow(g, etcdstore.RestoreRead{Witness: 31, Purged: 5, Header: 31}, nil) },
		"a witness followed":      func() { g.Saw(40) },
		"a purge at the drop":     func() { judgeNow(g, etcdstore.RestoreRead{Witness: 31, Purged: 30, Header: 31}, nil) },
		"a purge before the drop": func() { judgeNow(g, etcdstore.RestoreRead{Witness: 41, Purged: 29, Header: 42}, nil) },
	} {
		step()
		if g.Allows() || testutil.ToFloat64(gauge) != 1 {
			t.Fatalf("%s lifted the guard", name)
		}
	}
	judgeNow(g, etcdstore.RestoreRead{Witness: 45, Purged: 44, Header: 46}, nil) // the runner's purge
	if !g.Allows() || testutil.ToFloat64(gauge) != 0 || !strings.Contains(out.String(), "redemptions are served again") {
		t.Fatalf("a purge after the drop did not lift the guard: %q", out.String())
	}
	judgeNow(g, etcdstore.RestoreRead{Witness: 46, Purged: 44, Header: 47}, nil)
	if !g.Allows() {
		t.Fatal("the witness after the purge guarded again")
	}

	// Gone after one was seen guards too; gone before any was seen does not.
	fresh := newRestoreGuard(&out)
	fresh.begin(gauge)
	judgeNow(fresh, etcdstore.RestoreRead{Header: 3}, nil)
	if !fresh.Allows() {
		t.Fatal("no witness on a new keyspace guarded")
	}
	fresh.Saw(7)
	judgeNow(fresh, etcdstore.RestoreRead{Header: 50}, nil)
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
	judgeNow(g, etcdstore.RestoreRead{}, errors.New("down"))
	if g.Allows() {
		t.Fatal("a failed first read opened redemptions")
	}
	judgeNow(g, etcdstore.RestoreRead{Witness: 20, Header: 21}, nil)
	if !g.Allows() {
		t.Fatal("the first read that found nothing restored left redemptions refused")
	}
}

// A witness the runner writes while port49d's read is in flight, followed
// before the read is judged, is no restore: the record is taken before
// the read, as the runner's is (Task 15c, readWitness).
func TestAWitnessFollowedDuringTheGuardsReadIsNoDrop(t *testing.T) {
	var out bytes.Buffer
	g := newRestoreGuard(&out)
	g.Saw(100)
	high, seen := g.recorded()
	g.Saw(160) // the runner's next witness, followed while the read was in flight
	g.judge(etcdstore.RestoreRead{Witness: 100, Header: 150}, nil, high, seen)
	if !g.Allows() {
		t.Fatalf("a routine witness write guarded port49d: %q", out.String())
	}
}

// Once a witness was followed, a read that fails leaves redemptions
// refused until one answers: the outage may be the restore, and a
// redemption must not land between the store's return and the next read
// (Task 15d, ruling M-3). It is no guard: the gauge counts it, the
// guard's entry line is not said.
func TestAFailedReadRefusesRedemptionsUntilOneAnswers(t *testing.T) {
	var out bytes.Buffer
	g := newRestoreGuard(&out)
	g.begin(prometheus.NewGauge(prometheus.GaugeOpts{Name: "g"}))
	g.Saw(20)
	judgeNow(g, etcdstore.RestoreRead{Witness: 20, Header: 21}, nil)
	judgeNow(g, etcdstore.RestoreRead{}, errors.New("down"))
	if g.Allows() {
		t.Fatal("a failed read left redemptions open")
	}
	judgeNow(g, etcdstore.RestoreRead{}, errors.New("down"))
	if strings.Count(out.String(), "reading meta/witness") != 1 {
		t.Fatalf("a run of failures was said more than once: %q", out.String())
	}
	judgeNow(g, etcdstore.RestoreRead{Witness: 20, Header: 30}, nil)
	if !g.Allows() {
		t.Fatal("a read that found nothing restored left redemptions refused")
	}
	// Before any witness was followed, a failed read refuses nothing.
	fresh := newRestoreGuard(&out)
	fresh.begin(prometheus.NewGauge(prometheus.GaugeOpts{Name: "g"}))
	judgeNow(fresh, etcdstore.RestoreRead{}, errors.New("down"))
	if !fresh.Allows() {
		t.Fatal("a failed read refused redemptions on a keyspace with no witness")
	}
}
