package port49d

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/blanketfish/port49/internal/broker"
	"github.com/blanketfish/port49/internal/config"
	"github.com/blanketfish/port49/internal/daemon/metrics"
	"github.com/blanketfish/port49/internal/decision"
	"github.com/blanketfish/port49/internal/policy"
	"github.com/blanketfish/port49/internal/session"
	"github.com/blanketfish/port49/internal/store"
	"github.com/blanketfish/port49/internal/store/crypt"
	etcdstore "github.com/blanketfish/port49/internal/store/etcd"
)

// purgeRig is a split fleet's store with a witness at w0, from which runners
// are built on a witness record and a session store of the test's choosing.
type purgeRig struct {
	t    *testing.T
	ctx  context.Context
	bs   brokerStores
	m    *metrics.Metrics
	cfg  config.Config
	keys crypt.Keys
	b    *broker.Broker
	w0   uint64
	out  *syncBuffer
}

func newPurgeRig(t *testing.T) *purgeRig {
	t.Helper()
	f := splitFleet(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	m := metrics.New(prometheus.NewRegistry())
	bs, keys := openBrokerFor(t, ctx, f.broker, m, io.Discard)
	cfg, _ := loadBroker(t, f.broker)
	bcfg := brokerConfig(t, minimalPolicy)
	_, b, err := buildBroker(bcfg, "inventory_file "+bcfg.InventoryFile, bs.st, seedMinter(),
		decision.NewJSONLines(io.Discard), m)
	if err != nil {
		t.Fatal(err)
	}
	b.Sessions = session.New(bs.st, time.Now, cfg.ContextIdleTTL, cfg.Session.IndexTTL)
	b.Marks = store.NewMarks()
	w0, err := bs.raw.PutWitness(ctx, "runner-a", 0)
	if err != nil || w0 == 0 {
		t.Fatalf("%d %v", w0, err)
	}
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	return &purgeRig{t: t, ctx: ctx, bs: bs, m: m, cfg: cfg, keys: keys, b: b, w0: w0, out: &out}
}

// runner is a runner for who on wit and st.
func (g *purgeRig) runner(who string, wit *witnessRecord, st store.Store) *runner {
	return &runner{cfg: g.cfg, brk: g.b, raw: g.bs.raw, st: st, meta: g.bs.raw, keys: g.keys, m: g.m,
		alarm: newKeyAlarm(), who: who, witness: wit, marksReloaded: make(chan struct{}, 1)}
}

// witnessAtStore is meta/witness's ModRevision now.
func (g *purgeRig) witnessAtStore() uint64 {
	g.t.Helper()
	w, err := g.bs.raw.Witness(g.ctx)
	if err != nil {
		g.t.Fatal(err)
	}
	return w.ModRevision
}

// failsPurgeOnce fails the first PurgeTokens with an error that is not an
// outage, as a purge cut short by anything but the store being away.
type failsPurgeOnce struct {
	store.Store
	failed atomic.Bool
}

func (f *failsPurgeOnce) PurgeTokens(ctx context.Context) (int, error) {
	if f.failed.CompareAndSwap(false, true) {
		return 0, errors.New("purge cut short")
	}
	return f.Store.PurgeTokens(ctx)
}

// A purge cut short on a replica with no witness record, then the same broker
// restarted on the same state_dir: with meta/purged gone, ordering is the
// only safeguard. The cut-short purge saves no witness.json (the follower
// told the record the store's own witness meanwhile), and writes no
// meta/witness, so the restart still owes the purge (decision 56 ruling 2).
func TestAPurgeCutShortIsOwedAgainAfterARestartOnTheSameStateDir(t *testing.T) {
	for name, recorded := range map[string]uint64{"no record": 0, "a record above the store's": 1} {
		t.Run(name, func(t *testing.T) {
			g := newPurgeRig(t)
			path := filepath.Join(safeDir(t), stateWitnessFile)
			if recorded != 0 {
				seed := openWitness(path, "/port49/", io.Discard)
				seed.Reset(g.w0 + 1000)
				seed.save()
			}
			wit := openWitness(path, "/port49/", io.Discard)
			cut := &failsPurgeOnce{Store: g.bs.st}
			if err := g.runner("runner-a", wit, cut).witnessPass(g.ctx); err == nil {
				t.Fatal("the cut-short purge reported nothing")
			}
			if got := g.witnessAtStore(); got != g.w0 {
				t.Fatalf("a purge cut short wrote meta/witness: %d, was %d", got, g.w0)
			}
			wit.Saw(g.w0) // the follower tells the record the store's own witness
			wit.save()    // and the record is saved, as keep does each second
			// The broker restarts on the same state_dir.
			again := openWitness(path, "/port49/", io.Discard)
			before := len(g.out.String())
			if err := g.runner("runner-a", again, g.bs.st).witnessPass(g.ctx); err != nil {
				t.Fatal(err)
			}
			if n := strings.Count(g.out.String()[before:], "every unspent token is purged"); n != 1 {
				t.Fatalf("the restart did not purge (%d purges):\n%s", n, g.out.String()[before:])
			}
		})
	}
}

// The same cut-short purge, and the keyspace handed to another broker: B has
// a state_dir of its own, with a record above the store's witness or none.
func TestAPurgeCutShortIsOwedByTheBrokerTheKeyspaceIsHandedTo(t *testing.T) {
	for name, recorded := range map[string]uint64{"no record": 0, "a record above the store's": 1} {
		t.Run(name, func(t *testing.T) {
			g := newPurgeRig(t)
			a := openWitness(filepath.Join(safeDir(t), stateWitnessFile), "/port49/", io.Discard)
			if err := g.runner("runner-a", a, &failsPurgeOnce{Store: g.bs.st}).witnessPass(g.ctx); err == nil {
				t.Fatal("the cut-short purge reported nothing")
			}
			bPath := filepath.Join(safeDir(t), stateWitnessFile)
			if recorded != 0 {
				seed := openWitness(bPath, "/port49/", io.Discard)
				seed.Reset(g.w0 + 1) // just above the store's witness: a write by A would catch it up
				seed.save()
			}
			before := len(g.out.String())
			if err := g.runner("runner-b", openWitness(bPath, "/port49/", io.Discard), g.bs.st).witnessPass(g.ctx); err != nil {
				t.Fatal(err)
			}
			if n := strings.Count(g.out.String()[before:], "every unspent token is purged"); n != 1 {
				t.Fatalf("the broker handed the keyspace did not purge (%d purges):\n%s", n, g.out.String()[before:])
			}
		})
	}
}

// A purge owed is owed until it is done: a follower's tell does not lift it,
// and nothing is saved meanwhile.
func TestAnOwedPurgeIsNotLiftedByTheFollowerOrSaved(t *testing.T) {
	path := filepath.Join(safeDir(t), stateWitnessFile)
	w := openWitness(path, "/port49/", io.Discard)
	if _, gone, _, err := readWitness(context.Background(), w, func(context.Context) (etcdstore.WitnessRead, error) {
		return etcdstore.WitnessRead{ModRevision: 500, Header: 600}, nil
	}); err != nil || !gone {
		t.Fatalf("no record: gone %v, %v", gone, err)
	}
	w.Saw(500)
	w.save()
	if _, err := os.Stat(path); err == nil {
		t.Fatal("a record owing a purge was saved")
	}
	// A record above the store's: found restored, then the store's witness
	// climbs past the record before the purge is done. The owing stays.
	w.Reset(1000)
	at := func(rev uint64) func(context.Context) (etcdstore.WitnessRead, error) {
		return func(context.Context) (etcdstore.WitnessRead, error) {
			return etcdstore.WitnessRead{ModRevision: rev, Header: rev + 1}, nil
		}
	}
	if _, gone, _, _ := readWitness(context.Background(), w, at(400)); !gone {
		t.Fatal("a store below the record was not found restored")
	}
	w.Saw(2000)
	if _, gone, why, _ := readWitness(context.Background(), w, at(1500)); !gone || !strings.Contains(why, "not yet done") {
		t.Fatalf("the follower's tell lifted the owing: %v %q", gone, why)
	}
	w.Reset(500)
	w.Saw(510)
	if got, have := w.Recorded(); !have || got != 510 {
		t.Fatalf("after the purge: %d %v", got, have)
	}
}

// A mint during a restore's purge is refused with a retry message, and a mint
// after it is served: a token minted in the window is never minted and then
// purged.
func TestAMintDuringARestoresPurgeIsRefusedNotPurged(t *testing.T) {
	g := newPurgeRig(t)
	gate := newStartGate(nil)
	pol := policy.NewLive(buildPolicy(t, brokerConfig(t, minimalPolicy), minimalPolicy)).Load()
	gate.flag(pol.Bundle)
	gate.open("test", io.Discard)
	if err := gate.allow(pol); err != nil {
		t.Fatalf("control: %v", err)
	}
	blocking := &blocksPurge{Store: g.bs.st, in: make(chan struct{}), release: make(chan struct{})}
	r := g.runner("runner-a", openWitness(filepath.Join(safeDir(t), stateWitnessFile), "/port49/", io.Discard), blocking)
	r.holdMints = gate.purge
	done := make(chan error, 1)
	go func() { done <- r.witnessPass(g.ctx) }()
	select {
	case <-blocking.in:
	case <-time.After(10 * time.Second):
		t.Fatal("the purge never began")
	}
	if err := gate.allow(pol); err == nil || !strings.Contains(err.Error(), "retry") {
		t.Fatalf("a mint during the purge: %v", err)
	}
	close(blocking.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := gate.allow(pol); err != nil {
		t.Fatalf("a mint after the purge: %v", err)
	}
}

// blocksPurge holds PurgeTokens until released.
type blocksPurge struct {
	store.Store
	in, release chan struct{}
}

func (b *blocksPurge) PurgeTokens(ctx context.Context) (int, error) {
	close(b.in)
	select {
	case <-b.release:
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	return b.Store.PurgeTokens(ctx)
}

// A start whose meta/judged names its bundle opens its gate at once, except
// when the replica owes a purge: the judged record may be a restore's, and a
// token minted before the takeover's purge would be deleted by it.
func TestAStartGateStaysClosedWhileAPurgeIsOwed(t *testing.T) {
	cfg := brokerConfig(t, minimalPolicy)
	live := policy.NewLive(buildPolicy(t, cfg, minimalPolicy))
	bundle := live.Load().Bundle
	judged := judgedAt{ok: true}
	judged.rec.Bundle = bundle
	gate := newStartGate(nil)
	owes := func(context.Context) bool { return true }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		openAtJudged(ctx, judged, gate, live, time.Second, 10*time.Millisecond, io.Discard, owes)
	}()
	time.Sleep(200 * time.Millisecond)
	if gate.opened() {
		t.Fatal("the gate opened at meta/judged while a purge is owed")
	}
	cancel()
	<-done
	gate = newStartGate(nil)
	openAtJudged(context.Background(), judged, gate, live, time.Second, 10*time.Millisecond, io.Discard,
		func(context.Context) bool { return false })
	if !gate.opened() {
		t.Fatal("control: the gate stayed closed with nothing owed")
	}
}

// recordedWitness is a witness record that holds rev, as one read from a
// witness.json a replica saved: a record fresh on an empty state_dir owes a
// purge and takes no tell.
func recordedWitness(t *testing.T, rev uint64) *witnessRecord {
	t.Helper()
	path := filepath.Join(safeDir(t), stateWitnessFile)
	w := openWitness(path, "/port49/", io.Discard)
	w.Reset(rev)
	w.save()
	return openWitness(path, "/port49/", io.Discard)
}
