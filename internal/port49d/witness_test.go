package port49d

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/blanketfish/port49/internal/daemon/metrics"
	"github.com/blanketfish/port49/internal/decision"
	"github.com/blanketfish/port49/internal/session"
	"github.com/blanketfish/port49/internal/store"
	etcdstore "github.com/blanketfish/port49/internal/store/etcd"
	"github.com/blanketfish/port49/internal/store/etcd/etcdtest"
)

// The decision reads the witness's ModRevision alone: a restored key
// keeps it, with or without --bump-revision, while the read's header
// rises under the bump (Ruling 18; re-check R6).
func TestARestoredWitnessIsCaught(t *testing.T) {
	for name, c := range map[string]struct {
		read     etcdstore.WitnessRead
		recorded uint64
		have     bool
		want     bool
		says     string
	}{
		"below, no bump":              {etcdstore.WitnessRead{ModRevision: 812, Header: 900}, 1907, true, true, "is at revision 812, below the 1907 this replica saw"},
		"below, the header far above": {etcdstore.WitnessRead{ModRevision: 812, Header: 1_000_812}, 1907, true, true, "is at revision 812, below the 1907 this replica saw"},
		"equal":                       {etcdstore.WitnessRead{ModRevision: 1907, Header: 1950}, 1907, true, false, ""},
		"above, another runner's":     {etcdstore.WitnessRead{ModRevision: 2001, Header: 2001}, 1907, true, false, ""},
		"absent, with a record":       {etcdstore.WitnessRead{Header: 1_000_000}, 1907, true, true, "is absent, below the 1907 this replica saw"},
		"no record":                   {etcdstore.WitnessRead{ModRevision: 812, Header: 900}, 0, false, false, "no witness record in broker.state_dir"},
	} {
		got, why := restored(c.read, c.recorded, c.have)
		if got != c.want || !strings.Contains(why, c.says) || (c.says == "" && why != "") {
			t.Errorf("%s: %v %q", name, got, why)
		}
	}
}

// The record keeps the highest it is told, is lowered only by Reset,
// survives a restart owner only, and is no record for another prefix.
func TestTheWitnessRecordKeepsTheHighest(t *testing.T) {
	path := filepath.Join(safeDir(t), stateWitnessFile)
	var out bytes.Buffer
	w := openWitness(path, "/port49/", &out)
	if _, have := w.Recorded(); have {
		t.Fatal("a record with no file")
	}
	w.Saw(1907)
	w.Saw(812) // a restore's, followed
	if got, have := w.Recorded(); got != 1907 || !have {
		t.Fatalf("%d %v", got, have)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); w.keep(ctx) }()
	cancel()
	<-done // keep saves as it stops
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", fi, err)
	}
	if got, have := openWitness(path, "/port49/", &out).Recorded(); got != 1907 || !have {
		t.Fatalf("after a restart: %d %v", got, have)
	}
	if _, have := openWitness(path, "/other/", &out).Recorded(); have || !strings.Contains(out.String(), "another prefix's") {
		t.Fatalf("a record for another prefix: %v %q", have, out.String())
	}
	w.Reset(812)
	if got, _ := w.Recorded(); got != 812 {
		t.Fatalf("after Reset: %d", got)
	}
}

// A record that cannot be read or does not decode is taken as restored,
// not as no record: whatever the store's witness, the first check purges
// once, and the purge's Reset writes a good file. The file is moved
// aside, as the marks copy's is, and the line says so (fix round 1, M-1).
func TestAWitnessRecordThatCannotBeReadPurgesOnce(t *testing.T) {
	for name, write := range map[string]func(path string) error{
		"does not decode": func(path string) error { return os.WriteFile(path, []byte("{not json"), 0o600) },
		"cannot be read":  func(path string) error { return os.WriteFile(path, []byte(`{}`), 0o000) },
	} {
		t.Run(name, func(t *testing.T) {
			if name == "cannot be read" && os.Geteuid() == 0 {
				t.Skip("running as root, which reads a mode-0000 file: the unreadable case needs a non-root user")
			}
			dir := safeDir(t)
			path := filepath.Join(dir, stateWitnessFile)
			if err := write(path); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			w := openWitness(path, "/port49/", &out)
			if !strings.Contains(out.String(), "moved aside to "+path+".bad-") ||
				!strings.Contains(out.String(), "the first check purges every unspent token once") {
				t.Fatalf("%s: the line: %q", name, out.String())
			}
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%s: not moved aside: %v", name, err)
			}
			rec, have := w.Recorded()
			gone, why := restored(etcdstore.WitnessRead{ModRevision: 1 << 40, Header: 1 << 40}, rec, have)
			if !gone || !strings.Contains(why, "could not be read") {
				t.Fatalf("%s: a record that could not be read, against a witness far above: %v %q", name, gone, why)
			}
			w.Saw(1 << 41) // a witness followed meanwhile does not clear it
			if rec, _ := w.Recorded(); rec != unreadWitness {
				t.Fatalf("%s: following cleared the unread record: %d", name, rec)
			}
			// A replica restarted before it ever runs keeps the purge it owes:
			// the unread record is saved, and read back as one (re-review 1 M-5).
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			w.keep(ctx)
			var again bytes.Buffer
			reopened := openWitness(path, "/port49/", &again)
			if rec, have := reopened.Recorded(); rec != unreadWitness || !have ||
				!strings.Contains(again.String(), "the first check purges every unspent token once") {
				t.Fatalf("%s: reopened before a purge: %d %v %q", name, rec, have, again.String())
			}
			if gone, why := restored(etcdstore.WitnessRead{ModRevision: 1 << 40, Header: 1 << 40}, unreadWitness,
				true); !gone || !strings.Contains(why, "could not be read") {
				t.Fatalf("%s: reopened, not restored: %v %q", name, gone, why)
			}
			w.Reset(812) // the purge done
			w.keep(ctx)
			if got, have := openWitness(path, "/port49/", io.Discard).Recorded(); got != 812 || !have {
				t.Fatalf("%s: after the purge: %d %v", name, got, have)
			}
		})
	}
}

// A witness another runner writes while this one reads, followed into the
// record before the read answers, is no restore: the record is taken
// before the read (final check, Minor 1).
func TestAWitnessWrittenDuringTheReadIsNoRestore(t *testing.T) {
	w := openWitness(filepath.Join(t.TempDir(), stateWitnessFile), "/port49/", io.Discard)
	w.Saw(1907)
	_, gone, why, err := readWitness(context.Background(), w, func(context.Context) (etcdstore.WitnessRead, error) {
		w.Saw(2001) // another runner's witness, followed while the read was in flight
		return etcdstore.WitnessRead{ModRevision: 1907, Header: 1950}, nil
	})
	if err != nil || gone || why != "" {
		t.Fatalf("a witness written during the read: %v %q %v", gone, why, err)
	}
}

// A pass rewrites the witness only when the store has moved past it: two
// passes with nothing written between them leave it where it was, so the
// rewrite never feeds itself. A write elsewhere brings one more, and the
// replica records the witness it wrote (Ruling 18; re-check R6). On a
// member of the test's own: the shared one moves under every test.
func TestAQuietStoreWritesNoWitness(t *testing.T) {
	ctx := context.Background()
	srv := etcdtest.Start(t, etcdtest.Options{})
	s, err := etcdstore.Open(etcdstore.Config{Endpoints: []string{srv.Endpoint}, Prefix: "/port49/", Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	r := &runner{raw: s, who: "port49-broker on test",
		witness: openWitness(filepath.Join(safeDir(t), stateWitnessFile), "/port49/", io.Discard)}
	at := func() uint64 {
		t.Helper()
		w, err := s.Witness(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return w.ModRevision
	}
	pass := func() {
		t.Helper()
		if err := r.witnessPass(ctx); err != nil {
			t.Fatal(err)
		}
	}
	pass() // none yet: the store has moved past an absent witness
	first := at()
	if first == 0 {
		t.Fatal("no witness after a pass on a store with none")
	}
	pass()
	pass()
	if got := at(); got != first {
		t.Fatalf("a quiet store's witness moved from %d to %d", first, got)
	}
	if rec, _ := r.witness.Recorded(); rec != first {
		t.Fatalf("the replica recorded %d, not its own witness at %d", rec, first)
	}
	if _, err := srv.Client(t, "root").Put(ctx, "/port49/v1/elsewhere", "x"); err != nil {
		t.Fatal(err)
	}
	pass()
	if got := at(); got <= first {
		t.Fatalf("a write elsewhere brought no witness: %d after %d", got, first)
	}
}

// cutPurge fails PurgeTokens while fail is set, as a purge cut short.
type cutPurge struct {
	store.Store
	fail atomic.Bool
}

func (c *cutPurge) PurgeTokens(ctx context.Context) (int, error) {
	if c.fail.Load() {
		return 0, errors.New("cut short")
	}
	return c.Store.PurgeTokens(ctx)
}

// A running runner's pass that finds meta/witness below the record purges,
// has the marks applied again, and takes the store's witness as the record
// only once the purge is done: a purge cut short leaves the record, so the
// next pass, or the next runner, purges (Ruling 18). Once done, it purges
// no more. The purge supersedes every key first, so a replay mints afresh
// (Task 15c review I-1, M-3).
func TestARunningRunnerPurgesARestoreAndKeepsTheRecordUntilDone(t *testing.T) {
	f := splitFleet(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
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
	wit := openWitness(filepath.Join(safeDir(t), stateWitnessFile), "/port49/", io.Discard)
	wit.Saw(w0 + 1000) // a witness the restore lost
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	st := &cutPurge{Store: bs.st}
	st.fail.Store(true)
	r := &runner{cfg: cfg, brk: b, raw: bs.raw, st: st, meta: bs.raw, keys: keys, m: m, alarm: newKeyAlarm(),
		who: "runner-a", witness: wit, marksReloaded: make(chan struct{}, 1)}
	if err := r.witnessPass(ctx); err == nil {
		t.Fatal("a pass whose purge was cut short said nothing")
	}
	if rec, _ := wit.Recorded(); rec != w0+1000 {
		t.Fatalf("a purge cut short lowered the record to %d", rec)
	}
	select {
	case <-r.marksReloaded:
		t.Fatal("the marks were asked for before the purge was done")
	default:
	}
	st.fail.Store(false)
	before := time.Now()
	if err := r.witnessPass(ctx); err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("is at revision %d, below the %d this replica saw: the store was restored from a "+
		"snapshot; every unspent token is purged", w0, w0+1000); !strings.Contains(out.String(), want) {
		t.Fatalf("no purge line:\n%s", out.String())
	}
	if at, err := bs.raw.SupersededAt(ctx, store.TokenKey{NAS: "x", Username: "y"}); err != nil || at.Before(before) {
		t.Fatalf("the purge superseded no key: %v %v (the pass began %v)", at, err, before)
	}
	select {
	case <-r.marksReloaded:
	default:
		t.Fatal("the marks were not applied again after the purge")
	}
	if rec, _ := wit.Recorded(); rec != w0 {
		t.Fatalf("after the purge the record is %d, not the store's %d", rec, w0)
	}
	if err := r.witnessPass(ctx); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(out.String(), "every unspent token is purged"); n != 1 {
		t.Fatalf("%d purges for one restore", n)
	}
}

// movesWitness rewrites meta/witness once as a purge ends, as a restore
// landing inside the purge would change it.
type movesWitness struct {
	store.Store
	raw  *etcdstore.Store
	move atomic.Bool
}

func (m *movesWitness) PurgeTokens(ctx context.Context) (int, error) {
	n, err := m.Store.PurgeTokens(ctx)
	if err == nil && m.move.CompareAndSwap(true, false) {
		w, werr := m.raw.Witness(ctx)
		if werr != nil {
			return n, werr
		}
		if _, werr = m.raw.PutWitness(ctx, "runner-b", w.ModRevision); werr != nil {
			return n, werr
		}
	}
	return n, err
}

// A purge whose meta/purged write is refused, because meta/witness
// changed during it, leaves the record where it is: the next pass judges
// the store again and purges once more, so port49d's guard is never
// released over tokens that were not purged (Task 15d re-review M-8).
func TestARefusedPurgeRecordLeavesTheWitnessRecordForTheNextPass(t *testing.T) {
	f := splitFleet(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
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
	wit := openWitness(filepath.Join(safeDir(t), stateWitnessFile), "/port49/", io.Discard)
	wit.Saw(w0 + 1000) // a witness the restore lost
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	st := &movesWitness{Store: bs.st, raw: bs.raw}
	st.move.Store(true)
	r := &runner{cfg: cfg, brk: b, raw: bs.raw, st: st, meta: bs.raw, keys: keys, m: m, alarm: newKeyAlarm(),
		who: "runner-a", witness: wit, marksReloaded: make(chan struct{}, 1)}
	if err := r.witnessPass(ctx); err != nil {
		t.Fatal(err)
	}
	if got, err := bs.raw.RestoreRead(ctx); err != nil || got.Purged != 0 {
		t.Fatalf("a refused purge record landed: %+v %v", got, err)
	}
	if rec, _ := wit.Recorded(); rec != w0+1000 {
		t.Fatalf("a refused purge record reset the witness record to %d", rec)
	}
	if err := r.witnessPass(ctx); err != nil { // the witness moved: the record is still above it
		t.Fatal(err)
	}
	if n := strings.Count(out.String(), "every unspent token is purged"); n != 2 {
		t.Fatalf("%d purges, want a second after the refused one:\n%s", n, out.String())
	}
	if got, err := bs.raw.RestoreRead(ctx); err != nil || got.Purged == 0 {
		t.Fatalf("the second purge wrote no meta/purged: %+v %v", got, err)
	}
}

// hookTimeout is how long a wait on a hook gives before it fails.
const hookTimeout = 10 * time.Second

// hookSeen is what a recording hook has seen, by the pointer it was told of:
// one test process may run several daemons, so no wait is keyed by name.
type hookSeen[P comparable] struct {
	mu   sync.Mutex
	high map[P]uint64 // the highest revision followed, or the passes completed
}

func (h *hookSeen[P]) add(p P, rev uint64, count bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.high == nil {
		h.high = map[P]uint64{}
	}
	switch {
	case count:
		h.high[p]++
	case rev > h.high[p]:
		h.high[p] = rev
	}
}

func (h *hookSeen[P]) snapshot() map[P]uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return maps.Clone(h.high)
}

// waitHook polls ok until it holds or hookTimeout, failing with what the hook
// had seen. Hooks are package variables, so a test installs its recorder
// before it starts a daemon: the restore, a cleanup registered first, runs
// after the daemons have stopped.
func waitHook(t *testing.T, what string, ok func() bool, seen func() string) {
	t.Helper()
	for deadline := time.Now().Add(hookTimeout); !ok(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("waiting for %s: %s", what, seen())
		}
	}
}

// followWitness installs a recording witnessFollowed, restored in t.Cleanup,
// and returns a wait until rec has followed a revision of atLeast or more.
func followWitness(t *testing.T) func(t *testing.T, rec *witnessRecord, atLeast uint64) {
	t.Helper()
	var h hookSeen[*witnessRecord]
	old := witnessFollowed
	witnessFollowed = func(rec *witnessRecord, rev uint64) { h.add(rec, rev, false) }
	t.Cleanup(func() { witnessFollowed = old })
	return func(t *testing.T, rec *witnessRecord, atLeast uint64) {
		t.Helper()
		waitHook(t, fmt.Sprintf("the record to follow revision %d", atLeast),
			func() bool { return h.snapshot()[rec] >= atLeast },
			func() string { return fmt.Sprintf("the highest it followed is %d", h.snapshot()[rec]) })
	}
}

// followGuard is followWitness for port49d's restore guard, which a test
// cannot name (run makes it): the wait is until guards distinct guards have
// each followed atLeast, guards being the number of daemons the test runs, so
// a test with two daemons cannot pass on the first one alone.
func followGuard(t *testing.T) func(t *testing.T, guards int, atLeast uint64) {
	t.Helper()
	var h hookSeen[*restoreGuard]
	old := guardFollowed
	guardFollowed = func(g *restoreGuard, rev uint64) { h.add(g, rev, false) }
	t.Cleanup(func() { guardFollowed = old })
	return func(t *testing.T, guards int, atLeast uint64) {
		t.Helper()
		reached := func() (n int) {
			for _, v := range h.snapshot() {
				if v >= atLeast {
					n++
				}
			}
			return n
		}
		waitHook(t, fmt.Sprintf("%d guards to follow revision %d", guards, atLeast),
			func() bool { return reached() >= guards },
			func() string { return fmt.Sprintf("%d reached it", reached()) })
	}
}

// passesFrom takes the counts now and returns the wait for n more completed
// passes by at least daemons distinct owners.
func passesFrom[P comparable](h *hookSeen[P], what string) func(t *testing.T, daemons, n int) {
	base := h.snapshot()
	return func(t *testing.T, daemons, n int) {
		t.Helper()
		advanced := func() (k int) {
			for p, c := range h.snapshot() {
				if c >= base[p]+uint64(n) {
					k++
				}
			}
			return k
		}
		waitHook(t, fmt.Sprintf("%d %s to complete %d passes", daemons, what, n),
			func() bool { return advanced() >= daemons },
			func() string { return fmt.Sprintf("%d advanced", advanced()) })
	}
}

// passesAfter is a wait counted from its own call.
func passesAfter[P comparable](h *hookSeen[P], what string) func(t *testing.T, daemons, n int) {
	return func(t *testing.T, daemons, n int) {
		t.Helper()
		passesFrom(h, what)(t, daemons, n)
	}
}

// countPasses installs a recording restorePassed, restored in t.Cleanup, and
// returns a wait for n more completed passes of each of daemons guards.
func countPasses(t *testing.T) func(t *testing.T, daemons, n int) {
	t.Helper()
	var h hookSeen[*restoreGuard]
	old := restorePassed
	restorePassed = func(g *restoreGuard) { h.add(g, 0, true) }
	t.Cleanup(func() { restorePassed = old })
	return passesAfter(&h, "restore guards")
}

// countRunnerPasses is countPasses for the broker runner's witness passes.
func countRunnerPasses(t *testing.T) func(t *testing.T, daemons, n int) {
	t.Helper()
	var h hookSeen[*runner]
	old := witnessPassed
	witnessPassed = func(r *runner) { h.add(r, 0, true) }
	t.Cleanup(func() { witnessPassed = old })
	return passesAfter(&h, "runners")
}

func openFollowStore(t *testing.T) (*etcdtest.Server, *etcdstore.Store) {
	t.Helper()
	srv := etcdtest.Start(t, etcdtest.Options{})
	s, err := etcdstore.Open(etcdstore.Config{Endpoints: []string{srv.Endpoint}, Prefix: "/port49/", Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return srv, s
}

// The hook tells what the follower gave the record: a write of meta/witness
// is waited for by its revision.
func TestTheWitnessHookSeesWhatTheFollowerSaw(t *testing.T) {
	waitFollowed := followWitness(t)
	_, s := openFollowStore(t)
	rec := openWitness(filepath.Join(safeDir(t), stateWitnessFile), "/port49/", io.Discard)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.FollowWitness(ctx, rec.followed) }()
	t.Cleanup(func() { cancel(); <-done })
	rev, err := s.PutWitness(ctx, "port49-broker on test", 0)
	if err != nil || rev == 0 {
		t.Fatalf("writing meta/witness: %d %v", rev, err)
	}
	waitFollowed(t, rec, rev)
	if got, _ := rec.Recorded(); got < rev {
		t.Fatalf("the hook fired before the record took %d: it has %d", rev, got)
	}
}

// Passes are counted per guard: a second guard's are not the first's.
func TestRestorePassedCountsPasses(t *testing.T) {
	var h hookSeen[*restoreGuard]
	old := restorePassed
	restorePassed = func(g *restoreGuard) { h.add(g, 0, true) }
	t.Cleanup(func() { restorePassed = old })
	_, s := openFollowStore(t)
	a, b := newRestoreGuard(io.Discard), newRestoreGuard(io.Discard)
	ctx := context.Background()
	pass := func(g *restoreGuard) {
		t.Helper()
		if !g.pass(ctx, time.Second, s.RestoreRead) {
			t.Fatal("a pass was cut short")
		}
	}
	waitA := passesFrom(&h, "restore guards")
	pass(a)
	pass(a)
	waitA(t, 1, 2) // returns: a completed two since the counts were taken
	waitAB := passesFrom(&h, "restore guards")
	pass(a)
	pass(a)
	if base := h.snapshot(); base[a] != 4 || base[b] != 0 {
		t.Fatalf("counts a=%d b=%d, want 4 and 0", base[a], base[b])
	}
	advanced := make(chan struct{})
	go func() { defer close(advanced); waitAB(t, 2, 1) }()
	select {
	case <-advanced:
		t.Fatal("a's passes were counted as b's")
	case <-time.After(100 * time.Millisecond):
	}
	pass(b)
	<-advanced
}

// The hooks are what make the waits sound, so their place is pinned: the
// follow hook fires after Saw has raised the witness followed, and the pass
// hook after judge has judged the read. A hook moved before either would take
// the waits back to timing, and these go red.
func TestTheGuardHooksFireAfterTheirWork(t *testing.T) {
	var atFollow, atPass []string
	oldF, oldP := guardFollowed, restorePassed
	guardFollowed = func(g *restoreGuard, rev uint64) {
		if high, _, _ := g.recorded(); high < rev {
			atFollow = append(atFollow, fmt.Sprintf("followed %d, recorded %d", rev, high))
		}
	}
	restorePassed = func(g *restoreGuard) {
		g.mu.Lock()
		defer g.mu.Unlock()
		if !g.checked {
			atPass = append(atPass, "the read was not judged")
		}
	}
	t.Cleanup(func() { guardFollowed, restorePassed = oldF, oldP })
	_, s := openFollowStore(t)
	g := newRestoreGuard(io.Discard)
	g.followed(7)
	// A guard waiting for a read that answers: judge lifts it.
	g.mu.Lock()
	g.checked = false
	g.mu.Unlock()
	if !g.pass(context.Background(), time.Second, s.RestoreRead) {
		t.Fatal("a pass was cut short")
	}
	if len(atFollow) > 0 {
		t.Errorf("guardFollowed fired before Saw: %v", atFollow)
	}
	if len(atPass) > 0 {
		t.Errorf("restorePassed fired before judge: %v", atPass)
	}
}
