package port49d

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/session"
	"github.com/rhwendt/port49/internal/store"
	etcdstore "github.com/rhwendt/port49/internal/store/etcd"
	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
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
