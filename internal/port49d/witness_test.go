package port49d

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// A record that cannot be read or does not decode is no record, and says
// so: the takeover then goes by meta/judged alone, and never skips a
// purge it owes.
func TestAWitnessRecordThatDoesNotDecodeIsNoRecord(t *testing.T) {
	path := filepath.Join(safeDir(t), stateWitnessFile)
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, have := openWitness(path, "/port49/", &out).Recorded(); have || !strings.Contains(out.String(), "does not decode") {
		t.Fatalf("a record that does not decode: %v %q", have, out.String())
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
