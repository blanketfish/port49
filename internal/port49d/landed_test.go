package port49d

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/store"
	etcdstore "github.com/rhwendt/port49/internal/store/etcd"
	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
	"github.com/rhwendt/port49/internal/store/memory"
)

// The landed_after_lift flag survives broker.revocations_file, so a
// restart's put-back keeps it (re-review R-M5).
func TestTheFlagSurvivesTheRevocationsFile(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(safeDir(t), "revocations.json")
	if created, err := initRevocations(path, testInitConfig); err != nil || !created {
		t.Fatalf("init: %v %v", created, err)
	}
	at := time.Date(2026, 10, 21, 3, 0, 0, 0, time.UTC)
	before := memory.New(time.Now)
	for _, r := range []store.Revocation{
		{Kind: store.RevocationPrincipal, Key: "user:alice@example.com", At: at, Origin: "admin_socket uid 0",
			LandedAfterLift: true},
		{Kind: store.RevocationPrincipal, Key: "user:bob@example.com", At: at, Origin: "admin_socket uid 0"},
	} {
		if err := before.PutRevocation(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := persister(before, path, nil, nil, newMetrics())(ctx); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(raw), `"landed_after_lift": true`) != 1 {
		t.Fatalf("the file does not carry the flag once, as landed_after_lift:\n%s", raw)
	}
	after := memory.New(time.Now)
	if _, err := restoreRevocations(ctx, after, path); err != nil {
		t.Fatal(err)
	}
	a, err := after.GetRevocation(ctx, store.RevocationPrincipal, "user:alice@example.com")
	b, berr := after.GetRevocation(ctx, store.RevocationPrincipal, "user:bob@example.com")
	if err != nil || berr != nil || !a.LandedAfterLift || b.LandedAfterLift {
		t.Fatalf("after the restart: %+v %v, %+v %v", a, err, b, berr)
	}
}

// The flag survives a ds/m/ snapshot record, which a start in a cut serves
// from (re-review R-M5).
func TestTheFlagSurvivesTheSnapshot(t *testing.T) {
	keys := signInTestKeys
	now := time.Now()
	m := store.NewMarks()
	m.Set(store.Revocation{Kind: store.RevocationPrincipal, Key: "user:alice@example.com", At: now.Add(-time.Hour),
		LandedAfterLift: true}, true)
	m.Set(store.Revocation{Kind: store.RevocationPrincipal, Key: "user:bob@example.com", At: now.Add(-time.Hour)}, true)
	raw, err := sealSnapshot(keys, etcdstore.SnapshotMarks, "port49-broker@h1",
		marksSnapshot{Writer: "port49-broker@h1", Revision: 9, Confirmed: now.Add(-time.Minute), Marks: m.All()})
	if err != nil {
		t.Fatal(err)
	}
	v, ok, err := loadSnapshots(context.Background(), fakeSnapshots{etcdstore.SnapshotMarks: {"port49-broker@h1": raw}},
		keys, false, 4*time.Hour, time.Second, io.Discard, "port49-broker")
	if err != nil || !ok {
		t.Fatalf("%v %v", ok, err)
	}
	served := store.NewMarks()
	if _, err := store.LoadMarks(context.Background(), snapFeed{v}, served, nil); err != nil {
		t.Fatal(err)
	}
	a, _ := served.Get(store.RevocationPrincipal, "user:alice@example.com")
	b, _ := served.Get(store.RevocationPrincipal, "user:bob@example.com")
	if !a.LandedAfterLift || b.LandedAfterLift || served.Flagged() != 1 {
		t.Fatalf("served from the snapshot: %+v %+v", a, b)
	}
}

// A start with flagged marks says how many, once, since each mark's own
// line is not said again (re-review R-I5); with none it says nothing.
func TestAStartSaysHowManyMarksStandFlagged(t *testing.T) {
	m := store.NewMarks()
	var out bytes.Buffer
	sayFlagged(&out, "port49-broker", m.Flagged())
	if out.Len() != 0 {
		t.Fatalf("said with none flagged: %s", out.String())
	}
	m.Set(store.Revocation{Kind: store.RevocationPrincipal, Key: "user:alice@example.com", At: time.Now(),
		LandedAfterLift: true}, true)
	sayFlagged(&out, "port49-broker", m.Flagged())
	if out.String() != "port49-broker: store: 1 mark(s) stand flagged landed-after-lift; `port49 revoke --list` "+
		"names them\n" {
		t.Fatalf("said %q", out.String())
	}
}

// The runner says a mark this broker's own write failed to record as its
// own, never "made elsewhere" (post-11b, C2); another's still is.
func TestTheRunnerSaysAMarkThisBrokerFailedToRecordAsItsOwn(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	marks := store.NewMarks()
	mine := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:alice@example.com", At: time.Now().Round(0)}
	marks.NoteFailedWrite(mine)
	r := &runner{brk: &broker.Broker{Proc: "port49-broker", Marks: marks}, followed: make(chan store.Revocation, 2),
		followedLogouts: make(chan store.LogoutEntry, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); r.reachFollowed(ctx) }()
	defer func() { cancel(); <-done }()
	r.followed <- mine
	waitWithin(t, &out, "port49-broker: runner: a revocation of user:alice@example.com made on this port49-broker, "+
		"reported unrecorded then, reached", 5*time.Second)
	other := mine
	other.At = mine.At.Add(time.Second)
	r.followed <- other
	waitWithin(t, &out, "a revocation of user:alice@example.com made elsewhere reached", 5*time.Second)
	if strings.Count(out.String(), "made on this port49-broker") != 1 {
		t.Fatalf("said:\n%s", out.String())
	}
}

// L74 cell (i) on one etcd (task 2 review I1): region 1 lifts alice, and
// region 3's runner, whose watch never delivered the lift, puts her mark
// back from its marks copy. The mark lands flagged, saying it was put back,
// and the lifter's broker says the put-back form, never a copy a cut held
// back.
func TestARunnersPutBackOverALiveLiftIsSaidAsAPutBack(t *testing.T) {
	ctx := context.Background()
	srv := etcdtest.Start(t, etcdtest.Options{})
	prefix := etcdtest.Prefix()
	open := func() *etcdstore.Store {
		s, err := etcdstore.Open(etcdstore.Config{Endpoints: []string{srv.Endpoint}, Prefix: prefix})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		return s
	}
	region1, region3 := open(), open()
	now := time.Now().UTC().Round(0)
	alice := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:alice@example.com",
		At: now.Add(-20 * time.Second).Truncate(time.Second), Origin: "admin_socket uid 0"}
	if err := region1.PutRevocation(ctx, alice); err != nil {
		t.Fatal(err)
	}
	var out syncBuffer
	c := openMarksCopy(filepath.Join(safeStateDir(t), "marks.json"), &out)
	c.Apply(store.MarkChange{Revocation: alice, Standing: true}) // region 3 saw the mark, never its lift
	if err := region1.DeleteRevocation(ctx, alice.Kind, alice.Key, store.Lift{At: now,
		Origin: "admin_socket uid 0"}); err != nil {
		t.Fatal(err)
	}
	r := &runner{st: region3, copy: c}
	put, err := r.putBackMissing(ctx)
	if err != nil || len(put) != 1 {
		t.Fatalf("put back %v: %v", put, err)
	}
	got, err := region1.GetRevocation(ctx, alice.Kind, alice.Key)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.PutBackOf(got.Origin); !got.LandedAfterLift || !ok {
		t.Fatalf("the put-back landed as %+v", got)
	}
	var said bytes.Buffer
	brk := &broker.Broker{Proc: "port49-broker", Store: region1, Marks: store.NewMarks(),
		Say: func(format string, args ...any) { fmt.Fprintf(&said, format+"\n", args...) }}
	brk.MarkChanged(store.MarkChange{Revocation: got, Standing: true})
	if s := said.String(); !strings.Contains(s, "was put back after the lift at "+now.Format(time.RFC3339)+
		" by a port49-broker runner from its broker.state_dir/marks.json") || strings.Contains(s, "cut off") {
		t.Fatalf("the lifter's broker said %q", s)
	}
}
