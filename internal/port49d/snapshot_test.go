package port49d

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/store"
	etcdstore "github.com/rhwendt/port49/internal/store/etcd"
)

// fakeSnapshots is a session store's snapshot records by kind and writer.
type fakeSnapshots map[string]map[string][]byte

func (f fakeSnapshots) DirectorySnapshots(_ context.Context, kind string) (map[string][]byte, error) {
	return f[kind], nil
}

// N1: port49d serves the union of every marks record: its own record
// deleted, or an older body of it put back, lifts nothing a broker's record
// holds.
func TestTheSnapshotsMarksAreTheirUnion(t *testing.T) {
	keys := signInTestKeys
	now := time.Now()
	a := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:a@example.com", At: now.Add(-2 * time.Hour)}
	b := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:b@example.com", At: now.Add(-time.Minute)}
	seal := func(writer string, conf time.Time, marks ...store.Revocation) []byte {
		raw, err := sealSnapshot(keys, etcdstore.SnapshotMarks, writer,
			marksSnapshot{Writer: writer, Revision: 9, Confirmed: conf, Marks: marks})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	oldDaemon := seal("port49d@h1", now.Add(-time.Hour), a) // an older body, put back by the daemon's key holder
	broker := seal("port49-broker@h2", now.Add(-30*time.Second), a, b)
	for name, recs := range map[string]map[string][]byte{
		"an older body put back": {"port49d@h1": oldDaemon, "port49-broker@h2": broker},
		"its own record deleted": {"port49-broker@h2": broker},
	} {
		v, ok, err := loadSnapshots(context.Background(), fakeSnapshots{etcdstore.SnapshotMarks: recs}, keys, false,
			4*time.Hour, time.Second, io.Discard, "port49d")
		if err != nil || !ok {
			t.Fatalf("%s: %v %v", name, ok, err)
		}
		held := map[string]bool{}
		for _, r := range v.marks {
			held[r.Key] = true
		}
		if !held[a.Key] || !held[b.Key] || !v.confirmed.Equal(now.Add(-30*time.Second)) {
			t.Fatalf("%s: marks %v, confirmed %v; want both marks and the broker's time", name, held, v.confirmed)
		}
	}
	// A valid young record beside one that does not open is still served.
	good := seal("port49d@h1", now.Add(-time.Minute), a)
	if v, ok, _ := loadSnapshots(context.Background(), fakeSnapshots{etcdstore.SnapshotMarks: {"port49d@h1": good,
		"port49d@h3": []byte("not sealed")}}, keys, false, 4*time.Hour, time.Second, io.Discard, "port49d"); !ok ||
		len(v.marks) != 1 {
		t.Fatalf("a record beside an unsealed one: ok %v, marks %v", ok, v.marks)
	}
	// A record past the ceiling is not served; one that does not open is skipped.
	stale := seal("port49d@h1", now.Add(-5*time.Hour), a, b)
	if _, ok, _ := loadSnapshots(context.Background(), fakeSnapshots{etcdstore.SnapshotMarks: {"port49d@h1": stale,
		"port49d@h3": []byte("not sealed")}}, keys, false, 4*time.Hour, time.Second, io.Discard, "port49d"); ok {
		t.Fatal("a record past the ceiling was served")
	}
}
