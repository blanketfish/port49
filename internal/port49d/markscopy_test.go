package port49d

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/store"
)

// The copy keeps every mark it was told stands, drops one only on a lift
// the watch delivered, and keeps one a reload found missing: that may be a
// restore's loss (Ruling 12; pre-flight I5). It survives a restart, owner
// only.
func TestTheCopyKeepsAMarkAReloadFoundMissing(t *testing.T) {
	path := filepath.Join(safeStateDir(t), "marks.json")
	alice := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:alice@example.com", At: time.Unix(10, 0).UTC()}
	carol := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:carol@example.com", At: time.Unix(11, 0).UTC()}
	var out bytes.Buffer
	c := openMarksCopy(path, &out)
	c.Apply(store.MarkChange{Revocation: alice, Standing: true})
	c.Apply(store.MarkChange{Revocation: carol, Standing: true})
	c.Apply(store.MarkChange{Revocation: store.Revocation{Kind: alice.Kind, Key: alice.Key}, Reloaded: true})
	c.Apply(store.MarkChange{Revocation: store.Revocation{Kind: carol.Kind, Key: carol.Key}}) // a lift
	again := openMarksCopy(path, &out)
	if got := again.All(); len(got) != 1 || got[0].Key != alice.Key || !got[0].At.Equal(alice.At) {
		t.Fatalf("after a restart the copy holds %+v", got)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", fi, err)
	}
	if miss := again.Missing(nil); len(miss) != 1 || miss[0].Key != alice.Key {
		t.Fatalf("missing from an empty store: %+v", miss)
	}
	if miss := again.Missing([]store.Revocation{alice}); len(miss) != 0 {
		t.Fatalf("missing from a store holding it: %+v", miss)
	}
	if out.Len() != 0 {
		t.Fatalf("said %q", out.String())
	}
}

// A copy that does not decode is moved aside and replaced, never fatal:
// the store holds every mark. It is said, naming where it was moved and
// what is lost with it, and never trusted.
func TestACopyThatDoesNotDecodeIsMovedAside(t *testing.T) {
	dir := safeStateDir(t)
	path := filepath.Join(dir, "marks.json")
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if c := openMarksCopy(path, &out); len(c.All()) != 0 || !strings.Contains(out.String(), "does not decode") ||
		!strings.Contains(out.String(), "cannot be put back") {
		t.Fatalf("%q", out.String())
	}
	m, _ := filepath.Glob(path + ".bad-*")
	if len(m) != 1 {
		t.Fatalf("not moved aside: %v", m)
	}
	if !strings.Contains(out.String(), m[0]) {
		t.Fatalf("the line does not name %s: %q", m[0], out.String())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the bad copy is still at its path: %v", err)
	}
}

// A mark the copy cannot write stays in it for this run, and the failure
// is said once per run of failures, then its end.
func TestACopyWriteThatFailsIsSaidOnce(t *testing.T) {
	dir := safeStateDir(t)
	path := filepath.Join(dir, "marks.json")
	alice := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:alice@example.com", At: time.Unix(10, 0).UTC()}
	bob := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:bob@example.com", At: time.Unix(11, 0).UTC()}
	var out bytes.Buffer
	c := openMarksCopy(path, &out)
	if err := os.Chmod(dir, 0o770); err != nil { // the owner check refuses it
		t.Fatal(err)
	}
	c.Apply(store.MarkChange{Revocation: alice, Standing: true})
	c.Apply(store.MarkChange{Revocation: bob, Standing: true})
	if n := strings.Count(out.String(), "port49-broker: store: writing broker.state_dir/marks.json"); n != 1 {
		t.Fatalf("said %d times: %q", n, out.String())
	}
	if got := c.Missing(nil); len(got) != 2 {
		t.Fatalf("the copy lost a mark it could not write: %+v", got)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	carol := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:carol@example.com", At: time.Unix(12, 0).UTC()}
	c.Apply(store.MarkChange{Revocation: carol, Standing: true, Reloaded: true})
	if !strings.Contains(out.String(), "broker.state_dir/marks.json is written again") {
		t.Fatalf("%q", out.String())
	}
	if got := openMarksCopy(path, &out).All(); len(got) != 3 {
		t.Fatalf("after the write came back the file holds %+v", got)
	}
}

// safeStateDir is a broker.state_dir: a 0700 directory of this user's.
func safeStateDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}
