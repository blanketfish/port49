//go:build linux

package port49d

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"errors"
	"github.com/rhwendt/port49/internal/fence"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
	"path/filepath"
)

// port49d revoke --offline run as a uid that does not own the revocations
// file (root, at 3am) refuses with the owner and the line to run, and changes
// nothing: no mark, no file, no .lock for a port49d running as the owner to
// trip on. The uid is injected, since CI has no second one.
func TestOfflineRevokeAsAnotherUidRefusesAndChangesNothing(t *testing.T) {
	b := brokerConfig(t, minimalPolicy).Broker
	cfgPath := writeRunConfig(t, b)
	other := uint32(os.Geteuid()) + 1
	defer func(g func() int) { fence.Geteuid = g }(fence.Geteuid)
	fence.Geteuid = func() int { return int(other) }
	os.Remove(b.RevocationsFile + ".lock")
	before, _ := os.ReadFile(b.RevocationsFile)
	for _, args := range [][]string{{"--principal", "user:alice@example.com"}, {"--list"}} {
		var log, say bytes.Buffer
		code := offlineRevokeDaemon(append([]string{"--offline", "--config", cfgPath}, args...), &log, &say)
		if code != 1 || !strings.Contains(say.String(), "sudo -u ") ||
			!strings.Contains(say.String(), "port49d revoke --offline --config "+cfgPath) ||
			!strings.Contains(say.String(), "nothing was changed") {
			t.Fatalf("%v: exit %d: %s", args, code, say.String())
		}
		if log.Len() != 0 {
			t.Fatalf("%v: a refused command wrote a decision record", args)
		}
	}
	if after, _ := os.ReadFile(b.RevocationsFile); !bytes.Equal(before, after) {
		t.Fatal("a refused revocation changed broker.revocations_file")
	}
	if _, err := os.Lstat(b.RevocationsFile + ".lock"); err == nil {
		t.Fatal("a refused revocation created the .lock")
	}
}

// The lock sidecar is never followed: a symlink in its place is refused, and
// what it points at is not touched.
func TestASymlinkedLockIsRefused(t *testing.T) {
	file := filepath.Join(safeDir(t), "revocations.json")
	target := filepath.Join(safeDir(t), "victim")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, file+".lock"); err != nil {
		t.Fatal(err)
	}
	release, err := lockRevocations(file)
	if err == nil || errors.Is(err, errRevocationsLocked) || !strings.Contains(err.Error(), "the revocations lock") {
		if release != nil {
			release()
		}
		t.Fatalf("a symlinked .lock: %v", err)
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Fatal("the lock followed the link")
	}
}

// A pass that outlives the call that started it is drained before the lock is
// given up: the drain says no while the write hangs, and yes only once it has
// returned.
func TestADetachedPassIsDrainedBeforeTheUnlock(t *testing.T) {
	ctx := context.Background()
	st := memory.New(time.Now)
	path := filepath.Join(safeDir(t), "revocations.json")
	persist, drain := persisterDrain(st, path, nil, nil, newMetrics())
	release := hangWrites(t, 50*time.Millisecond)
	if err := st.PutRevocation(ctx, store.Revocation{Kind: store.RevocationPrincipal, Key: "user:alice@example.com",
		At: time.Now(), Origin: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := persist(ctx); err == nil {
		t.Fatal("the hung write answered")
	}
	if drain(100 * time.Millisecond) {
		t.Fatal("drained while a pass was still writing")
	}
	release()
	if !drain(5 * time.Second) {
		t.Fatal("did not drain once the write returned")
	}
	rs, err := loadRevocations(path)
	if err != nil || len(rs) != 1 {
		t.Fatalf("the pass finished before the drain answered: %v %v", rs, err)
	}
}
