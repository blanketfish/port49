package port49d

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/blanketfish/port49/internal/bundle"
	"github.com/blanketfish/port49/internal/fence"
)

// Ruling 1's second half: the mirror is a shared mount the owner fence
// cannot hold, so a copy group- and world-writable, in a directory the same,
// owned by another user, is still taken — its signature vouches for it.
// Linux only: fence.FileOwner exists there alone, and elsewhere the fence
// refuses every read.
func TestAMirrorCopyTheOwnerFenceWouldRefuseIsTakenOnItsSignature(t *testing.T) {
	svc, key, keys := coldRig(t)
	if err := os.Chmod(svc.MirrorDir, 0o777); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(svc.MirrorDir, "bundle.json")
	mustMirror(t, svc.MirrorDir, sealedDoc(t, key, 5, 2))
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	defer func(o func(fs.FileInfo) (uint32, bool)) { fence.FileOwner = o }(fence.FileOwner)
	fence.FileOwner = func(fs.FileInfo) (uint32, bool) { return uint32(os.Geteuid()) + 1, true }
	if _, err := fence.Read(path, bundle.MaxDocument, "bundle"); err == nil {
		t.Fatal("the fixture passes the owner fence, so it proves nothing")
	}
	e := stderr
	defer func() { stderr = e }()
	stderr = &syncBuffer{}
	p, from, err := coldStart(context.Background(), svc, keys, &fakeService{t: t, forbid: true}, testMetrics(), nil)
	if err != nil || from != "the mirror's copy" || p.Doc.Sequence != 5 {
		t.Fatalf("bundle %d %q %v", seqOf(p), from, err)
	}
}
