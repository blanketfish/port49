package inventory

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/bundle"
)

func published(t *testing.T, key ed25519.PrivateKey, seq int64, devices ...string) Published {
	t.Helper()
	var inv admission.Inventory
	for i, d := range devices {
		inv.Devices = append(inv.Devices, admission.Device{Name: d, Platform: "arista_eos",
			Addresses: []netip.Addr{netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)})}, Transport: admission.TransportTCP})
	}
	doc := bundle.NewDocument(seq, time.Now(), []byte("scopes: []\n"), "1.1.0", inv, map[string][]string{"a": devices})
	raw, err := bundle.Seal(doc, key)
	if err != nil {
		t.Fatal(err)
	}
	return Published{Raw: raw, Doc: doc, Inv: inv}
}

// stateDir is a state_dir Save creates, 0700 as the service's is: the fence
// refuses one others can write, and t.TempDir follows the umask.
func stateDir(t *testing.T) string { return filepath.Join(t.TempDir(), "state") }

func TestSavedStateIsTheLatestAndKeepsHistory(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	s := State{Dir: stateDir(t), Keep: 2}
	if p, err := s.Latest([]ed25519.PublicKey{pub}); p != nil || err != nil {
		t.Fatalf("empty state: %v %v", p, err)
	}
	for seq := int64(1); seq <= 3; seq++ {
		if err := s.Save(published(t, key, seq, "leaf-01")); err != nil {
			t.Fatal(err)
		}
	}
	keys := []ed25519.PublicKey{pub}
	p, err := s.Latest(keys)
	if err != nil || p.Doc.Sequence != 3 {
		t.Fatalf("latest: %v %v", p, err)
	}
	if _, err := s.At(1, keys); err == nil || !strings.Contains(err.Error(), "bundle 1 is no longer kept") {
		t.Fatalf("pruned: %v", err)
	}
	if p, err := s.At(2, keys); err != nil || p.Doc.Sequence != 2 {
		t.Fatalf("kept: %v %v", p, err)
	}
	fi, _ := os.Stat(filepath.Join(s.Dir, "published.json"))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	// No temporary file is left behind.
	if left, _ := filepath.Glob(filepath.Join(s.Dir, ".tmp-*")); len(left) != 0 {
		t.Fatalf("left %v", left)
	}
}

// State another key signed, or a corrupt file, is an error that names the
// file and quotes nothing from it.
func TestStateThatDoesNotVerifyIsAnError(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	s := State{Dir: stateDir(t), Keep: 2}
	if err := s.Save(published(t, other, 1, "leaf-01")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Latest([]ed25519.PublicKey{pub}); err == nil || !strings.Contains(err.Error(), "published.json") {
		t.Fatalf("got %v", err)
	}
	os.WriteFile(filepath.Join(s.Dir, "published.json"), []byte("SECRET"), 0o600)
	if _, err := s.Latest([]ed25519.PublicKey{pub}); err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("got %v", err)
	}
}

// Every read accepts the keys it is given and no other (pre-flight M6): state
// or a mirror signed by a key outside the list is refused, and an empty list
// accepts nothing.
func TestStateSignedByAnUnlistedKeyIsRefused(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	listed, _, _ := ed25519.GenerateKey(rand.Reader)
	_, unlisted, _ := ed25519.GenerateKey(rand.Reader)
	s := State{Dir: stateDir(t), MirrorDir: t.TempDir(), Keep: 2}
	p := published(t, unlisted, 4, "leaf-01")
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteMirror(p.Raw); err != nil {
		t.Fatal(err)
	}
	for _, keys := range [][]ed25519.PublicKey{{pub, listed}, nil} {
		if _, err := s.Latest(keys); !errors.Is(err, bundle.ErrUnknownKey) {
			t.Fatalf("latest under %d keys: %v", len(keys), err)
		}
		if _, err := s.At(4, keys); !errors.Is(err, bundle.ErrUnknownKey) {
			t.Fatalf("history under %d keys: %v", len(keys), err)
		}
		if _, err := s.Mirror(keys); !errors.Is(err, bundle.ErrUnknownKey) {
			t.Fatalf("mirror under %d keys: %v", len(keys), err)
		}
	}
}

// A rotation keeps the sequence and the history (pre-flight M6): with the old
// public key among the keys, what the old key signed still opens, and the next
// bundle, signed by the new key, carries the sequence on.
func TestARotationKeepsTheSequenceAndTheHistory(t *testing.T) {
	oldPub, oldKey, _ := ed25519.GenerateKey(rand.Reader)
	newPub, newKey, _ := ed25519.GenerateKey(rand.Reader)
	s := State{Dir: stateDir(t), Keep: 5}
	for seq := int64(1); seq <= 2; seq++ {
		if err := s.Save(published(t, oldKey, seq, "leaf-01")); err != nil {
			t.Fatal(err)
		}
	}
	keys := []ed25519.PublicKey{newPub, oldPub}
	last, err := s.Latest(keys)
	if err != nil || last.Doc.Sequence != 2 {
		t.Fatalf("after the rotation: %v %v", last, err)
	}
	if err := s.Save(published(t, newKey, last.Doc.Sequence+1, "leaf-01")); err != nil {
		t.Fatal(err)
	}
	if p, err := s.Latest(keys); err != nil || p.Doc.Sequence != 3 {
		t.Fatalf("latest: %v %v", p, err)
	}
	for seq := int64(1); seq <= 3; seq++ {
		if p, err := s.At(seq, keys); err != nil || p.Doc.Sequence != seq {
			t.Fatalf("history %d: %v %v", seq, p, err)
		}
	}
	// Without the old key the old history is refused, not skipped.
	if _, err := s.At(1, []ed25519.PublicKey{newPub}); !errors.Is(err, bundle.ErrUnknownKey) {
		t.Fatalf("old history under the new key alone: %v", err)
	}
}

func TestTheMirrorRoundTrips(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	s := State{Dir: stateDir(t), MirrorDir: t.TempDir(), Keep: 2}
	if raw, err := s.MirrorRaw(); raw != nil || err != nil {
		t.Fatalf("empty mirror: %v %v", raw, err)
	}
	p := published(t, key, 9, "leaf-01")
	if err := s.WriteMirror(p.Raw); err != nil {
		t.Fatal(err)
	}
	m, err := s.Mirror([]ed25519.PublicKey{pub})
	if err != nil || m.Doc.Sequence != 9 {
		t.Fatalf("%v %v", m, err)
	}
	if raw, err := s.MirrorRaw(); err != nil || string(raw) != string(p.Raw) {
		t.Fatalf("mirror bytes: %v", err)
	}
	if fi, _ := os.Stat(filepath.Join(s.MirrorDir, "bundle.json")); fi.Mode().Perm() != 0o640 {
		t.Fatalf("the mirror copy is mode %v", fi.Mode())
	}
	if m, err := (State{Dir: t.TempDir()}).Mirror([]ed25519.PublicKey{pub}); m != nil || err != nil {
		t.Fatalf("no mirror configured: %v %v", m, err)
	}
}

// A read is bounded before Open: a file past bundle.MaxDocument is refused
// by its size, without being read whole.
func TestAnOversizedStateFileIsRefused(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	path := filepath.Join(t.TempDir(), "bundle.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(bundle.MaxDocument + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := OpenSignedFile(path, []ed25519.PublicKey{pub}); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("got %v", err)
	}
}

// The state is the trust anchor for the sequence, so it is read behind the
// fence: a link in published.json's or a history file's place, or a state
// file others could write, is refused rather than read.
func TestStateBehindALinkOrWritableByOthersIsRefused(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	keys := []ed25519.PublicKey{pub}
	s := State{Dir: stateDir(t), Keep: 5}
	for seq := int64(1); seq <= 2; seq++ {
		if err := s.Save(published(t, key, seq, "leaf-01")); err != nil {
			t.Fatal(err)
		}
	}
	// An older, validly signed copy elsewhere, linked into published.json's
	// place.
	old := filepath.Join(t.TempDir(), "old.json")
	if err := os.WriteFile(old, published(t, key, 1, "leaf-01").Raw, 0o600); err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(s.Dir, "published.json")
	os.Remove(pubPath)
	if err := os.Symlink(old, pubPath); err != nil {
		t.Fatal(err)
	}
	if p, err := s.Latest(keys); err == nil || !strings.Contains(err.Error(), "is a symbolic link") {
		t.Fatalf("a linked published.json: bundle %t, %v", p != nil, err)
	}
	histPath := filepath.Join(s.Dir, "history", "2.json")
	os.Remove(histPath)
	if err := os.Symlink(old, histPath); err != nil {
		t.Fatal(err)
	}
	if p, err := s.At(2, keys); err == nil || !strings.Contains(err.Error(), "is a symbolic link") {
		t.Fatalf("a linked history file: bundle %t, %v", p != nil, err)
	}

	s = State{Dir: stateDir(t), Keep: 5}
	if err := s.Save(published(t, key, 1, "leaf-01")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(s.Dir, "published.json"), 0o620); err != nil {
		t.Fatal(err)
	}
	if p, err := s.Latest(keys); err == nil || !strings.Contains(err.Error(), "writable by others") {
		t.Fatalf("a group-writable published.json: bundle %t, %v", p != nil, err)
	}
	if err := os.Chmod(filepath.Join(s.Dir, "published.json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(s.Dir, 0o770); err != nil {
		t.Fatal(err)
	}
	if p, err := s.Latest(keys); err == nil || !strings.Contains(err.Error(), "writable by others") {
		t.Fatalf("a group-writable state_dir: bundle %t, %v", p != nil, err)
	}
}

// The mirror is a shared mount, trusted by its signature, but its name is
// never followed as a link.
func TestALinkedMirrorIsRefused(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	s := State{Dir: stateDir(t), MirrorDir: t.TempDir()}
	elsewhere := filepath.Join(t.TempDir(), "bundle.json")
	if err := os.WriteFile(elsewhere, published(t, key, 3, "leaf-01").Raw, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(s.MirrorDir, "bundle.json")); err != nil {
		t.Fatal(err)
	}
	if p, err := s.Mirror([]ed25519.PublicKey{pub}); err == nil || !strings.Contains(err.Error(), "is a symbolic link") {
		t.Fatalf("mirror: bundle %t, %v", p != nil, err)
	}
	if raw, err := s.MirrorRaw(); err == nil || raw != nil {
		t.Fatalf("mirror bytes: %v", err)
	}
	if p, err := OpenSignedFile(filepath.Join(s.MirrorDir, "bundle.json"), []ed25519.PublicKey{pub}); err == nil || p != nil {
		t.Fatalf("OpenSignedFile: %v", err)
	}
}

// An older, validly signed document put back in published.json's place does
// not roll the sequence back: Latest refuses it, so the service does not start
// on it, and Save refuses a sequence not above every one kept.
func TestAReplayedOlderStateCannotLowerTheSequence(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	keys := []ed25519.PublicKey{pub}
	s := State{Dir: stateDir(t), Keep: 5}
	for seq := int64(1); seq <= 3; seq++ {
		if err := s.Save(published(t, key, seq, "leaf-01")); err != nil {
			t.Fatal(err)
		}
	}
	old, err := os.ReadFile(filepath.Join(s.Dir, "history", "1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteAtomic(s.Dir, "published.json", old, 0o600); err != nil {
		t.Fatal(err)
	}
	if p, err := s.Latest(keys); err == nil || !strings.Contains(err.Error(), "holds bundle 1") ||
		!strings.Contains(err.Error(), "holds bundle 3") {
		t.Fatalf("replayed: bundle %t, %v", p != nil, err)
	}
	for _, seq := range []int64{2, 3} {
		if err := s.Save(published(t, key, seq, "leaf-01")); err == nil || !strings.Contains(err.Error(), "never goes back") {
			t.Fatalf("save %d: %v", seq, err)
		}
	}
	if err := s.Save(published(t, key, 4, "leaf-01")); err != nil {
		t.Fatal(err)
	}
	if p, err := s.Latest(keys); err != nil || p.Doc.Sequence != 4 {
		t.Fatalf("after 4: %v %v", p, err)
	}
}

// History without published.json is not a fresh install: Latest refuses, so
// the service does not start the sequence again at 1.
func TestHistoryWithoutAPublishedBundleIsRefused(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	s := State{Dir: stateDir(t), Keep: 5}
	for seq := int64(1); seq <= 3; seq++ {
		if err := s.Save(published(t, key, seq, "leaf-01")); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(filepath.Join(s.Dir, "published.json")); err != nil {
		t.Fatal(err)
	}
	if p, err := s.Latest([]ed25519.PublicKey{pub}); err == nil || !strings.Contains(err.Error(), "is missing") ||
		!strings.Contains(err.Error(), "holds bundle 3") {
		t.Fatalf("latest: bundle %t, %v", p != nil, err)
	}
}

// A crash between Save's two writes leaves published.json at N and the
// history at N-1. Another document at N is refused: bundle N is never two
// different documents.
func TestSaveAfterACrashTakesItsFloorFromThePublishedBundle(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	s := State{Dir: stateDir(t), Keep: 5}
	for seq := int64(1); seq <= 2; seq++ {
		if err := s.Save(published(t, key, seq, "leaf-01")); err != nil {
			t.Fatal(err)
		}
	}
	crashed := published(t, key, 3, "leaf-01")
	if err := WriteAtomic(s.Dir, "published.json", crashed.Raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if p, err := s.Latest([]ed25519.PublicKey{pub}); err != nil || p.Doc.Sequence != 3 {
		t.Fatalf("after the crash: bundle %t, %v", p != nil, err)
	}
	if err := s.Save(published(t, key, 3, "leaf-01", "leaf-02")); err == nil ||
		!strings.Contains(err.Error(), "bundle 3 is not above bundle 3") {
		t.Fatalf("another bundle 3: %v", err)
	}
	if err := s.Save(published(t, key, 4, "leaf-01", "leaf-02")); err != nil {
		t.Fatal(err)
	}
	// A published.json that does not parse is no floor of zero.
	if err := WriteAtomic(s.Dir, "published.json", []byte("SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(published(t, key, 5, "leaf-01")); err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("an unparsable published.json: %v", err)
	}
}

// Only a name Save writes is a sequence. A stray file — signed, padded, or not
// a number — is skipped: it neither stops pruning nor sets the floor.
func TestAStrayHistoryNameIsSkipped(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	s := State{Dir: stateDir(t), Keep: 2}
	if err := s.Save(published(t, key, 1, "leaf-01")); err != nil {
		t.Fatal(err)
	}
	stray := []string{"+7.json", "007.json", "-3.json", "0.json", "notes.json", "8"}
	for _, name := range stray {
		if err := os.WriteFile(filepath.Join(s.Dir, "history", name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for seq := int64(2); seq <= 4; seq++ {
		if err := s.Save(published(t, key, seq, "leaf-01")); err != nil {
			t.Fatalf("save %d: %v", seq, err)
		}
	}
	names, err := os.ReadDir(filepath.Join(s.Dir, "history"))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, n := range names {
		got = append(got, n.Name())
	}
	want := []string{"+7.json", "-3.json", "0.json", "007.json", "3.json", "4.json", "8", "notes.json"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("history holds %v, want %v", got, want)
	}
	if p, err := s.Latest([]ed25519.PublicKey{pub}); err != nil || p.Doc.Sequence != 4 {
		t.Fatalf("latest: bundle %t, %v", p != nil, err)
	}
}

func TestSaveWithNoStateDirIsRefused(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	if err := (State{Keep: 2}).Save(published(t, key, 1, "leaf-01")); err == nil ||
		!strings.Contains(err.Error(), "no state_dir") {
		t.Fatalf("got %v", err)
	}
}

// The mirror's sequence never goes back, as state_dir's does not: a copy at
// or above the one written stays, whatever key signed it (review Important 1).
func TestTheMirrorIsNeverWrittenBelowWhatItHolds(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	s := State{Dir: stateDir(t), MirrorDir: t.TempDir()}
	two := published(t, key, 2, "leaf-01", "leaf-02")
	if err := s.WriteMirror(two.Raw); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteMirror(two.Raw); err != nil {
		t.Fatalf("the same copy again: %v", err)
	}
	for _, p := range []Published{published(t, other, 1, "leaf-01"), published(t, other, 2, "leaf-01")} {
		err := s.WriteMirror(p.Raw)
		if err == nil || !strings.Contains(err.Error(), "holds bundle 2") {
			t.Fatalf("bundle %d over bundle 2: %v", p.Doc.Sequence, err)
		}
	}
	if raw, _ := s.MirrorRaw(); string(raw) != string(two.Raw) {
		t.Fatal("the mirror's copy was replaced")
	}
	if err := s.WriteMirror(published(t, other, 3, "leaf-01").Raw); err != nil {
		t.Fatalf("bundle 3: %v", err)
	}
}
