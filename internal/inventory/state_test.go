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

func TestSavedStateIsTheLatestAndKeepsHistory(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	s := State{Dir: filepath.Join(t.TempDir(), "state"), Keep: 2}
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
	s := State{Dir: t.TempDir(), Keep: 2}
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
	s := State{Dir: t.TempDir(), MirrorDir: t.TempDir(), Keep: 2}
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
	s := State{Dir: t.TempDir(), Keep: 5}
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
	s := State{Dir: t.TempDir(), MirrorDir: t.TempDir(), Keep: 2}
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
	dir := t.TempDir()
	path := filepath.Join(dir, "published.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(bundle.MaxDocument + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := OpenFile(path, []ed25519.PublicKey{pub}); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("got %v", err)
	}
}
