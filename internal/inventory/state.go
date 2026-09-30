package inventory

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/bundle"
	"github.com/rhwendt/port49/internal/config"
)

// Published is one bundle the service published: the sealed bytes, and what
// they hold.
type Published struct {
	Raw []byte
	Doc bundle.Document
	Inv admission.Inventory
}

// State is what the service keeps (spec §10): the bundle it publishes, so a
// restart serves it and continues its sequence; the last Keep of them by
// sequence, for bundle/diff; and, when MirrorDir is set, the copy daemons read
// at a cold start.
type State struct {
	Dir, MirrorDir string
	Keep           int
}

const (
	publishedName = "published.json"
	historyDir    = "history"
	mirrorName    = "bundle.json"
)

// Save keeps p as the bundle published, then in the history, pruned to the
// newest Keep. published.json is written first: a crash between the two
// loses a diff, never the bundle being served.
func (s State) Save(p Published) error {
	if err := os.MkdirAll(filepath.Join(s.Dir, historyDir), 0o700); err != nil {
		return err
	}
	if err := WriteAtomic(s.Dir, publishedName, p.Raw, 0o600); err != nil {
		return err
	}
	if err := WriteAtomic(filepath.Join(s.Dir, historyDir), strconv.FormatInt(p.Doc.Sequence, 10)+".json", p.Raw,
		0o600); err != nil {
		return err
	}
	seqs, err := s.history()
	if err != nil {
		return err
	}
	for len(seqs) > max(s.Keep, 1) {
		if err := os.Remove(filepath.Join(s.Dir, historyDir, strconv.FormatInt(seqs[0], 10)+".json")); err != nil {
			return err
		}
		seqs = seqs[1:]
	}
	return nil
}

// history is every sequence kept, oldest first.
func (s State) history() ([]int64, error) {
	names, err := os.ReadDir(filepath.Join(s.Dir, historyDir))
	if err != nil {
		return nil, err
	}
	var seqs []int64
	for _, n := range names {
		if seq, err := strconv.ParseInt(strings.TrimSuffix(n.Name(), ".json"), 10, 64); err == nil {
			seqs = append(seqs, seq)
		}
	}
	slices.Sort(seqs)
	return seqs, nil
}

// Latest is the bundle published, or nil when the service has published none.
// keys are every key the service accepts for its own state (pre-flight M6).
func (s State) Latest(keys []ed25519.PublicKey) (*Published, error) {
	return openIfPresent(filepath.Join(s.Dir, publishedName), keys)
}

// At is bundle seq from the history.
func (s State) At(seq int64, keys []ed25519.PublicKey) (*Published, error) {
	p, err := openIfPresent(filepath.Join(s.Dir, historyDir, strconv.FormatInt(seq, 10)+".json"), keys)
	if err == nil && p == nil {
		return nil, fmt.Errorf("bundle %d is no longer kept; the service keeps the last %d", seq, max(s.Keep, 1))
	}
	return p, err
}

// WriteMirror writes the copy daemons read at a cold start (spec §10). 0640:
// the fleet list and its addresses are for the daemons' group, not the
// world (pre-flight minor 7); the deployment gives port49d that group.
func (s State) WriteMirror(raw []byte) error {
	// An empty dir would put the temporary file in os.TempDir.
	if s.MirrorDir == "" {
		return errors.New("inventory: no mirror_dir is set")
	}
	return WriteAtomic(s.MirrorDir, mirrorName, raw, 0o640)
}

// MirrorRaw is the mirror's bytes as they are, or nil with no mirror or no
// copy in it.
func (s State) MirrorRaw() ([]byte, error) {
	if s.MirrorDir == "" {
		return nil, nil
	}
	raw, err := config.ReadRegular(filepath.Join(s.MirrorDir, mirrorName), bundle.MaxDocument)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return raw, err
}

// Mirror is the mirror's copy, or nil with no mirror or no copy in it.
func (s State) Mirror(keys []ed25519.PublicKey) (*Published, error) {
	if s.MirrorDir == "" {
		return nil, nil
	}
	return openIfPresent(filepath.Join(s.MirrorDir, mirrorName), keys)
}

func openIfPresent(path string, keys []ed25519.PublicKey) (*Published, error) {
	p, err := OpenFile(path, keys)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return p, err
}

// OpenFile reads a sealed copy as a regular file of at most
// bundle.MaxDocument bytes and opens it against keys. Its error names the
// file and, from bundle.Open, quotes nothing in it.
func OpenFile(path string, keys []ed25519.PublicKey) (*Published, error) {
	raw, err := config.ReadRegular(path, bundle.MaxDocument)
	if err != nil {
		return nil, err
	}
	doc, inv, err := bundle.Open(raw, keys)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &Published{Raw: raw, Doc: doc, Inv: inv}, nil
}

// WriteAtomic writes body to dir/name so that a reader sees the old file or
// the new one, whole: a temporary file in dir, synced, renamed over name,
// and the directory synced so the rename survives a crash.
func WriteAtomic(dir, name string, body []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(dir, ".tmp-"+name+"-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // after the rename there is nothing here to remove
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(body); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
