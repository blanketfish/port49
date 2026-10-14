// Package enrollfile is store.Enrollments on a sealed file in
// broker.state_dir (plan 9e, spec §13 decision 47 D7): the mark, and every
// second factor with the used-step record, in one file the broker's own
// encryption key seals. It is never created by a start: init-enrollments
// (CreateEnrollmentMark) is its only creator, so a missing file or volume
// reads as a lost store, never as an install with no one enrolled.
package enrollfile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/rhwendt/port49/internal/fence"
	"github.com/rhwendt/port49/internal/inventory"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/crypt"
)

// fileVersion is the envelope's port49_enrollments member.
const fileVersion = 1

// maxFile bounds what Open reads.
const maxFile = 64 << 20

// fileBound is the additional data the file's body is sealed under, so a
// sealed record of another kind is never read as this file.
var fileBound = []byte("enrollments_file")

type envelope struct {
	Version int    `json:"port49_enrollments"`
	KeyID   string `json:"key_id"`
	Sealed  []byte `json:"sealed"` // base64 in JSON
}

// File is store.Enrollments on the file at its path.
type File struct {
	path, dir, base string
	keys            crypt.Keys
	now             func() time.Time

	mu      sync.Mutex
	lost    string // why the file did not open; "" when it did, or none is there
	present bool   // a file is at path: one opened, one that did not, or one written
	mark    *store.EnrollmentMark
	records map[string]store.SecondFactor
	seq     uint64 // the last revision handed out
}

var _ store.Enrollments = (*File)(nil)

// Open reads path (D7). A missing file is an empty store with no mark (which
// the broker reads as lost until init-enrollments); a file that does not
// open is a lost store (every method: store.ErrEnrollmentStoreLost). It
// refuses a directory others can write (fence.CheckDir) and a link at path
// (fence.ReadNoLink). It never creates the file.
func Open(path string, keys crypt.Keys, now func() time.Time) (*File, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err := fence.CheckDir(abs, "enrollments file"); err != nil {
		return nil, err
	}
	f := &File{path: abs, dir: filepath.Dir(abs), base: filepath.Base(abs), keys: keys, now: now,
		records: map[string]store.SecondFactor{}}
	raw, err := fence.ReadNoLink(abs, maxFile, "enrollments file")
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return f, nil
	case err != nil:
		return nil, err
	}
	f.present = true
	body, why := f.open(raw)
	if why != "" {
		f.lost = why
		return f, nil
	}
	f.load(body)
	return f, nil
}

// Lost is why the file did not open, "" when it did.
func (f *File) Lost() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lost
}

// open unseals raw and decodes its body, or says why it cannot.
func (f *File) open(raw []byte) (store.EnrollmentBody, string) {
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil || env.Version != fileVersion {
		return store.EnrollmentBody{}, "it is not an enrollments file this port49 reads (it does not decode, or " +
			"its port49_enrollments member is not 1)"
	}
	plain, err := f.keys.OpenBound(env.Sealed, fileBound)
	switch {
	case errors.Is(err, crypt.ErrUnknownKey):
		return store.EnrollmentBody{}, fmt.Sprintf("it is sealed under key id %q, which this broker does not hold: "+
			"set encryption.previous to it, restore the file, or run `port49 directory reset-second-factor --all`",
			crypt.SealedKeyID(env.Sealed))
	case err != nil:
		return store.EnrollmentBody{}, "it does not unseal (damaged, or changed after it was written): restore " +
			"the file, or run `port49 directory reset-second-factor --all`"
	}
	var b store.EnrollmentBody
	if err := json.Unmarshal(plain, &b); err != nil {
		return store.EnrollmentBody{}, "it unseals and does not load"
	}
	return b, ""
}

// load takes b as the store's content. A body with no creation time holds
// no mark: records, if any, are held, and the broker reads the store as lost.
func (f *File) load(b store.EnrollmentBody) {
	if !b.CreatedAt.IsZero() {
		f.mark = &store.EnrollmentMark{CreatedAt: b.CreatedAt, ReopenAllUntil: b.ReopenAllUntil}
	}
	for p, r := range b.SecondFactors {
		f.records[p] = store.SecondFactorOf(p, r)
		f.seq = max(f.seq, r.Rev)
	}
}

func (f *File) lostErr() error {
	if f.lost == "" {
		return nil
	}
	return fmt.Errorf("%w: %s: %s", store.ErrEnrollmentStoreLost, f.path, f.lost)
}

// body is the content for mark and records, as written.
func body(mark *store.EnrollmentMark, records map[string]store.SecondFactor) store.EnrollmentBody {
	b := store.EnrollmentBody{SecondFactors: make(map[string]store.EnrollmentRecord, len(records))}
	if mark != nil {
		b.CreatedAt, b.ReopenAllUntil = mark.CreatedAt, mark.ReopenAllUntil
	}
	for p, r := range records {
		b.SecondFactors[p] = store.RecordOf(r)
	}
	return b
}

// seal is b as the file keeps it, under the current key.
func (f *File) seal(b store.EnrollmentBody) ([]byte, error) {
	plain, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	sealed, err := f.keys.SealBound(plain, fileBound)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{Version: fileVersion, KeyID: f.keys.Current.ID, Sealed: sealed})
}

// write puts b at path, 0600, atomically. A file opened under the previous
// key is thus sealed under the current one at its first write.
func (f *File) write(b store.EnrollmentBody) error {
	raw, err := f.seal(b)
	if err != nil {
		return err
	}
	return inventory.WriteAtomic(f.dir, f.base, raw, 0o600)
}

func (f *File) GetSecondFactor(_ context.Context, principal string) (store.SecondFactor, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.lostErr(); err != nil {
		return store.SecondFactor{}, err
	}
	r, ok := f.records[principal]
	if !ok {
		return store.SecondFactor{}, store.ErrNotFound
	}
	return clone(r), nil
}

// SwapSecondFactor writes the file with f in place and, only once it is
// written, in memory: a write that fails changes nothing (fail closed).
func (f *File) SwapSecondFactor(_ context.Context, sf store.SecondFactor, rev uint64) error {
	if sf.Principal == "" {
		return store.ErrNoPrincipal
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.lostErr(); err != nil {
		return err
	}
	cur, ok := f.records[sf.Principal]
	if rev == 0 && ok || rev != 0 && (!ok || cur.Rev != rev) {
		return store.ErrConflict
	}
	sf.Rev, sf.Stale = f.seq+1, false
	next := make(map[string]store.SecondFactor, len(f.records)+1)
	for p, r := range f.records {
		next[p] = r
	}
	next[sf.Principal] = clone(sf)
	if err := f.write(body(f.mark, next)); err != nil {
		return fmt.Errorf("enrollfile: writing %s: %w", f.path, err)
	}
	f.seq, f.records, f.present = sf.Rev, next, true
	return nil
}

func (f *File) SecondFactorPrincipals(_ context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.lostErr(); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(f.records))
	for p := range f.records {
		out = append(out, p)
	}
	slices.Sort(out)
	return out, nil
}

func (f *File) GetEnrollmentMark(_ context.Context) (store.EnrollmentMark, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.lostErr(); err != nil {
		return store.EnrollmentMark{}, err
	}
	if f.mark == nil {
		return store.EnrollmentMark{}, store.ErrNotFound
	}
	return *f.mark, nil
}

// CreateEnrollmentMark writes a file holding only m, and refuses
// (store.ErrConflict) where a file is at path, readable or not, or a mark or
// a record is held (init-enrollments, D7). The file is linked into place, so
// one that appears after the look is never replaced.
func (f *File) CreateEnrollmentMark(_ context.Context, m store.EnrollmentMark) error {
	if m.CreatedAt.IsZero() {
		return errors.New("enrollfile: a mark needs its creation time")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.present || f.lost != "" || f.mark != nil || len(f.records) > 0 {
		return store.ErrConflict
	}
	raw, err := f.seal(body(&m, nil))
	if err != nil {
		return err
	}
	switch err := createExclusive(f.dir, f.base, raw); {
	case errors.Is(err, fs.ErrExist):
		f.present = true
		return store.ErrConflict
	case err != nil:
		return fmt.Errorf("enrollfile: creating %s: %w", f.path, err)
	}
	f.mark, f.present = &m, true
	return nil
}

// PutEnrollmentMark writes m, keeping the records, or, where the store is
// lost, replacing it: the unreadable file is renamed aside, never deleted,
// and a fresh file written holding only m.
func (f *File) PutEnrollmentMark(_ context.Context, m store.EnrollmentMark) error {
	if m.CreatedAt.IsZero() {
		return errors.New("enrollfile: a mark needs its creation time")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	records := f.records
	if f.lost != "" {
		if err := f.setAside(); err != nil {
			return err
		}
		records = map[string]store.SecondFactor{}
	}
	if err := f.write(body(&m, records)); err != nil {
		return fmt.Errorf("enrollfile: writing %s: %w", f.path, err)
	}
	f.mark, f.records, f.lost, f.present = &m, records, "", true
	return nil
}

// setAside renames the unreadable file to path.unreadable-<UTC time>: what
// is in it may be all an operator has to restore from.
func (f *File) setAside() error {
	stamp := f.now().UTC().Format("20060102T150405Z")
	to := f.path + ".unreadable-" + stamp
	for i := 2; ; i++ {
		if _, err := os.Lstat(to); errors.Is(err, fs.ErrNotExist) {
			break
		}
		to = fmt.Sprintf("%s.unreadable-%s-%d", f.path, stamp, i)
	}
	if err := os.Rename(f.path, to); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("enrollfile: setting the unreadable %s aside: %w", f.path, err)
	}
	return nil
}

// Export is the envelope of the body with exported_at set, sealed as the
// file is (D13).
func (f *File) Export(_ context.Context) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.lostErr(); err != nil {
		return nil, err
	}
	if f.mark == nil {
		return nil, errors.New("enrollfile: the enrollment store has no creation mark to export")
	}
	b := body(f.mark, f.records)
	b.ExportedAt = f.now().UTC()
	return f.seal(b)
}

// Import opens an export under the held keys and writes it whole, where the
// store holds no record enrolled or reset after the export, or replace
// (D13); a lost store is replaced as PutEnrollmentMark replaces it.
func (f *File) Import(_ context.Context, raw []byte, replace bool) (int, time.Time, error) {
	b, why := f.open(raw)
	if why != "" {
		return 0, time.Time{}, fmt.Errorf("enrollfile: the export does not open: %s", why)
	}
	if b.CreatedAt.IsZero() || b.ExportedAt.IsZero() {
		return 0, time.Time{}, errors.New("enrollfile: the export holds no creation mark or no export time")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lost == "" && !replace {
		for _, r := range f.records {
			if store.EnrolledAfter(store.RecordOf(r), b.ExportedAt) {
				return 0, time.Time{}, store.ErrConflict
			}
		}
	}
	if f.lost != "" {
		if err := f.setAside(); err != nil {
			return 0, time.Time{}, err
		}
	}
	seq := f.seq
	next := make(map[string]store.SecondFactor, len(b.SecondFactors))
	for p, r := range b.SecondFactors {
		seq++ // a fresh revision: no reader's old one matches an imported record
		sf := store.SecondFactorOf(p, r)
		sf.Rev = seq
		next[p] = sf
	}
	mark := store.EnrollmentMark{CreatedAt: b.CreatedAt, ReopenAllUntil: b.ReopenAllUntil}
	if err := f.write(body(&mark, next)); err != nil {
		return 0, time.Time{}, fmt.Errorf("enrollfile: writing %s: %w", f.path, err)
	}
	f.seq, f.records, f.mark, f.lost, f.present = seq, next, &mark, "", true
	return len(next), b.ExportedAt, nil
}

func clone(r store.SecondFactor) store.SecondFactor {
	r.Secret, r.Sealed = slices.Clone(r.Secret), slices.Clone(r.Sealed)
	return r
}

// createExclusive writes raw to a new file dir/base, 0600, and fails with
// fs.ErrExist if base is already there: a temporary file beside it is
// written and synced, then linked to the name, which, unlike a rename,
// never replaces a file that appeared after the look. The directory is
// synced, so the name survives a crash.
func createExclusive(dir, base string, raw []byte) error {
	tmp, err := os.CreateTemp(dir, "."+base+".init-*") // 0600
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, werr := tmp.Write(raw)
	if werr == nil {
		werr = tmp.Sync()
	}
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return werr
	}
	if err := os.Link(tmp.Name(), filepath.Join(dir, base)); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
