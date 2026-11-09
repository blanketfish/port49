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
	"syscall"
	"time"

	"github.com/blanketfish/port49/internal/fence"
	"github.com/blanketfish/port49/internal/inventory"
	"github.com/blanketfish/port49/internal/printsafe"
	"github.com/blanketfish/port49/internal/store"
	"github.com/blanketfish/port49/internal/store/crypt"
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
	late    bool   // lost was set by a look after Open, at a file that appeared later: the next look retries it
	mark    *store.EnrollmentMark
	records map[string]store.SecondFactor
	unlocks map[string]time.Time
	seq     uint64 // the last revision handed out
	markRev uint64 // the last mark revision handed out
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
	if err := f.read(); err != nil {
		return nil, err
	}
	return f, nil
}

// read loads the file at f.path into f, once: a missing file leaves f an empty store with no mark; one
// that does not open leaves it lost; a link at the path is an error.
func (f *File) read() error {
	raw, err := fence.ReadNoLink(f.path, maxFile, "enrollments file")
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case errors.Is(err, syscall.ELOOP):
		return err // a link at the path: a configuration refusal, as the fence's others
	case err != nil:
		// A file that cannot be read (a restore left it root's at 0600, an
		// I/O error, one over maxFile) does not open: lost, so the broker's
		// other paths keep serving and only password sign-in refuses (D7).
		f.present, f.lost = true, readFailure(f.path, err)+": fix its owner and mode, restore it, or "+
			"run `port49 directory reset-second-factor --all`"
		return nil
	}
	f.present = true
	body, why := f.open(raw)
	if why != "" {
		f.lost = why
		return nil
	}
	f.load(body)
	return nil
}

// pickUpLate reads the path again while this handle holds no file and has written none, or holds one it
// refused when it appeared late: the store is created by another process (init-enrollments runs beside a
// running broker), and a handle that read the path once would otherwise never see it. A file it finds and
// cannot take (a link, an unreadable or foreign one, one sealed under another key) puts the handle in the
// lost state, exactly as one refused at Open, so no write lands over it without the set-aside; late marks
// it for the next look, which reads the path again, so the operator's fix needs no restart. Every write
// calls it first, so a write never lands on a path it has not judged. Under f.mu.
func (f *File) pickUpLate() error {
	if !f.late && (f.present || f.lost != "" || f.mark != nil || len(f.records) > 0) {
		return nil
	}
	raw, err := fence.ReadNoLink(f.path, maxFile, "enrollments file")
	if errors.Is(err, fs.ErrNotExist) {
		if f.late { // the refused file is gone: the handle holds none again
			f.lost, f.late, f.present = "", false, false
		}
		return nil
	}
	why := ""
	if err != nil {
		why = readFailure(f.path, err) + ": fix its owner and mode, or remove a link"
	} else {
		var body store.EnrollmentBody
		if body, why = f.open(raw); why == "" {
			f.present, f.lost, f.late = true, "", false
			f.load(body)
			return nil
		}
	}
	f.present, f.lost, f.late = true, why, true
	return fmt.Errorf("%w: %s: %s; this broker looks again at its next recheck, with no restart", store.ErrEnrollmentStoreLost,
		f.shownPath(), why)
}

// shownPath is the path as a lost reason names it: its last 40 bytes (the
// file name and a few directories; the full path is the operator's own
// configuration), so a deep path never pushes the cause and the remedy past
// the broker's cut (#58).
func (f *File) shownPath() string { return printsafe.Tail(f.path, 40) }

// readFailure is why the file at the path does not read, in words that do
// not repeat the path, which the fence's own error names again (#58).
//
// An error that names another path (a directory above the file that cannot
// be searched) keeps its operation and the tail of that path, so the
// operator checks the directory that failed.
func readFailure(path string, err error) string {
	var pe *fs.PathError
	switch {
	case errors.Is(err, syscall.ELOOP): // first: the link refusal wraps a PathError; reached only from pickUpLate, as read returns ELOOP before it
		return "it is a symbolic link, and the enrollment store is read only as a file of its own"
	case errors.As(err, &pe) && pe.Path != path:
		return "it cannot be read (" + pe.Op + " " + printsafe.Tail(pe.Path, 40) + ": " + pe.Err.Error() + ")"
	case errors.As(err, &pe):
		return "it cannot be read (" + pe.Err.Error() + ")"
	}
	return "it cannot be read (" + err.Error() + ")"
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
		// Short on purpose: with a 64-byte key id (shown by its last 12) and a
		// shown path, the cause and all three remedies fit the broker's
		// 300-byte cut at start and late (#58).
		return store.EnrollmentBody{}, fmt.Sprintf("sealed under key id %q, not held here: set encryption.previous "+
			"to it, restore the file, or run `port49 directory reset-second-factor --all`",
			printsafe.Tail(crypt.SealedKeyID(env.Sealed), 12))
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
		m := f.revised(store.EnrollmentMark{CreatedAt: b.CreatedAt, ReopenAllUntil: b.ReopenAllUntil, Sealed: b.MarkSealed})
		f.mark = &m
	}
	for p, r := range b.SecondFactors {
		f.records[p] = store.SecondFactorOf(p, r)
		f.seq = max(f.seq, r.Rev)
	}
	f.unlocks = b.Unlocks
	if f.unlocks == nil {
		f.unlocks = map[string]time.Time{}
	}
}

func (f *File) lostErr() error {
	if f.lost == "" {
		return nil
	}
	return fmt.Errorf("%w: %s: %s", store.ErrEnrollmentStoreLost, f.shownPath(), f.lost)
}

// body is the content for mark, records and unlocks, as written.
func body(mark *store.EnrollmentMark, records map[string]store.SecondFactor, unlocks map[string]time.Time) store.EnrollmentBody {
	b := store.EnrollmentBody{SecondFactors: make(map[string]store.EnrollmentRecord, len(records)), Unlocks: unlocks}
	if mark != nil {
		b.CreatedAt, b.ReopenAllUntil, b.MarkSealed = mark.CreatedAt, mark.ReopenAllUntil, mark.Sealed
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
	_ = f.pickUpLate() // a refusal is the lost state the checks below judge
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
	_ = f.pickUpLate() // a refusal is the lost state the checks below judge
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
	if err := f.write(body(f.mark, next, f.unlocks)); err != nil {
		return fmt.Errorf("enrollfile: writing %s: %w", f.path, err)
	}
	f.seq, f.records, f.present = sf.Rev, next, true
	return nil
}

func (f *File) SecondFactorPrincipals(_ context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_ = f.pickUpLate() // a refusal is the lost state the checks below judge
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
	if err := f.pickUpLate(); err != nil {
		return store.EnrollmentMark{}, err
	}
	if err := f.lostErr(); err != nil {
		return store.EnrollmentMark{}, err
	}
	if f.mark == nil {
		return store.EnrollmentMark{}, store.ErrNotFound
	}
	return *f.mark, nil
}

// SwapEnrollmentMark writes m, keeping the records, if the mark is still at
// rev. The revision lives in the process alone: a restart reads a mark at a
// new one, so a swap that spans it is refused, which fails safe.
func (f *File) SwapEnrollmentMark(_ context.Context, m store.EnrollmentMark, rev uint64) error {
	if m.CreatedAt.IsZero() {
		return errors.New("enrollfile: a mark needs its creation time")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	_ = f.pickUpLate() // a refusal is the lost state the checks below judge
	if err := f.lostErr(); err != nil {
		return err
	}
	if f.mark == nil || rev == 0 || f.mark.Rev != rev {
		return store.ErrConflict
	}
	m = f.revised(m)
	if err := f.write(body(&m, f.records, f.unlocks)); err != nil {
		return fmt.Errorf("enrollfile: writing %s: %w", f.path, err)
	}
	f.mark = &m
	return nil
}

// revised is m at a fresh mark revision. The caller holds f.mu.
func (f *File) revised(m store.EnrollmentMark) store.EnrollmentMark {
	f.markRev++
	m.Rev, m.Stale = f.markRev, false
	return m
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
	_ = f.pickUpLate() // a refusal is the lost state the checks below judge
	if f.present || f.lost != "" || f.mark != nil || len(f.records) > 0 {
		return store.ErrConflict
	}
	raw, err := f.seal(body(&m, nil, f.unlocks))
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
	m = f.revised(m)
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
	_ = f.pickUpLate() // a refusal is the lost state the checks below judge
	records := f.records
	if f.lost != "" {
		if err := f.setAside(); err != nil {
			return err
		}
		records = map[string]store.SecondFactor{}
	}
	if err := f.write(body(&m, records, f.unlocks)); err != nil {
		return fmt.Errorf("enrollfile: writing %s: %w", f.path, err)
	}
	m = f.revised(m)
	f.mark, f.records, f.lost, f.present, f.late = &m, records, "", true, false
	return nil
}

// setAside renames the unreadable file to path.unreadable-<UTC time>: what
// is in it may be all an operator has to restore from.
func (f *File) setAside() error {
	stamp := f.now().UTC().Format("20060102T150405Z")
	to := f.path + ".unreadable-" + stamp
	for i := 2; ; i++ {
		_, err := os.Lstat(to)
		if errors.Is(err, fs.ErrNotExist) {
			break
		}
		if err != nil { // not "taken": an error here would loop for ever
			return fmt.Errorf("enrollfile: setting the unreadable %s aside: %w", f.path, err)
		}
		to = fmt.Sprintf("%s.unreadable-%s-%d", f.path, stamp, i)
	}
	if err := os.Rename(f.path, to); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("enrollfile: setting the unreadable %s aside: %w", f.path, err)
	}
	return nil
}

// Export is the body with exported_at set, bare: the sealing layer above
// seals it, as it does on every backend, so an export moves between them.
func (f *File) Export(_ context.Context) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_ = f.pickUpLate() // a refusal is the lost state the checks below judge
	if err := f.lostErr(); err != nil {
		return nil, err
	}
	if f.mark == nil {
		return nil, errors.New("enrollfile: the enrollment store has no creation mark to export")
	}
	b := body(f.mark, f.records, nil)
	b.ExportedAt = f.now().UTC()
	return json.Marshal(b)
}

// Import takes a bare export and writes it whole, where the
// store holds no record enrolled or reset after the export, or replace
// (D13); a lost store is replaced as PutEnrollmentMark replaces it.
func (f *File) Import(_ context.Context, raw []byte, replace bool) (int, time.Time, error) {
	var b store.EnrollmentBody
	if err := json.Unmarshal(raw, &b); err != nil { // the decoder's text quotes its input: never wrapped
		return 0, time.Time{}, errors.New("enrollfile: the export does not decode")
	}
	if b.CreatedAt.IsZero() || b.ExportedAt.IsZero() {
		return 0, time.Time{}, errors.New("enrollfile: the export holds no creation mark or no export time")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	_ = f.pickUpLate() // a refusal is the lost state the checks below judge
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
	mark := store.EnrollmentMark{CreatedAt: b.CreatedAt, ReopenAllUntil: b.ReopenAllUntil, Sealed: b.MarkSealed}
	if err := f.write(body(&mark, next, f.unlocks)); err != nil {
		return 0, time.Time{}, fmt.Errorf("enrollfile: writing %s: %w", f.path, err)
	}
	mark = f.revised(mark)
	f.seq, f.records, f.mark, f.lost, f.present, f.late = seq, next, &mark, "", true, false
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

func (f *File) GetUnlock(_ context.Context, principal string) (time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_ = f.pickUpLate() // a refusal is the lost state the checks below judge
	if err := f.lostErr(); err != nil {
		return time.Time{}, err
	}
	at, ok := f.unlocks[principal]
	if !ok {
		return time.Time{}, store.ErrNotFound
	}
	return at, nil
}

// PutUnlock writes the file with the unlock in place and, only once it
// is written, in memory: a write that fails changes nothing.
func (f *File) PutUnlock(_ context.Context, principal string, at time.Time) error {
	switch {
	case principal == "":
		return store.ErrNoPrincipal
	case at.IsZero():
		return store.ErrBadUnlock
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	_ = f.pickUpLate() // a refusal is the lost state the checks below judge
	if err := f.lostErr(); err != nil {
		return err
	}
	if cur, ok := f.unlocks[principal]; ok && !at.After(cur) {
		at = cur.Add(time.Nanosecond)
	}
	next := make(map[string]time.Time, len(f.unlocks)+1)
	for p, t := range f.unlocks {
		next[p] = t
	}
	next[principal] = at.UTC()
	if err := f.write(body(f.mark, f.records, next)); err != nil {
		return fmt.Errorf("enrollfile: writing %s: %w", f.path, err)
	}
	f.unlocks, f.present = next, true
	return nil
}
