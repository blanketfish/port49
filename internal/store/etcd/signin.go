package etcd

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/rhwendt/port49/internal/store"
)

var _ store.Enrollments = (*Store)(nil)

// signInAttemptRec is sa/<key> (plan 9e, D12): the count of one window and
// the window's end.
type signInAttemptRec struct {
	N   int       `json:"n"`
	End time.Time `json:"end"`
}

// NoteSignInAttempt counts one attempt in a fixed window that starts at the
// first, by a compare on the record's revision, so every racer is told its
// own count. The record's lease follows the window's end.
func (s *Store) NoteSignInAttempt(ctx context.Context, key string, window time.Duration) (int, time.Time, error) {
	if key == "" {
		return 0, time.Time{}, store.ErrNoKey
	}
	if window <= 0 {
		return 0, time.Time{}, store.ErrBadTTL
	}
	now := s.now()
	var n int
	var end time.Time
	err := casAs(ctx, s.tok, s.tokLeases, s.k.signInAttempts(key), "sign-in attempt count",
		func(r signInAttemptRec) bool { return now.Before(r.End) },
		func(r *signInAttemptRec, found bool) (bool, time.Time, bool, error) {
			if !found {
				*r = signInAttemptRec{End: now.Add(window)}
			}
			r.N++
			n, end = r.N, r.End
			return true, r.End, false, nil
		})
	if err != nil {
		return 0, time.Time{}, err
	}
	return n, end, nil
}

// UndoSignInAttempt takes one back, never below zero, leaving the record's
// lease as it is.
func (s *Store) UndoSignInAttempt(ctx context.Context, key string) error {
	now := s.now()
	return casAs(ctx, s.tok, s.tokLeases, s.k.signInAttempts(key), "sign-in attempt count",
		func(r signInAttemptRec) bool { return now.Before(r.End) },
		func(r *signInAttemptRec, found bool) (bool, time.Time, bool, error) {
			if !found || r.N <= 0 {
				return false, time.Time{}, false, nil
			}
			r.N--
			return true, time.Time{}, true, nil
		})
}

// ClearSignInAttempts deletes the record and returns the count it held
// (zero for none, or one past its window), in one step: a racing attempt
// is counted before the delete or starts the next window.
func (s *Store) ClearSignInAttempts(ctx context.Context, key string) (int, error) {
	k := s.k.signInAttempts(key)
	for {
		var r signInAttemptRec
		mod, ok, err := getJSONAs(ctx, s.tok, k, "sign-in attempt count", &r)
		if err != nil || !ok {
			return 0, err
		}
		resp, err := s.tok.Txn(ctx).If(unchanged(k, mod)).Then(clientv3.OpDelete(k)).Commit()
		if err != nil {
			return 0, unavailable(err)
		}
		if !resp.Succeeded {
			continue
		}
		if !s.now().Before(r.End) {
			return 0, nil
		}
		return r.N, nil
	}
}

// errNoMarkTime is a mark with no creation time, which an export would emit
// and an import refuse: every backend refuses it at the write.
var errNoMarkTime = errors.New("etcd: a mark needs its creation time")

// enrollmentMarkRec is meta/enrollments (plan 9e, D7).
type enrollmentMarkRec struct {
	CreatedAt      time.Time `json:"created_at"`
	ReopenAllUntil time.Time `json:"reopen_all_until,omitzero"`
	Sealed         []byte    `json:"sealed,omitempty"`
}

func (s *Store) GetSecondFactor(ctx context.Context, principal string) (store.SecondFactor, error) {
	var r store.EnrollmentRecord
	mod, ok, err := getJSONAs(ctx, s.tok, s.k.secondFactor(principal), "second factor", &r)
	switch {
	case err != nil:
		return store.SecondFactor{}, err
	case !ok:
		return store.SecondFactor{}, store.ErrNotFound
	}
	r.Rev = uint64(mod)
	return store.SecondFactorOf(principal, r), nil
}

// SwapSecondFactor writes f in a transaction comparing the record's
// mod_revision to rev (its absence for rev 0), with no lease: an enrollment
// does not lapse.
func (s *Store) SwapSecondFactor(ctx context.Context, f store.SecondFactor, rev uint64) error {
	if f.Principal == "" {
		return store.ErrNoPrincipal
	}
	key := s.k.secondFactor(f.Principal)
	r := store.RecordOf(f)
	r.Rev = 0 // the key's mod_revision is the record's, never the body's
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	cmp := unchanged(key, int64(rev))
	if rev == 0 {
		cmp = clientv3.Compare(clientv3.CreateRevision(key), "=", 0)
	}
	resp, err := s.tok.Txn(ctx).If(cmp).Then(clientv3.OpPut(key, string(body))).Commit()
	if err != nil {
		return unavailable(err)
	}
	if !resp.Succeeded {
		return store.ErrConflict
	}
	return nil
}

func (s *Store) SecondFactorPrincipals(ctx context.Context) ([]string, error) {
	prefix := s.k.family(famSecondFactor)
	resp, err := s.tok.Get(ctx, prefix, clientv3.WithPrefix(), clientv3.WithKeysOnly())
	if err != nil {
		return nil, unavailable(err)
	}
	out := make([]string, 0, len(resp.Kvs))
	for _, kv := range resp.Kvs {
		p, err := url.PathUnescape(strings.TrimPrefix(string(kv.Key), prefix))
		if err != nil {
			return nil, notDecoded("second factor key")
		}
		out = append(out, p)
	}
	slices.Sort(out)
	return out, nil
}

func (s *Store) GetEnrollmentMark(ctx context.Context) (store.EnrollmentMark, error) {
	var r enrollmentMarkRec
	mod, ok, err := getJSONAs(ctx, s.tok, s.k.enrollmentMark(), "enrollment mark", &r)
	switch {
	case err != nil:
		return store.EnrollmentMark{}, err
	case !ok:
		return store.EnrollmentMark{}, store.ErrNotFound
	}
	return store.EnrollmentMark{CreatedAt: r.CreatedAt, ReopenAllUntil: r.ReopenAllUntil, Sealed: r.Sealed,
		Rev: uint64(mod)}, nil
}

// SwapEnrollmentMark writes m if the mark's mod_revision is still rev: a
// reset --all, an import or another re-seal since the read changed it.
func (s *Store) SwapEnrollmentMark(ctx context.Context, m store.EnrollmentMark, rev uint64) error {
	if m.CreatedAt.IsZero() {
		return errNoMarkTime
	}
	if rev == 0 {
		return store.ErrConflict
	}
	body, err := json.Marshal(enrollmentMarkRec{CreatedAt: m.CreatedAt, ReopenAllUntil: m.ReopenAllUntil, Sealed: m.Sealed})
	if err != nil {
		return err
	}
	key := s.k.enrollmentMark()
	resp, err := s.tok.Txn(ctx).If(clientv3.Compare(clientv3.ModRevision(key), "=", int64(rev))).
		Then(clientv3.OpPut(key, string(body))).Commit()
	if err != nil {
		return unavailable(err)
	}
	if !resp.Succeeded {
		return store.ErrConflict
	}
	return nil
}

// CreateEnrollmentMark is one transaction: the mark is written where there
// is no mark and no sf/ record, so init-enrollments never papers over a
// store that lost its mark (D7). A compare over a range holds only when it
// holds for every key in it, and for none it is the compare against an
// absent key.
func (s *Store) CreateEnrollmentMark(ctx context.Context, m store.EnrollmentMark) error {
	if m.CreatedAt.IsZero() {
		return errNoMarkTime
	}
	key := s.k.enrollmentMark()
	body, err := json.Marshal(enrollmentMarkRec{CreatedAt: m.CreatedAt, ReopenAllUntil: m.ReopenAllUntil, Sealed: m.Sealed})
	if err != nil {
		return err
	}
	resp, err := s.tok.Txn(ctx).If(
		clientv3.Compare(clientv3.CreateRevision(key), "=", 0),
		clientv3.Compare(clientv3.CreateRevision(s.k.family(famSecondFactor)), "=", 0).WithPrefix(),
	).Then(clientv3.OpPut(key, string(body))).Commit()
	if err != nil {
		return unavailable(err)
	}
	if !resp.Succeeded {
		return store.ErrConflict
	}
	return nil
}

func (s *Store) PutEnrollmentMark(ctx context.Context, m store.EnrollmentMark) error {
	if m.CreatedAt.IsZero() {
		return errNoMarkTime
	}
	body, err := json.Marshal(enrollmentMarkRec{CreatedAt: m.CreatedAt, ReopenAllUntil: m.ReopenAllUntil, Sealed: m.Sealed})
	if err != nil {
		return err
	}
	_, err = s.tok.Put(ctx, s.k.enrollmentMark(), string(body))
	return unavailable(err)
}

// enrollmentsRead is the mark and every record, read in one transaction: the
// body, whether a mark was there and its mod_revision (0 for none), and the
// store revision of the read.
type enrollmentsRead struct {
	body     store.EnrollmentBody
	haveMark bool
	markMod  int64
	rev      int64
}

func (s *Store) readEnrollments(ctx context.Context) (enrollmentsRead, error) {
	prefix := s.k.family(famSecondFactor)
	resp, err := s.tok.Txn(ctx).Then(clientv3.OpGet(s.k.enrollmentMark()),
		clientv3.OpGet(prefix, clientv3.WithPrefix())).Commit()
	if err != nil {
		return enrollmentsRead{}, unavailable(err)
	}
	out := enrollmentsRead{rev: resp.Header.Revision}
	b := &out.body
	if kvs := resp.Responses[0].GetResponseRange().Kvs; len(kvs) == 1 {
		var m enrollmentMarkRec
		if err := json.Unmarshal(kvs[0].Value, &m); err != nil {
			return out, notDecoded("enrollment mark")
		}
		b.CreatedAt, b.ReopenAllUntil, b.MarkSealed = m.CreatedAt, m.ReopenAllUntil, m.Sealed
		out.haveMark, out.markMod = true, kvs[0].ModRevision
	}
	b.SecondFactors = map[string]store.EnrollmentRecord{}
	for _, kv := range resp.Responses[1].GetResponseRange().Kvs {
		p, err := url.PathUnescape(strings.TrimPrefix(string(kv.Key), prefix))
		if err != nil {
			return out, notDecoded("second factor key")
		}
		var r store.EnrollmentRecord
		if err := json.Unmarshal(kv.Value, &r); err != nil {
			return out, notDecoded("second factor")
		}
		r.Rev = uint64(kv.ModRevision)
		b.SecondFactors[p] = r
	}
	return out, nil
}

// Export is every record and the mark, read in one revision, in the body
// shape the sealed file keeps, unsealed (the sealing layer seals it).
func (s *Store) Export(ctx context.Context) ([]byte, error) {
	read, err := s.readEnrollments(ctx)
	if err != nil {
		return nil, err
	}
	b, haveMark := read.body, read.haveMark
	if !haveMark {
		return nil, errors.New("etcd: the enrollment store has no creation mark to export")
	}
	b.ExportedAt = s.now().UTC()
	return json.Marshal(b)
}

// Import writes the exported records and, last, the mark. One that fits in
// a transaction (maxTxnOps) is atomic. A larger one runs in chunks, and its
// first transaction deletes the mark, so an import cut short is a store with
// records and no mark, which reads as lost (D7) until the import is run
// again: it completes, since no record is newer than the export. The first
// transaction compares that no record and not the mark changed since the
// read the conflict check made. The records go first, with the deletes of
// those the export does not hold, and the mark last.
func (s *Store) Import(ctx context.Context, raw []byte, replace bool) (int, time.Time, error) {
	var b store.EnrollmentBody
	if err := json.Unmarshal(raw, &b); err != nil { // the decoder's text quotes its input: never wrapped
		return 0, time.Time{}, notDecoded("enrollment export")
	}
	if b.CreatedAt.IsZero() || b.ExportedAt.IsZero() {
		return 0, time.Time{}, errors.New("etcd: the export holds no creation mark or no export time")
	}
	read, err := s.readEnrollments(ctx)
	if err != nil {
		return 0, time.Time{}, err
	}
	have, rev := read.body, read.rev
	var ops []clientv3.Op
	for p, r := range b.SecondFactors {
		r.Rev = 0
		body, err := json.Marshal(r)
		if err != nil {
			return 0, time.Time{}, err
		}
		ops = append(ops, clientv3.OpPut(s.k.secondFactor(p), string(body)))
	}
	for p, r := range have.SecondFactors {
		if !replace && store.EnrolledAfter(r, b.ExportedAt) {
			return 0, time.Time{}, store.ErrConflict
		}
		if _, ok := b.SecondFactors[p]; !ok {
			ops = append(ops, clientv3.OpDelete(s.k.secondFactor(p)))
		}
	}
	mark, err := json.Marshal(enrollmentMarkRec{CreatedAt: b.CreatedAt, ReopenAllUntil: b.ReopenAllUntil, Sealed: b.MarkSealed})
	if err != nil {
		return 0, time.Time{}, err
	}
	putMark := clientv3.OpPut(s.k.enrollmentMark(), string(mark))
	unmoved := []clientv3.Cmp{
		clientv3.Compare(clientv3.ModRevision(s.k.family(famSecondFactor)), "<", rev+1).WithPrefix(),
		clientv3.Compare(clientv3.ModRevision(s.k.enrollmentMark()), "=", read.markMod),
	}
	if len(ops)+1 > maxTxnOps {
		// Too large for one transaction: the mark goes in the first, and the
		// put that returns it in the last (etcd refuses both in one).
		ops = append([]clientv3.Op{clientv3.OpDelete(s.k.enrollmentMark())}, ops...)
	}
	ops = append(ops, putMark)
	if s.importHook != nil {
		if err := s.importHook(0); err != nil { // after the read, before the first write
			return 0, time.Time{}, err
		}
	}
	for chunk := 1; len(ops) > 0; chunk++ {
		n := min(len(ops), maxTxnOps)
		txn := s.tok.Txn(ctx)
		switch {
		case chunk == 1:
			txn = txn.If(unmoved...)
		case n == len(ops):
			// The last chunk puts the mark back. The first deleted it, so a
			// mark here was written since, by a reset-second-factor --all on
			// the store the import left lost: it is not overwritten.
			txn = txn.If(clientv3.Compare(clientv3.CreateRevision(s.k.enrollmentMark()), "=", 0))
		}
		resp, err := txn.Then(ops[:n]...).Commit()
		if err != nil {
			return 0, time.Time{}, unavailable(err)
		}
		if !resp.Succeeded {
			return 0, time.Time{}, store.ErrConflict // a record or the mark was written since the read, or a mark since the first chunk
		}
		ops = ops[n:]
		if s.importHook != nil && len(ops) > 0 {
			if err := s.importHook(chunk); err != nil {
				return 0, time.Time{}, err
			}
		}
	}
	return len(b.SecondFactors), b.ExportedAt, nil
}

// unlockRec is ul/<principal> (plan 11a, R15): when an operator last
// cleared the person's failed sign-ins.
type unlockRec struct {
	At time.Time `json:"at"`
}

func (s *Store) GetUnlock(ctx context.Context, principal string) (time.Time, error) {
	var r unlockRec
	_, ok, err := getJSONAs(ctx, s.tok, s.k.unlock(principal), "unlock", &r)
	switch {
	case err != nil:
		return time.Time{}, err
	case !ok:
		return time.Time{}, store.ErrNotFound
	}
	return r.At, nil
}

// PutUnlock advances the unlock by a compare on the key's revision (its
// absence for none), reading again when another write came between: at, or
// a nanosecond after the standing one when at is not later. No lease: an
// unlock is a few bytes per person ever unlocked.
func (s *Store) PutUnlock(ctx context.Context, principal string, at time.Time) error {
	switch {
	case principal == "":
		return store.ErrNoPrincipal
	case at.IsZero():
		return store.ErrBadUnlock
	}
	key := s.k.unlock(principal)
	for {
		var r unlockRec
		mod, ok, err := getJSONAs(ctx, s.tok, key, "unlock", &r)
		if err != nil {
			return err
		}
		next := at
		if ok && !at.After(r.At) {
			next = r.At.Add(time.Nanosecond)
		}
		body, err := json.Marshal(unlockRec{At: next.UTC()})
		if err != nil {
			return err
		}
		cmp := unchanged(key, mod)
		if !ok {
			cmp = clientv3.Compare(clientv3.CreateRevision(key), "=", 0)
		}
		resp, err := s.tok.Txn(ctx).If(cmp).Then(clientv3.OpPut(key, string(body))).Commit()
		if err != nil {
			return unavailable(err)
		}
		if resp.Succeeded {
			return nil
		}
	}
}
