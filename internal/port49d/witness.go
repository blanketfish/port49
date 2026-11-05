package port49d

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"sync"
	"time"

	"github.com/blanketfish/port49/internal/printsafe"
	etcdstore "github.com/blanketfish/port49/internal/store/etcd"
)

// witnessRecord is this replica's record of the restore witness (plan 7e,
// Ruling 18; re-check R6): the highest ModRevision of meta/witness it has
// seen, followed or written, kept in broker.state_dir/witness.json so it
// outlives an etcd restore. A store whose witness is below it lost writes
// this replica saw. The file is keyed by prefix, not by cluster ID, which
// a restore may or may not keep. Which way it errs: a record lost or old
// only weakens the check; one the store never reached (a witness deleted
// by hand, a state_dir reused against a new keyspace), or one that cannot
// be read (unreadWitness), purges once. A nil *witnessRecord is no record.
type witnessRecord struct {
	path, prefix string
	out          io.Writer
	mu           sync.Mutex
	high         uint64
	have         bool
	saved        bool // high is in the file
	// owed is set when a check found a purge owed (no record, or a store
	// below it) and stays until Reset, which the purge calls once it is done.
	// While it is set the record takes no revision and saves nothing: a
	// purge cut short is owed again by the next runner on this state_dir,
	// since meta/purged no longer says it was done (decision 56 ruling 2).
	owed    bool
	failing bool // the last save failed: said once per run of failures
}

type witnessFile struct {
	Prefix      string `json:"prefix"`
	ModRevision uint64 `json:"mod_revision"`
}

// unreadWitness is the record of a witness.json that could not be read or
// did not decode: above any witness, so the first check purges once, and
// the purge's Reset replaces it (fix round 1, M-1).
const unreadWitness = math.MaxUint64

// openWitness reads path. An absent file is no record, and so is another
// prefix's, which says so; the next save replaces it. A file that cannot
// be read or does not decode is moved aside to path + ".bad-" + the time,
// as the marks copy's is, and taken as a record above any witness
// (unreadWitness), which keep saves: this replica cannot rule out a
// restore, so the first check, at this start or a later one, purges every
// unspent token once, which costs a re-login, and says why.
func openWitness(path, prefix string, out io.Writer) *witnessRecord {
	w := &witnessRecord{path: path, prefix: prefix, out: out, saved: true}
	// No record is a purge owed from the start, before the follower can tell
	// the record the store's own witness: that would make the first check
	// find nothing to purge (decision 56 ruling 2).
	w.owed = true
	body, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return w
	}
	var f witnessFile
	if err == nil {
		if json.Unmarshal(body, &f) != nil {
			err = errors.New("it does not decode")
		}
	}
	switch {
	case err != nil:
		aside := path + ".bad-" + time.Now().UTC().Format("20060102T150405.000000000Z")
		moved := "moved aside to " + aside
		if rerr := os.Rename(path, aside); rerr != nil {
			moved = fmt.Sprintf("could not be moved aside (%v); it is written over once the purge is done", rerr)
		}
		fmt.Fprintf(out, "port49-broker: reading %s: %v; %s; this replica cannot tell whether the store was "+
			"restored, so the first check purges every unspent token once\n", path, err, moved)
		// Saved, so a restart before the purge still owes it (re-review 1 M-5).
		w.high, w.have, w.saved, w.owed = unreadWitness, true, false, false
	case f.Prefix != prefix:
		fmt.Fprintf(out, "port49-broker: %s is another prefix's (%s), not %s's; no witness record\n", path,
			printsafe.Line(f.Prefix, 256), prefix)
	case f.ModRevision == unreadWitness:
		fmt.Fprintf(out, "port49-broker: %s records that this replica's earlier witness record could not be read; "+
			"the first check purges every unspent token once\n", path)
		w.high, w.have, w.owed = unreadWitness, true, false
	default:
		w.high, w.have, w.owed = f.ModRevision, true, false
	}
	return w
}

// witnessFollowed is told each revision of meta/witness the broker's follower
// gave rec, after rec took it. Only tests swap it, to wait on the follower
// instead of sleeping; it is keyed by the record, not by process, because a
// test process may run several daemons.
var witnessFollowed = func(rec *witnessRecord, rev uint64) {}

// followed is what the broker's FollowWitness calls: Saw, then the hook.
func (w *witnessRecord) followed(rev uint64) {
	w.Saw(rev)
	witnessFollowed(w, rev)
}

// Saw raises the record to rev and never lowers it: a lower witness is a
// restore's, which the runner judges.
func (w *witnessRecord) Saw(rev uint64) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.owed {
		return
	}
	if !w.have || rev > w.high {
		w.high, w.have, w.saved = rev, true, false
	}
}

// Recorded is the record, and whether there is one.
func (w *witnessRecord) Recorded() (uint64, bool) {
	rec, have, _ := w.state()
	return rec, have
}

// state is the record, whether there is one, and whether a purge is owed.
func (w *witnessRecord) state() (rec uint64, have, owed bool) {
	if w == nil {
		return 0, false, false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.high, w.have, w.owed
}

// owe records that a purge is owed, until Reset.
func (w *witnessRecord) owe() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.owed = true
}

// Reset takes rev as the record, lower or not. The runner calls it once
// its purge after a restore is done, and only then (Ruling 18).
func (w *witnessRecord) Reset(rev uint64) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.high, w.have, w.saved, w.owed = rev, true, false, false
}

// keep saves the record, when it changed, once a second and as ctx ends.
func (w *witnessRecord) keep(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			w.save()
			return
		case <-t.C:
			w.save()
		}
	}
}

// save writes the record owner only (writeOwnerOnly), through a temporary
// file renamed into place, as the marks copy is written.
func (w *witnessRecord) save() {
	w.mu.Lock()
	if w.saved || !w.have || w.owed {
		w.mu.Unlock()
		return
	}
	high := w.high
	w.mu.Unlock()
	body, err := json.Marshal(witnessFile{Prefix: w.prefix, ModRevision: high})
	if err == nil {
		err = writeOwnerOnly(w.path, body)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err != nil {
		if !w.failing {
			fmt.Fprintf(w.out, "port49-broker: saving %s: %v; the record is kept in memory and saved again each "+
				"second\n", w.path, err)
		}
		w.failing = true
		return
	}
	w.failing = false
	w.saved = w.high == high
}

// restored judges a read of meta/witness against this replica's record
// (plan 7e, Ruling 18; re-check R6). Only the key's ModRevision counts: a
// restored key keeps its own, with or without --bump-revision, while the
// read's header rises under the bump. why is said when it is not "".
func restored(read etcdstore.WitnessRead, recorded uint64, haveRecord bool) (bool, string) {
	if !haveRecord {
		return true, "no witness record in broker.state_dir; the store may have been restored, which only a " +
			"witness record can tell"
	}
	if read.ModRevision >= recorded {
		return false, ""
	}
	if recorded == unreadWitness {
		return true, "this replica's witness record (broker.state_dir/witness.json) could not be read: the " +
			"store is taken as restored from a snapshot"
	}
	at := fmt.Sprintf("at revision %d", read.ModRevision)
	if read.ModRevision == 0 {
		at = "absent"
	}
	return true, fmt.Sprintf("the store's meta/witness is %s, below the %d this replica saw: the store was "+
		"restored from a snapshot", at, recorded)
}

// readWitness takes the replica's record, then reads meta/witness, and
// judges the read against it (Ruling 18). The record is taken first: a
// linearizable read sees every witness the record held unless the store
// went back, while a record taken after the read may hold a witness
// another runner wrote meanwhile (two runners for a moment, Ruling 6),
// which would purge at a routine handover (final check, Minor 1).
func readWitness(ctx context.Context, w *witnessRecord,
	read func(context.Context) (etcdstore.WitnessRead, error)) (etcdstore.WitnessRead, bool, string, error) {
	rec, have, owed := w.state()
	got, err := read(ctx)
	if err != nil {
		return got, false, "", err
	}
	if w == nil { // a runner built without a record (tests): nothing to judge by
		return got, false, "", nil
	}
	gone, why := restored(got, rec, have)
	if !gone && owed {
		gone, why = true, "an earlier check found a purge owed and it is not yet done"
	}
	if gone {
		w.owe()
	}
	return got, gone, why, nil
}
