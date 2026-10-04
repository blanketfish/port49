package port49d

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sync"
	"time"

	"github.com/rhwendt/port49/internal/printsafe"
	etcdstore "github.com/rhwendt/port49/internal/store/etcd"
)

// witnessRecord is this replica's record of the restore witness (plan 7e,
// Ruling 18; re-check R6): the highest ModRevision of meta/witness it has
// seen, followed or written, kept in broker.state_dir/witness.json so it
// outlives an etcd restore. A store whose witness is below it lost writes
// this replica saw. The file is keyed by prefix, not by cluster ID, which
// a restore may or may not keep. Which way it errs: a record lost or old
// only weakens the check; one the store never reached (a witness deleted
// by hand, a state_dir reused against a new keyspace) purges once. A nil
// *witnessRecord is no record.
type witnessRecord struct {
	path, prefix string
	out          io.Writer
	mu           sync.Mutex
	high         uint64
	have         bool
	saved        bool // high is in the file
	failing      bool // the last save failed: said once per run of failures
}

type witnessFile struct {
	Prefix      string `json:"prefix"`
	ModRevision uint64 `json:"mod_revision"`
}

// openWitness reads path. An absent file is no record. A file that cannot
// be read, does not decode, or is another prefix's is no record either,
// and says so; the next save replaces it.
func openWitness(path, prefix string, out io.Writer) *witnessRecord {
	w := &witnessRecord{path: path, prefix: prefix, out: out, saved: true}
	body, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return w
	}
	var f witnessFile
	switch {
	case err != nil:
		fmt.Fprintf(out, "port49-broker: reading %s: %v; no witness record\n", path, err)
	case json.Unmarshal(body, &f) != nil:
		fmt.Fprintf(out, "port49-broker: %s does not decode; no witness record\n", path)
	case f.Prefix != prefix:
		fmt.Fprintf(out, "port49-broker: %s is another prefix's (%s), not %s's; no witness record\n", path,
			printsafe.Line(f.Prefix, 256), prefix)
	default:
		w.high, w.have = f.ModRevision, true
	}
	return w
}

// Saw raises the record to rev and never lowers it: a lower witness is a
// restore's, which the runner judges.
func (w *witnessRecord) Saw(rev uint64) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.have || rev > w.high {
		w.high, w.have, w.saved = rev, true, false
	}
}

// Recorded is the record, and whether there is one.
func (w *witnessRecord) Recorded() (uint64, bool) {
	if w == nil {
		return 0, false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.high, w.have
}

// Reset takes rev as the record, lower or not. The runner calls it once
// its purge after a restore is done, and only then (Ruling 18).
func (w *witnessRecord) Reset(rev uint64) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.high, w.have, w.saved = rev, true, false
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
	if w.saved || !w.have {
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
		return false, "no witness record in broker.state_dir; cannot tell whether the store was restored"
	}
	if read.ModRevision >= recorded {
		return false, ""
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
	rec, have := w.Recorded()
	got, err := read(ctx)
	if err != nil {
		return got, false, "", err
	}
	gone, why := restored(got, rec, have)
	return got, gone, why, nil
}
