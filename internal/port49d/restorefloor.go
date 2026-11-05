package port49d

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/blanketfish/port49/internal/daemon/metrics"
	"github.com/blanketfish/port49/internal/policy"
	"github.com/blanketfish/port49/internal/printsafe"
	"github.com/blanketfish/port49/internal/store"
	etcdstore "github.com/blanketfish/port49/internal/store/etcd"
)

// restoreSkew is the margin on the band's MintedAt cutoff (restoreFloor.
// Restored). MintedAt is the minting broker's clock and the band's start is
// port49d's, read when it found the drop. A token restored from a snapshot
// was minted before the restore, so before that read, but a broker whose
// clock runs ahead stamps it later than port49d's clock then said. The
// cutoff is therefore the read time plus the skew, never less. It is the
// largest clock disagreement port49 tolerates anywhere (broker.identity.
// clock_skew's ceiling, an inventory's published_at lead, OCSP and CRL
// ThisUpdate); spec decision 55 ruling 15.
const restoreSkew = 5 * time.Minute

// restoreFloor is port49d's half of the restore witness (spec decision 56):
// an etcd restore brings back every token redeemed since its snapshot,
// unspent. A token carries the store revision its record was created at
// (store.Token.Revision), and a restore, bumped or not, leaves the store at a
// revision below the one port49d last read. The floor is the header of the
// read that found the drop: a token at or below it is refused token_spent,
// with no clock and no scan of the token family.
//
// Without --bump-revision the restored store's revisions climb through the
// range the old timeline used, so a token a running broker mints after the
// restore may carry a revision below the old high mark. The band covers the
// old range for a token_ttl and restoreSkew after the drop, for tokens minted
// before the drop was found only (Restored). The cost is that a token minted
// in that stretch is refused once too.
//
// A read of the witness that fails holds every redemption store_unavailable
// until one answers (Held). The record outlives the process: it is kept in
// restore.json beside accounting.spool_path, so a restart after a restore
// still tells it, and a restart does not forget the floor.
type restoreFloor struct {
	out io.Writer
	now func() time.Time
	// save writes the record, writeOwnerOnlyAs by default; a test swaps it
	// to fail it.
	save func(path string, body []byte) error

	mu           sync.Mutex
	path, prefix string
	attached     bool

	// The record. witness and header are the highest meta/witness ModRevision
	// and read header since the last drop; witnessHeader is the header of the
	// read that last showed witness (or a lower bound the follower gave it);
	// highHeader is the highest header ever read, across drops.
	witness, header, witnessHeader, highHeader uint64
	floor                                      uint64
	band                                       uint64
	bandFrom, bandUntil                        time.Time
	// unread is a record that could not be read: the first read is a drop.
	unread bool
	// pending is a followed witness no live put can have written; the next
	// pass judges it a drop. Not saved.
	pending bool
	// rev counts changes to the saved record; savedRev is the one on disk.
	rev, savedRev uint64
	saveFailing   bool

	// held is true while no read has answered in this run, or the last one
	// failed.
	held, failing bool
	// detectedAt is the last time a drop was found, kept in the record.
	detectedAt time.Time
	m          *metrics.Metrics
}

// floorFile is restore.json.
type floorFile struct {
	Prefix        string    `json:"prefix"`
	Witness       uint64    `json:"witness"`
	Header        uint64    `json:"header"`
	WitnessHeader uint64    `json:"witness_header"`
	HighHeader    uint64    `json:"high_header"`
	Floor         uint64    `json:"floor"`
	Band          uint64    `json:"band,omitempty"`
	BandFrom      time.Time `json:"band_from,omitzero"`
	BandUntil     time.Time `json:"band_until,omitzero"`
	UnreadRecord  bool      `json:"unread_record,omitempty"`
	DetectedAt    time.Time `json:"detected_at,omitzero"`
}

func newRestoreFloor(out io.Writer, now func() time.Time) *restoreFloor {
	return &restoreFloor{out: out, now: now, save: func(path string, body []byte) error {
		return writeOwnerOnlyAs("accounting.spool_path's directory ", path, body)
	}}
}

// attach opens the record at path, kept for prefix's keyspace. A later run's
// call with the same path and prefix changes nothing; one with another (a
// config reload between runs) opens that keyspace's record afresh. An absent
// record is said once. A
// record of another prefix is no record. One that cannot be read, does not
// decode or is owned by another user is moved aside and makes the first read
// a drop: this port49d cannot rule out a restore.
func (f *restoreFloor) attach(path, prefix string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.attached && f.path == path && f.prefix == prefix {
		return
	}
	if f.attached {
		f.witness, f.header, f.witnessHeader, f.highHeader, f.floor, f.band = 0, 0, 0, 0, 0, 0
		f.bandFrom, f.bandUntil, f.detectedAt, f.unread, f.pending = time.Time{}, time.Time{}, time.Time{}, false, false
	}
	f.attached, f.path, f.prefix = true, path, prefix
	body, err := readOwnerOnly(path)
	var rec floorFile
	if err == nil && body != nil {
		switch {
		case json.Unmarshal(body, &rec) != nil:
			err = errors.New("it does not decode")
		case rec.Prefix == "" || rec.Witness == 0 && rec.Header == 0 && !rec.UnreadRecord:
			// Valid JSON that is no record ({}, null, a prefix alone) is
			// not read as one: that would be no record at all.
			err = errors.New("it holds no record")
		}
	}
	switch {
	case err != nil:
		aside := path + ".bad-" + time.Now().UTC().Format("20060102T150405.000000000Z")
		moved := "moved aside to " + aside
		if rerr := os.Rename(path, aside); rerr != nil {
			moved = fmt.Sprintf("could not be moved aside (%v); it is written over at the next save", rerr)
		}
		fmt.Fprintf(f.out, "port49d: store: reading %s: %v; %s; this port49d cannot tell whether the store was "+
			"restored, so its first read of the store is taken as a restore: every token in the store is refused "+
			"(token_spent) once\n", path, err, moved)
		f.unread = true
		f.rev++
	case body == nil:
		fmt.Fprintf(f.out, "port49d: store: no restore record at %s: a restore made before this port49d's first read "+
			"of the store cannot be told; start a broker first after a restore (design §13)\n", path)
	case rec.Prefix != prefix:
		fmt.Fprintf(f.out, "port49d: store: %s is another prefix's (%s), not %s's; no restore record\n", path,
			printsafe.Line(rec.Prefix, 256), prefix)
	default:
		f.witness, f.header, f.witnessHeader, f.highHeader = rec.Witness, rec.Header, rec.WitnessHeader, rec.HighHeader
		f.floor, f.band, f.bandFrom, f.bandUntil, f.unread = rec.Floor, rec.Band, rec.BandFrom, rec.BandUntil, rec.UnreadRecord
		f.detectedAt = rec.DetectedAt
		f.savedRev = f.rev
	}
}

// begin starts a run: m is its registry. Redemptions wait for the run's first
// read (held), and the gauge the process holds is set again.
func (f *restoreFloor) begin(m *metrics.Metrics) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m, f.held, f.failing = m, true, false
	f.gauges()
}

// gauges sets the run's gauges; f.mu is held.
func (f *restoreFloor) gauges() {
	if f.m == nil {
		return
	}
	f.m.RedemptionRestoreUnjudged.Set(b2f(f.held))
	if f.detectedAt.IsZero() {
		f.m.StoreRestoreDetected.Set(0)
	} else {
		f.m.StoreRestoreDetected.Set(float64(f.detectedAt.Unix()))
	}
}

// Held reports that no read of the store's witness has answered in this run,
// or the last failed: every redemption is refused store_unavailable.
func (f *restoreFloor) Held() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.held
}

// Restored reports that t came back with a restore: its revision is at or
// below the floor, or inside the band while the band lasts and t was minted
// before the drop was found. A token with no revision (a wrapper dropped it)
// is below any floor. The token's MintedAt counts only for the band.
func (f *restoreFloor) Restored(t store.Token, now time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.floor != 0 && t.Revision <= f.floor {
		return true
	}
	return f.band != 0 && now.Before(f.bandUntil) && t.Revision <= f.band && !t.MintedAt.After(f.bandFrom.Add(restoreSkew))
}

// floorFollowed is told each revision of meta/witness port49d's follower gave
// f, after f took it, and floorPassed each completed pass of f. Only tests
// swap them, to wait on port49d's floor instead of sleeping; both are keyed by
// the floor, not by process, because a test process may run several daemons.
var (
	floorFollowed = func(f *restoreFloor, rev uint64) {}
	floorPassed   = func(f *restoreFloor) {}
)

// followed is what port49d's FollowWitness calls: Saw, then the hook.
func (f *restoreFloor) followed(rev uint64) {
	f.Saw(rev)
	floorFollowed(f, rev)
}

// Saw takes a witness the follower gave. It never judges and never lowers.
// A rev above the witness and above the header the witness was read at is a
// live put: the witness rises. One above the witness and at or below that
// header cannot be a live put (the store was at the header already), so the
// next pass judges a drop. A rev below the witness is a late watch event, and
// one equal to it is the same record: nothing changes. Without the pending
// rule the follower could raise the witness to a restored value before the
// pass reads it, and the pass would see no change.
func (f *restoreFloor) Saw(rev uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case f.witness == 0 && f.header == 0 && f.witnessHeader == 0:
		f.witness, f.witnessHeader = rev, rev
		f.rev++
	case rev > f.witness && rev > f.witnessHeader:
		f.witness, f.witnessHeader = rev, rev
		f.rev++
	case rev > f.witness:
		f.pending = true
	}
}

// floorSnap is the record taken before a read (judge): a witness followed
// while the read is in flight is newer than the read, not proof of a drop.
type floorSnap struct {
	witness, header, witnessHeader uint64
	have, unread, pending          bool
}

func (f *restoreFloor) record() floorSnap {
	f.mu.Lock()
	defer f.mu.Unlock()
	return floorSnap{witness: f.witness, header: f.header, witnessHeader: f.witnessHeader,
		have: f.witness != 0 || f.header != 0, unread: f.unread, pending: f.pending}
}

// judge is one read of the store's witness (RestoreRead), or its error, as
// seen against the record s taken before it.
func (f *restoreFloor) judge(s floorSnap, r etcdstore.RestoreRead, err error) {
	f.mu.Lock()
	if f.m != nil {
		outcome := "ok"
		if err != nil {
			outcome = "error"
		}
		f.m.StoreOps.WithLabelValues("restore_read", outcome).Inc()
	}
	if err != nil {
		// A failed read is no restore, but the outage may be one: redemptions
		// wait for a read that answers.
		if !f.failing {
			fmt.Fprintf(f.out, "port49d: store: reading meta/witness, to tell whether the store was restored: %v; "+
				"token redemptions are refused (store_unavailable) until a read answers; tried again every %v\n", err,
				witnessEvery)
		}
		f.held, f.failing = true, true
		f.gauges()
		f.mu.Unlock()
		return
	}
	f.held, f.failing = false, false
	drop := s.unread || s.pending || s.have && (r.Witness < s.witness || r.Header < s.header ||
		r.Witness != s.witness && r.Witness <= s.witnessHeader)
	if drop {
		f.drop(s, r)
	} else {
		f.take(s, r)
	}
	f.gauges()
	f.mu.Unlock()
	f.saveIfDirty() // a drop is saved at once
}

// take folds a read that is no drop into the record; f.mu is held.
func (f *restoreFloor) take(s floorSnap, r etcdstore.RestoreRead) {
	was := [4]uint64{f.witness, f.header, f.witnessHeader, f.highHeader}
	// A read at header H that shows witness W says the store was at H with W
	// in it, so no live put makes another witness at or below H: the header
	// of the read that last showed the witness only rises.
	switch {
	case r.Witness > f.witness:
		f.witness, f.witnessHeader = r.Witness, r.Header
	case r.Witness == f.witness:
		f.witnessHeader = max(f.witnessHeader, r.Header)
	}
	f.header = max(f.header, r.Header)
	f.highHeader = max(f.highHeader, r.Header)
	if was != [4]uint64{f.witness, f.header, f.witnessHeader, f.highHeader} {
		f.rev++
	}
}

// drop is a read that found the store restored: the floor becomes the read's
// header and the band is armed; f.mu is held.
func (f *restoreFloor) drop(s floorSnap, r etcdstore.RestoreRead) {
	now := f.now()
	f.floor = r.Header
	f.band, f.bandFrom, f.bandUntil = 0, time.Time{}, time.Time{}
	if band := max(r.Header, f.highHeader); band > f.floor {
		f.band, f.bandFrom, f.bandUntil = band, now, now.Add(policy.MaxTokenTTL+restoreSkew)
	}
	f.witness, f.header, f.witnessHeader = r.Witness, r.Header, r.Header
	f.highHeader = max(f.highHeader, r.Header)
	f.pending, f.unread = false, false
	f.detectedAt = now
	f.rev++

	from := "an unknown record"
	if s.have {
		from = fmt.Sprintf("a record of witness %s at revision %d", witnessWords(s.witness), s.header)
	}
	fmt.Fprintf(f.out, "port49d: store: the session store was restored from a snapshot: meta/witness is %s at revision "+
		"%d, from %s. Tokens at or below revision %d are refused (token_spent) and their users mint again; a token "+
		"minted after this read is served; tokens minted since the restore and before this read are refused once "+
		"too.", witnessWords(r.Witness), r.Header, from, f.floor)
	if f.band != 0 {
		fmt.Fprintf(f.out, " The restore kept the revision counter, so a token minted before this read at a revision "+
			"up to %d is refused until %s; restore with --bump-revision (design §13) to end that.", f.band,
			f.bandUntil.UTC().Format(time.RFC3339))
	}
	fmt.Fprintln(f.out, " Revocations and marks made after the snapshot are lost: follow the restore runbook (design §13)")
}

func witnessWords(rev uint64) string {
	if rev == 0 {
		return "absent"
	}
	return fmt.Sprintf("at revision %d", rev)
}

// saveIfDirty writes the record when it changed since the last save. A write
// that fails is said once per run of failures; the record is kept in memory
// and the next call tries again.
func (f *restoreFloor) saveIfDirty() {
	f.mu.Lock()
	if f.path == "" || f.rev == f.savedRev {
		f.mu.Unlock()
		return
	}
	rev := f.rev
	body, err := json.Marshal(floorFile{Prefix: f.prefix, Witness: f.witness, Header: f.header,
		WitnessHeader: f.witnessHeader, HighHeader: f.highHeader, Floor: f.floor, Band: f.band,
		BandFrom: f.bandFrom, BandUntil: f.bandUntil, UnreadRecord: f.unread, DetectedAt: f.detectedAt})
	path := f.path
	f.mu.Unlock()
	if err == nil {
		err = f.save(path, body)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err != nil {
		if !f.saveFailing {
			fmt.Fprintf(f.out, "port49d: store: saving %s: %v; the restore record is kept in memory and saved again "+
				"each second; a restart before it is saved cannot tell a restore\n", path, err)
		}
		f.saveFailing = true
		return
	}
	f.saveFailing = false
	f.savedRev = rev
}

// keep follows meta/witness, reads it every witnessEvery, each read given the
// store's own deadline (the longer of witnessEvery and callTimeout), and saves
// the record each second, until ctx ends: the watch alone can wait at a
// revision a store restored without --bump-revision has not reached, and never
// tell.
func (f *restoreFloor) keep(ctx context.Context, s *etcdstore.Store, callTimeout time.Duration) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); s.FollowWitness(ctx, f.followed) }()
	defer wg.Wait()
	read, save := time.NewTicker(witnessEvery), time.NewTicker(time.Second)
	defer read.Stop()
	defer save.Stop()
	for {
		select {
		case <-ctx.Done():
			f.saveIfDirty()
			return
		case <-save.C:
			f.saveIfDirty()
		case <-read.C:
			f.pass(ctx, callTimeout, s.RestoreRead)
		}
	}
}

// pass is one read and its judgment: the record is taken before the read, so
// a witness followed while it is in flight is no drop. It reports false once
// ctx ended, with nothing judged.
func (f *restoreFloor) pass(ctx context.Context, callTimeout time.Duration,
	read func(context.Context) (etcdstore.RestoreRead, error)) bool {
	s := f.record()
	rctx, cancel := context.WithTimeout(ctx, max(witnessEvery, callTimeout))
	r, err := read(rctx)
	cancel()
	if ctx.Err() != nil {
		return false
	}
	f.judge(s, r, err)
	floorPassed(f)
	return true
}
