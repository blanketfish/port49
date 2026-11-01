package port49d

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/blanketfish/port49/internal/config"
	"github.com/blanketfish/port49/internal/printsafe"
	"github.com/blanketfish/port49/internal/store"
	"github.com/blanketfish/port49/internal/store/crypt"
	etcdstore "github.com/blanketfish/port49/internal/store/etcd"
)

// snapshotEvery is how often a process in a split writes its directory
// snapshot records (plan 11a, R19); a variable so a test can shorten it.
var snapshotEvery = time.Minute

// snapshotCeiling is how old a snapshot may be served (R19):
// session.staleness_ceiling, or its default when it is off; a variable so
// a test can shorten it without shortening the contexts' ceiling.
var snapshotCeiling = func(cfg config.Config) time.Duration {
	if c := cfg.Session.StalenessCeiling; c > 0 {
		return c
	}
	return config.DefaultStalenessCeiling
}

// marksSnapshot is a marks record (ds/m/<writer>): the directory revision
// read before the copy was taken, when the copy was last confirmed, and the
// marks. Every process writes one; port49d reads every one. The store types
// encode by their Go field names: only this code reads it back.
type marksSnapshot struct {
	Writer    string
	Revision  uint64
	Confirmed time.Time
	Marks     []store.Revocation
}

// brokerSnapshot is a broker record (ds/b/<writer>): the logout records and
// the cached pins, which the daemon's role cannot read (N4).
type brokerSnapshot struct {
	Writer    string
	Revision  uint64
	Confirmed time.Time
	Logouts   []store.LogoutEntry
	Pins      []store.Membership
}

// snapshotView is what a start serves from: the union of every record's
// marks (and, for a broker, logouts), the newest broker record's pins, the
// newest confirmed time, and how many records it was made of.
type snapshotView struct {
	marks     []store.Revocation
	logouts   []store.LogoutEntry
	pins      []store.Membership
	confirmed time.Time
	newest    string // the writer of the newest record
	records   int
}

// snapshotSource is a session store's snapshot records (*etcd.Store).
type snapshotSource interface {
	DirectorySnapshots(ctx context.Context, kind string) (map[string][]byte, error)
}

// writerName is this process's snapshot key: proc@host. Two replicas on one
// host share it.
func writerName(proc string) string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		h = "unknown"
	}
	return proc + "@" + h
}

// sealSnapshot seals body as writer's record of kind, bound to its key, so a
// record copied under another key does not open.
func sealSnapshot(keys crypt.Keys, kind, writer string, body any) ([]byte, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return keys.SealBound(raw, []byte("ds/"+kind+"/"+writer))
}

// openSnapshots opens every record of kind in src into fn, skipping one
// that does not open (said by its writer and key id alone) or whose writer
// is not its key's.
func openSnapshots(ctx context.Context, src snapshotSource, keys crypt.Keys, kind string, bound time.Duration,
	out io.Writer, proc string, fn func(writer string, raw []byte) bool) error {
	rctx, cancel := context.WithTimeout(ctx, bound)
	all, err := src.DirectorySnapshots(rctx, kind)
	cancel()
	if err != nil {
		return err
	}
	for w, sealed := range all {
		raw, err := keys.OpenBound(sealed, []byte("ds/"+kind+"/"+w))
		if err != nil || !fn(w, raw) {
			fmt.Fprintf(out, "%s: directory store: the snapshot record %s/%s does not open (key %s); skipped\n", proc,
				kind, printsafe.Line(w, 200), crypt.LineKeyID(crypt.SealedKeyID(sealed)))
		}
	}
	return nil
}

// snapshotSkew is how far ahead of this host's clock a snapshot record's
// Confirmed may be and still be served, as from now: a writer's clock a
// little ahead. One further ahead (a clock far off, or a forged record)
// would read young forever, and R19's ceiling would never bound the serve.
const snapshotSkew = time.Minute

// loadSnapshots is what a start in a cut serves from (R19, N1): the union
// of the marks of every marks record that opens and is younger than
// ceiling, never the newest alone, so a deleted or replayed record lifts
// nothing another record holds. With broker, also the union of every
// broker record's logouts and the newest broker record's pins, and at
// least one broker record is needed. false when nothing young enough opens.
func loadSnapshots(ctx context.Context, src snapshotSource, keys crypt.Keys, broker bool, ceiling,
	bound time.Duration, out io.Writer, proc string) (snapshotView, bool, error) {
	var v snapshotView
	seen := map[[2]string]bool{}
	now := time.Now()
	// young clamps at to now, and is false for one past snapshotSkew ahead,
	// said.
	young := func(kind, w string, at *time.Time) bool {
		if at.After(now.Add(snapshotSkew)) {
			fmt.Fprintf(out, "%s: directory store: the snapshot record %s/%s is confirmed at %s, ahead of this "+
				"host's clock by more than %v; skipped\n", proc, kind, printsafe.Line(w, 200),
				at.UTC().Format(time.RFC3339), snapshotSkew)
			return false
		}
		if at.After(now) {
			*at = now
		}
		return now.Sub(*at) < ceiling
	}
	note := func(w string, at time.Time) {
		v.records++
		if at.After(v.confirmed) {
			v.confirmed, v.newest = at, w
		}
	}
	if err := openSnapshots(ctx, src, keys, etcdstore.SnapshotMarks, bound, out, proc, func(w string, raw []byte) bool {
		var b marksSnapshot
		if json.Unmarshal(raw, &b) != nil || b.Writer != w {
			return false
		}
		if !young(etcdstore.SnapshotMarks, w, &b.Confirmed) {
			return true
		}
		note(w, b.Confirmed)
		for _, r := range b.Marks {
			if k := [2]string{r.Kind, r.Key}; !seen[k] {
				seen[k] = true
				v.marks = append(v.marks, r)
			}
		}
		return true
	}); err != nil {
		return snapshotView{}, false, err
	}
	if v.records == 0 {
		return snapshotView{}, false, nil
	}
	if !broker {
		return v, true, nil
	}
	brokers := 0
	var pinsAt time.Time
	if err := openSnapshots(ctx, src, keys, etcdstore.SnapshotBroker, bound, out, proc, func(w string, raw []byte) bool {
		var b brokerSnapshot
		if json.Unmarshal(raw, &b) != nil || b.Writer != w {
			return false
		}
		if !young(etcdstore.SnapshotBroker, w, &b.Confirmed) {
			return true
		}
		brokers++
		v.logouts = append(v.logouts, b.Logouts...) // LogoutSet.Put keeps the later of a key's
		if b.Confirmed.After(pinsAt) {
			v.pins, pinsAt = b.Pins, b.Confirmed
		}
		return true
	}); err != nil {
		return snapshotView{}, false, err
	}
	return v, brokers > 0, nil
}

// snapFeed is a view's marks as a MarkFeed for one load. It never watches.
type snapFeed struct{ v snapshotView }

func (f snapFeed) Revocations(context.Context) (uint64, []store.Revocation, error) {
	return 1, f.v.marks, nil
}

func (f snapFeed) WatchRevocations(context.Context, uint64, func(r store.Revocation, lifted bool, rev uint64),
	func(rev uint64)) error {
	return fmt.Errorf("%w: a snapshot is not watched", store.ErrUnavailable)
}

// snapshotLine is the start's line for a run that serves from v.
// cause is why the directory did not answer.
func snapshotLine(proc string, v snapshotView, ceiling time.Duration, then string, cause error) string {
	return fmt.Sprintf("%s: directory store: not answering; serving from %d snapshot(s), the newest %s's, confirmed "+
		"%s ago: %d revocation(s) in their union; served until it is %s old (session.staleness_ceiling), then %s; "+
		"the directory store said: %s",
		proc, v.records, printsafe.Line(v.newest, 200), ageText(time.Since(v.confirmed)), len(v.marks), ceiling, then,
		printsafeErr(cause))
}

// noSnapshotLine is the start's line when the directory did not answer and
// no snapshot serves: either none is young enough, or the session store's
// records could not be read (serr).
func noSnapshotLine(proc string, ref storeRef, cause, serr error, ceiling time.Duration) string {
	why := fmt.Sprintf("no snapshot in the session store is younger than session.staleness_ceiling (%s)", ceiling)
	if serr != nil {
		why = fmt.Sprintf("the session store's snapshots could not be read (%s)", printsafeErr(serr))
	}
	return fmt.Sprintf("%s: directory store at %s: not answering (%s); %s", proc, ref.where(), printsafeErr(cause), why)
}

// keepSnapshot writes this process's snapshot records every snapshotEvery
// while its copy is confirmed live (R19), until ctx ends: the directory's
// revision first, then its marks record, and with brokerTake (nil for
// port49d) its broker record. A write that fails is said once until one
// lands.
func keepSnapshot(ctx context.Context, sess *etcdstore.Store, dir *dirHandle, fresh *store.Freshness,
	keys crypt.Keys, writer string, ttl, bound time.Duration, marks func() []store.Revocation,
	brokerTake func(*brokerSnapshot), out io.Writer, proc string) {
	t := time.NewTicker(snapshotEvery)
	defer t.Stop()
	failing := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		d := dir.get()
		at, ok := fresh.Confirmed()
		if reach, _ := fresh.Reachable(); d == nil || !ok || !reach || fresh.Snapshot() {
			continue // only a copy confirmed live is written
		}
		err := func() error {
			rctx, cancel := context.WithTimeout(ctx, bound)
			defer cancel()
			rev, err := d.Revision(rctx)
			if err != nil {
				return err
			}
			sealed, err := sealSnapshot(keys, etcdstore.SnapshotMarks, writer,
				marksSnapshot{Writer: writer, Revision: rev, Confirmed: at, Marks: marks()})
			if err == nil {
				err = sess.PutDirectorySnapshot(rctx, etcdstore.SnapshotMarks, writer, sealed, ttl)
			}
			if err != nil || brokerTake == nil {
				return err
			}
			b := brokerSnapshot{Writer: writer, Revision: rev, Confirmed: at}
			brokerTake(&b)
			if sealed, err = sealSnapshot(keys, etcdstore.SnapshotBroker, writer, b); err != nil {
				return err
			}
			return sess.PutDirectorySnapshot(rctx, etcdstore.SnapshotBroker, writer, sealed, ttl)
		}()
		switch {
		case err != nil && !failing:
			fmt.Fprintf(out, "%s: directory store: the snapshot was not written (%s); the last one written stands\n",
				proc, printsafeErr(err))
			failing = true
		case err == nil:
			failing = false
		}
	}
}

// ceilingErr is the copy's ceiling while it serves a snapshot not yet
// reloaded from the directory (R19, N5): nil before it, the reason after.
func ceilingErr(fresh *store.Freshness, ceiling time.Duration) error {
	if !fresh.Snapshot() {
		return nil
	}
	if age, ok := fresh.Age(); ok && age > ceiling {
		return fmt.Errorf("the snapshot this run serves from is %s old, past session.staleness_ceiling (%s)",
			ageText(age), ceiling)
	}
	return nil
}

// watchCeiling is port49d's ceiling (R19): every second, once the snapshot
// it serves from passes the ceiling, it says so, forgets that it holds a
// cache (dc), and calls gone, which closes the listeners; the next run
// waits for the directory. It returns then, or when ctx ends.
func watchCeiling(ctx context.Context, dc *directoryCache, ceiling time.Duration, gone func(error), out io.Writer) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := ceilingErr(dc.fresh, ceiling); err != nil {
			fmt.Fprintf(out, "port49d: directory store: %v: the listeners close; the next run serves a younger snapshot if the session store holds one, else waits for the directory\n", err)
			dc.loaded.Store(false)
			gone(&storeGone{why: "directory store: " + err.Error()})
			return
		}
	}
}

// sayBrokerCeiling says once, when the snapshot port49-broker serves from
// passes the ceiling, that its mints, refreshes and sign-ins are refused
// until the directory answers; and again for a later snapshot. It returns
// when ctx ends.
func sayBrokerCeiling(ctx context.Context, fresh *store.Freshness, ceiling time.Duration, out io.Writer) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	said := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		err := ceilingErr(fresh, ceiling)
		if err != nil && !said {
			fmt.Fprintf(out, "port49-broker: directory store: %v: mints, refreshes and sign-ins are refused until the "+
				"directory store answers\n", err)
		}
		said = err != nil
	}
}
