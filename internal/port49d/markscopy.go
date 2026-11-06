package port49d

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blanketfish/port49/internal/printsafe"
	"github.com/blanketfish/port49/internal/store"
)

// marksCopy is one port49-broker replica's copy of the revocation marks,
// kept in broker.state_dir/marks.json (plan 7e, Ruling 12; pre-flight I5).
// With broker.revocations_file retired on etcd, an etcd restore lifts
// every mark made since its snapshot, silently, and the copy is what puts
// them back: the runner puts back every mark it holds that the store lacks
// (runner.putBackMissing), and every other replica keeps those in force
// (runner.reloadHook, keepCopied).
//
// It errs toward denying: it adds every mark it is told stands, and drops
// one only on a lift the watch delivered (Apply), never on a reload's
// difference, which may be a restore's loss. So a mark the store lost is
// put back, and so is a mark whose lift this copy missed (lifted on
// another replica and this one stopped before its watch delivered it, or
// while it was stopped, or while its watch was compacted away). A lift made
// on this replica leaves the copy before it is answered
// (Lifted), but three windows remain, each denying more: a reload whose
// list was read before the lift's delete can stand the mark again until the
// watch delivers the delete; the runner's putBackMissing, listing the store
// after the delete's commit and reading the copy before Lifted, puts the
// mark back; and another replica's lift is only the watch's to deliver.
// The put-back line names each put-back and how to lift it.
//
// The file is rewritten on each change, owner only (writeOwnerOnly). A
// write that fails leaves the mark in this run's copy, and is said once
// per run of failures. It is safe for concurrent use. A nil *marksCopy
// holds nothing.
type marksCopy struct {
	path string
	out  io.Writer
	mu   sync.Mutex
	m    map[[2]string]store.Revocation
	// fresh is set when marks.json did not exist at open (a first start, or a
	// state_dir that was lost or is new): the copy then holds only what the
	// marks feed brought from the store, so it cannot put back a mark a
	// restore took from the store. takeFresh reads and clears it.
	fresh bool
	// failing is set while writes fail, so a run of them is said once.
	failing bool
	// lastErr is the last write's error, nil when it landed.
	lastErr error
	// unread is each entry of the file this port49 does not understand, as
	// read, written back unchanged after the marks it does: a downgrade, or
	// a field a newer port49 added, never erases a revocation.
	unread []json.RawMessage
	// lifted is each mark this replica lifted (Lifted), by its time, until
	// the watch delivers the lift or a reload (stand) ends it: the watch's
	// late put of that mark is not added back. A reload may resume past the
	// lift's delete, so it clears every tombstone.
	lifted map[[2]string]time.Time
	// deleted is each key whose lift the watch delivered, or a reload ended
	// the tombstone of, since its last standing put: a Lifted for such a key sets no tombstone, since the
	// watch is not behind, and a later put of it is the store's (another
	// replica's put-back). The one case this gets wrong, a put still in
	// flight behind that delete, keeps the mark, which denies more.
	deleted map[[2]string]bool
}

// marksFile is marks.json: every mark the copy holds, sorted by kind and
// key, then each entry it did not understand, unchanged.
type marksFile struct {
	Marks []json.RawMessage `json:"marks"`
}

type copiedMark struct {
	Kind string    `json:"kind"`
	Key  string    `json:"key"`
	At   time.Time `json:"at"`
}

// wrongOwnerError is ownStateDir's refusal of a path another user owns: the
// start's words are for a service whose directory may be chowned to its
// user, and the offline tool words it for itself (offlineCopy).
type wrongOwnerError struct {
	what      string
	uid, euid uint32
}

func (e *wrongOwnerError) Error() string {
	return fmt.Sprintf("%s is owned by uid %d: port49-broker's own state is kept there, and whoever owns it "+
		"could put back or drop a revocation; it must belong to the user port49-broker runs as (uid %d) or "+
		"to root - chown it", e.what, e.uid, e.euid)
}

// openMarksCopy reads the copy at path. An absent file is an empty copy,
// said: a first start, or a broker.state_dir not kept across restarts,
// whose copy protects nothing (Task 15b review M-6). A file that cannot be
// read or does not decode is said, moved aside to path + ".bad-" + the
// time, and never trusted: the copy starts empty, the store still holds
// every mark it holds, and the start's load fills the copy from the store
// at once. What is lost is a mark an etcd restore had already lost, which
// the line says, with the way back (review M-1). A file that decodes keeps
// every mark it holds that this port49 understands; one it does not (no
// kind it knows, no key, no time: a newer port49's, read after a rollback)
// is skipped alone and named, never discarding the rest, and written back
// unchanged at every write (review M-2).
func openMarksCopy(path string, out io.Writer) *marksCopy {
	c := &marksCopy{path: path, out: out, m: map[[2]string]store.Revocation{}}
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		c.fresh = true
		fmt.Fprintf(out, "port49-broker: store: broker.state_dir/%s is absent: this replica's copy starts from the "+
			"store (a first start; otherwise broker.state_dir is not kept across restarts, and a mark an etcd "+
			"restore lost cannot be put back from it)\n", stateMarksFile)
		return c
	}
	var f marksFile
	if err == nil {
		err = json.Unmarshal(raw, &f)
	}
	if err == nil {
		var skipped []string
		for _, e := range f.Marks {
			var m copiedMark
			if json.Unmarshal(e, &m) != nil || m.Key == "" || m.At.IsZero() ||
				(m.Kind != store.RevocationPrincipal && m.Kind != store.RevocationCert) {
				c.unread = append(c.unread, e)
				skipped = append(skipped, fmt.Sprintf("%q %q", printsafe.Line(m.Kind, 64), printsafe.Line(m.Key, 256)))
				continue
			}
			c.m[[2]string{m.Kind, m.Key}] = store.Revocation{Kind: m.Kind, Key: m.Key, At: m.At}
		}
		if len(skipped) > 0 {
			named := skipped
			if len(named) > 20 {
				named = append(named[:20:20], fmt.Sprintf("and %d more", len(skipped)-20))
			}
			fmt.Fprintf(out, "port49-broker: store: %d mark(s) in broker.state_dir/%s are not understood and are "+
				"skipped (written by a newer port49, or edited by hand): this replica neither enforces nor puts "+
				"them back, and keeps them in the file unchanged; revoke again any the store lacks: %s\n",
				len(skipped), stateMarksFile, strings.Join(named, ", "))
		}
		return c
	}
	aside := path + ".bad-" + time.Now().UTC().Format("20060102T150405.000000000Z")
	moved := "moved aside to " + aside
	back := fmt.Sprintf("if etcd was restored before this start, stop this replica, repair %s and move it back to "+
		"broker.state_dir/%s, then start it; or revoke again each mark another replica's or port49d's \"missing "+
		"from the store\" line names", aside, stateMarksFile)
	if rerr := os.Rename(path, aside); rerr != nil {
		moved = fmt.Sprintf("could not be moved aside (%v); it is written over at the next change", rerr)
		back = "if etcd was restored before this start, revoke again each mark another replica's or port49d's " +
			"\"missing from the store\" line names"
	}
	fmt.Fprintf(out, "port49-broker: store: broker.state_dir/%s does not decode or cannot be read (%v); %s, and "+
		"this replica starts with an empty copy, filled from the store at once: a revocation an etcd restore lost "+
		"before this start cannot be put back from it; %s\n", stateMarksFile, err, moved, back)
	return c
}

// Apply is one change the marks feed told: a mark that stands is added; a
// lift is removed only when the watch delivered it (!ch.Reloaded), never
// when a reload found it missing.
func (c *marksCopy) Apply(ch store.MarkChange) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	k := [2]string{ch.Kind, ch.Key}
	switch {
	case ch.Standing:
		if at, ok := c.lifted[k]; ok && at.Equal(ch.At) {
			return // lifted here already; the watch is behind
		}
		delete(c.deleted, k)
		if cur, ok := c.m[k]; ok && (ch.At.IsZero() || cur.At.Equal(ch.At)) {
			return
		}
		if ch.At.IsZero() {
			return // a mark with no time could not be put back
		}
		c.m[k] = store.Revocation{Kind: ch.Kind, Key: ch.Key, At: ch.At}
	case ch.Reloaded:
		return
	default:
		delete(c.lifted, k)
		if c.deleted == nil {
			c.deleted = map[[2]string]bool{}
		}
		c.deleted[k] = true
		if _, ok := c.m[k]; !ok {
			return
		}
		delete(c.m, k)
	}
	c.write()
}

// Lifted is a lift this replica made and the store committed: r, at its
// time, is dropped and the file written before the lift is answered, so a
// stop before the watch delivers it does not keep or put the mark back. A
// newer mark of the same key (another time) is kept. Until the watch
// delivers the lift or a reload ends it (stand), its late put of r is not
// added back; when the watch already delivered the lift, no such put is
// behind and none is skipped.
func (c *marksCopy) Lifted(r store.Revocation) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	k := [2]string{r.Kind, r.Key}
	if !c.deleted[k] {
		if c.lifted == nil {
			c.lifted = map[[2]string]time.Time{}
		}
		c.lifted[k] = r.At
	}
	if cur, ok := c.m[k]; ok && cur.At.Equal(r.At) {
		delete(c.m, k)
		c.write()
	}
}

// stand adds every mark in rs, the store's at one revision, with one
// write: the start's load, and each reload's.
func (c *marksCopy) stand(rs []store.Revocation) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	changed := false
	// A reload may resume past a lift's delete, so the watch never tells
	// it: the tombstone would outlive its lift and skip a later put-back of
	// the same mark. The reload ends it, and marks the key deleted as the
	// watch's delete would have. One window remains: a Lifted whose delete
	// a reload already resumed past, run after that reload, sets a tombstone
	// nothing ends. It matches only that lifted mark's At, so it can skip
	// putting back the mark the operator lifted, never a later revocation.
	for k := range c.lifted {
		delete(c.lifted, k)
		if c.deleted == nil {
			c.deleted = map[[2]string]bool{}
		}
		c.deleted[k] = true
	}
	for _, r := range rs {
		k := [2]string{r.Kind, r.Key}
		if cur, ok := c.m[k]; r.At.IsZero() || (ok && cur.At.Equal(r.At)) {
			continue
		}
		c.m[k] = store.Revocation{Kind: r.Kind, Key: r.Key, At: r.At}
		changed = true
	}
	if changed {
		c.write()
	}
}

// write rewrites the file from c.m; c.mu is held.
func (c *marksCopy) write() {
	f := marksFile{Marks: []json.RawMessage{}}
	var err error
	for _, r := range c.sorted() {
		var e []byte
		if e, err = json.Marshal(copiedMark{Kind: r.Kind, Key: r.Key, At: r.At}); err != nil {
			break
		}
		f.Marks = append(f.Marks, e)
	}
	f.Marks = append(f.Marks, c.unread...)
	var body []byte
	if err == nil {
		body, err = json.Marshal(f)
	}
	if err == nil {
		err = writeOwnerOnly(c.path, body)
	}
	c.lastErr = err
	switch {
	case err != nil && !c.failing:
		c.failing = true
		fmt.Fprintf(c.out, "port49-broker: store: writing broker.state_dir/%s: %v; the marks stay in this run's "+
			"copy, but a restart loses what was not written, and with it what an etcd restore lost; tried again "+
			"at each change\n", stateMarksFile, err)
	case err == nil && c.failing:
		c.failing = false
		fmt.Fprintf(c.out, "port49-broker: store: broker.state_dir/%s is written again\n", stateMarksFile)
	}
}

// writeErr is the last write's error, nil when it landed.
func (c *marksCopy) writeErr() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastErr
}

// sorted is every mark held, sorted by kind and key; c.mu is held.
func (c *marksCopy) sorted() []store.Revocation {
	out := make([]store.Revocation, 0, len(c.m))
	for _, r := range c.m {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// takeFresh says whether the copy started without a marks.json, once.
func (c *marksCopy) takeFresh() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	f := c.fresh
	c.fresh = false
	return f
}

// Missing is every mark the copy holds that stored lacks, sorted by kind
// and key.
func (c *marksCopy) Missing(stored []store.Revocation) []store.Revocation {
	if c == nil {
		return nil
	}
	in := map[[2]string]bool{}
	for _, r := range stored {
		in[[2]string{r.Kind, r.Key}] = true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []store.Revocation
	for _, r := range c.sorted() {
		if !in[[2]string{r.Kind, r.Key}] {
			out = append(out, r)
		}
	}
	return out
}

// All is every mark the copy holds, sorted by kind and key.
func (c *marksCopy) All() []store.Revocation {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sorted()
}

// copyingFeed is the marks feed port49-broker follows, which tells its
// copy every change the store's watch delivers, and every mark a reload
// reads, as it happens: not the changes FollowMarks tells on, which skips a
// change this process's marks already hold. A revocation or lift made on
// this replica is applied to its marks before the watch delivers it
// (broker.Revoke, Lift), and the copy must see it too. A revocation reaches
// it through the watch; a lift made on this replica, from broker.Lift's
// OnLift hook (Lifted), before it is answered, for a stop before the watch
// delivers it.
type copyingFeed struct {
	store.MarkFeed
	copy *marksCopy
}

// Revocations is the feed's, each mark it read added to the copy: a
// reload's, which drops nothing from it.
func (f copyingFeed) Revocations(ctx context.Context) (uint64, []store.Revocation, error) {
	rev, rs, err := f.MarkFeed.Revocations(ctx)
	if err == nil {
		f.copy.stand(rs)
	}
	return rev, rs, err
}

// WatchRevocations is the feed's, each put and lift applied to the copy
// before fn hears it.
func (f copyingFeed) WatchRevocations(ctx context.Context, after uint64, fn func(store.Revocation, bool, uint64),
	progress func(uint64)) error {
	return f.MarkFeed.WatchRevocations(ctx, after, func(r store.Revocation, lifted bool, rev uint64) {
		f.copy.Apply(store.MarkChange{Revocation: r, Standing: !lifted})
		fn(r, lifted, rev)
	}, progress)
}

// keepCopied keeps in force, in marks, every mark the copy holds that the
// store lacks, and returns them: a replica's start, whose marks were just
// loaded from the store (stored), so a restart never lifts a mark an etcd
// restore lost (plan 7e, Ruling 12). Kept (store.Marks.Keep), a reload
// lifts none of them; the runner's put-back, or a revocation, makes each
// the store's again, and a lift the watch delivers lifts it.
func keepCopied(c *marksCopy, marks *store.Marks, stored []store.Revocation) []store.Revocation {
	missing := c.Missing(stored)
	for _, r := range missing {
		marks.Set(r, true)
		marks.Keep(r)
	}
	return missing
}
