package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/admin"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/fence"
	"github.com/rhwendt/port49/internal/inventory"
	"github.com/rhwendt/port49/internal/store"
)

// revocationsFile is broker.revocations_file (plan 7a): the marks in force,
// so a restart forgets none. snake_case, like every file port49 writes.
type revocationsFile struct {
	Revocations []revocationEntry `json:"revocations"`
}

type revocationEntry struct {
	Kind   string `json:"kind"`
	Key    string `json:"key"`
	At     string `json:"at"`
	Origin string `json:"origin"`
}

const maxRevocationsFile = 1 << 20

// markerOf is the file that says revocations_file was created once, so a
// missing file beside it was lost, not never written (pre-flight C1).
func markerOf(path string) string { return path + ".created" }

// readRevocations reads the file behind the write fence, its own name never
// a link (fence.ReadNoLink): whoever could write it could lift a revocation
// at the next restart. The directory is fenced first, whether or not the
// file is there (fence.CheckDir). A file that is not there is an error,
// always: port49d never creates it (spec §13 decision 32, amended
// 2026-10-02). An unmounted or empty volume that passes the fence would
// otherwise read as a first install and start with no marks; `port49d
// init-revocations` creates it, once. The marker beside it only changes what
// the refusal says: with it, the revocations were lost. Without it, the
// refusal leads with the volume, then the first install (pre-flight M13).
// Anything else it cannot read whole is an error. It writes nothing.
func readRevocations(path string) ([]store.Revocation, error) {
	if err := fence.CheckDir(path, "revocations file"); err != nil {
		return nil, err
	}
	raw, err := fence.ReadNoLink(path, maxRevocationsFile, "revocations file")
	if errors.Is(err, fs.ErrNotExist) {
		switch _, merr := os.Lstat(markerOf(path)); {
		case merr == nil:
			return nil, errors.New(`is missing, and its marker says port49d held revocations here; port49d will ` +
				`not start without them: restore the file, or, if they are truly lost, write {"revocations": []} ` +
				`on purpose`)
		case !errors.Is(merr, fs.ErrNotExist):
			return nil, merr
		}
		return nil, errors.New("does not exist: if port49d has run here before, the volume holding it is missing " +
			"or empty: mount it or restore the file; only on a first install, run 'port49d init-revocations' once, " +
			"as port49d's user, with the same --config")
	}
	if err != nil {
		return nil, err
	}
	var f revocationsFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("does not load as a revocations file (%v); port49d will not start without "+
			`the revocations it holds: restore it, or write {"revocations": []} on purpose`, err)
	}
	out := make([]store.Revocation, 0, len(f.Revocations))
	for i, e := range f.Revocations {
		at, err := time.Parse(time.RFC3339Nano, e.At)
		switch {
		case e.Kind != store.RevocationPrincipal && e.Kind != store.RevocationCert:
			return nil, fmt.Errorf("revocation %d: kind must be principal or cert", i)
		case e.Key == "" || len(e.Key) > 4096 || !utf8.ValidString(e.Key) ||
			strings.IndexFunc(e.Key, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0:
			return nil, fmt.Errorf("revocation %d: its key is empty, too long, or not printable", i)
		case err != nil:
			return nil, fmt.Errorf("revocation %d: at is not an RFC 3339 time", i)
		}
		out = append(out, store.Revocation{Kind: e.Kind, Key: e.Key, At: at, Origin: e.Origin})
	}
	return out, nil
}

// loadRevocations is a start's read (readRevocations), then, when no marker
// is beside the file that loaded (laid down by config management, or
// restored onto a new volume), it writes one, as 7a's start did. That
// creates no revocations file, and it makes the file's later loss refuse
// the start as a loss rather than read as a first install (spec §13
// decision 32; pre-flight M12).
func loadRevocations(path string) ([]store.Revocation, error) {
	rs, err := readRevocations(path)
	if err != nil {
		return nil, err
	}
	switch _, err := os.Lstat(markerOf(path)); {
	case errors.Is(err, fs.ErrNotExist):
		abs, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		if err := writeMarker(abs); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, err
	}
	return rs, nil
}

// markerBody is what the marker beside the file at abs says.
func markerBody(abs string) []byte {
	return []byte("port49d created " + filepath.Base(abs) + " at " + decision.FormatTime(time.Now()) + "\n")
}

// writeMarker writes the marker beside the file at abs, 0600, atomically.
func writeMarker(abs string) error {
	return inventory.WriteAtomic(filepath.Dir(abs), filepath.Base(markerOf(abs)), markerBody(abs), 0o600)
}

// encodeRevocations is the file's content for rs.
func encodeRevocations(rs []store.Revocation) ([]byte, error) {
	f := revocationsFile{Revocations: []revocationEntry{}}
	for _, r := range rs {
		f.Revocations = append(f.Revocations, revocationEntry{Kind: r.Kind, Key: r.Key,
			At: decision.FormatTime(r.At), Origin: r.Origin})
	}
	body, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

// saveRevocations writes rs whole, 0600, atomically: a reader sees the old
// file or the new one.
func saveRevocations(path string, rs []store.Revocation) error {
	body, err := encodeRevocations(rs)
	if err != nil {
		return err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	return inventory.WriteAtomic(filepath.Dir(abs), filepath.Base(abs), body, 0o600)
}

// createExclusive writes body to a new file at abs, 0600, and fails with
// fs.ErrExist if abs is already there: a temporary file beside it is
// written and synced, then linked to the name, which, unlike a rename,
// never replaces a file that appeared after init looked (pre-flight M10).
// The directory is synced, so the name survives a crash.
func createExclusive(abs string, body []byte) error {
	dir := filepath.Dir(abs)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(abs)+".init-*") // 0600
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, werr := tmp.Write(body)
	if werr == nil {
		werr = tmp.Sync()
	}
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return werr
	}
	if err := os.Link(tmp.Name(), abs); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// initRevocations is `port49d init-revocations` (spec §13 decision 32,
// amended): broker.revocations_file created once per install, empty, by the
// user that owns its directory (initOwner, asked first, so a root-run init
// is told to run as that user rather than, by the fence, to chown), behind
// the directory fence a start applies. cfgPath is the config it was read
// from, for the line a refusal gives to run.
//
// created is false, and err nil, when the file is already there and loads:
// nothing is written, so a provisioning step may run it twice (pre-flight
// I6). It refuses a file that is there and does not load, and a marker with
// no file beside it: a loss, which a restore or a deliberate
// {"revocations": []} answers, never a re-created file. Otherwise it
// creates the file, then the marker, each exclusively (initCreate): a crash
// between the two leaves a file with no marker, which the next start loads
// and marks, and the next init finds initialized (task 2 review m1). A file
// that appears before init's own lands is another init's, or one just run:
// this one writes nothing and says so (m3). A marker that appears before
// init's own is a start's, beside the file this init wrote, and stands.
func initRevocations(path, cfgPath string) (created bool, err error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return false, err
	}
	if err := initOwner(filepath.Dir(abs), cfgPath); err != nil {
		return false, err
	}
	if err := fence.CheckDir(abs, "revocations file"); err != nil {
		return false, err
	}
	switch _, err := os.Lstat(abs); {
	case err == nil:
		if _, err := readRevocations(abs); err != nil {
			return false, fmt.Errorf("exists and does not load (%v); init never replaces it", err)
		}
		return false, nil
	case !errors.Is(err, fs.ErrNotExist):
		return false, err
	}
	switch _, err := os.Lstat(markerOf(abs)); {
	case err == nil:
		return false, fmt.Errorf("is missing, and its marker %s says port49d held revocations here: init never "+
			`re-creates a lost file; restore it from backup, or write {"revocations": []} on purpose`, markerOf(abs))
	case !errors.Is(err, fs.ErrNotExist):
		return false, err
	}
	body, err := encodeRevocations(nil)
	if err != nil {
		return false, err
	}
	switch err := initCreate(abs, body); {
	case errors.Is(err, fs.ErrExist):
		return false, errors.New("appeared while this ran: another init-revocations is running or has just run; " +
			"nothing written")
	case err != nil:
		return false, err
	}
	if err := initCreate(markerOf(abs), markerBody(abs)); err != nil && !errors.Is(err, fs.ErrExist) {
		return false, err
	}
	return true, nil
}

// initCreate is initRevocations' exclusive create, swapped in tests to
// race it.
var initCreate = createExclusive

// initRevocationsCmd runs `port49d init-revocations [--config FILE]`. It
// exits 0 having created the file or found it already there and loading, 1
// when it would not, and 2 on usage. It refuses a relative
// broker.revocations_file: that would resolve against this shell's
// directory, and port49d resolves it against its own, so init would create
// a file port49d may never look at (task 2 review m4). A start still takes
// a relative path as Load does.
func initRevocationsCmd(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("port49d init-revocations", flag.ContinueOnError)
	flags.SetOutput(stderr)
	cfgPath := flags.String("config", "/etc/port49/port49d.yaml", "path to port49d.yaml")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: port49d init-revocations [--config FILE]")
		return 2
	}
	raw, err := config.ReadRegular(*cfgPath, config.MaxConfigSize)
	if err != nil {
		fmt.Fprintln(stderr, "port49d init-revocations:", err)
		return 1
	}
	path, err := config.RevocationsFile(raw)
	if err != nil {
		fmt.Fprintln(stderr, "port49d init-revocations:", err)
		return 1
	}
	if !filepath.IsAbs(path) {
		fmt.Fprintf(stderr, "port49d init-revocations: broker.revocations_file %q is relative: it must be absolute, "+
			"since it would resolve against this shell's directory, not port49d's; give an absolute path in "+
			"port49d.yaml\n", path)
		return 1
	}
	abs := filepath.Clean(path)
	cfgAbs, err := filepath.Abs(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "port49d init-revocations:", err)
		return 1
	}
	created, err := initRevocations(abs, cfgAbs)
	switch {
	case err != nil:
		fmt.Fprintf(stderr, "port49d init-revocations: broker.revocations_file %s: %v\n", abs, err)
		return 1
	case !created:
		fmt.Fprintf(stdout, "port49d: broker.revocations_file %s is already initialized; nothing written\n", abs)
		return 0
	}
	fmt.Fprintf(stdout, "port49d: created broker.revocations_file %s with no revocations, and its marker %s; "+
		"run this once per install, never on a start path: from now on port49d refuses to start if the file "+
		"goes missing\n", abs, markerOf(abs))
	return 0
}

// restoreRevocations puts every mark in the file in force in st, before
// the broker serves a request, and returns them for the listener's copy.
// A mark the store refuses (a certificate key with no issuer) is named by
// its index; run names the file.
func restoreRevocations(ctx context.Context, st store.Store, path string) ([]store.Revocation, error) {
	rs, err := loadRevocations(path)
	if err != nil {
		return nil, err
	}
	for i, r := range rs {
		if err := st.PutRevocation(ctx, r); err != nil {
			return nil, fmt.Errorf("revocation %d: %w", i, err)
		}
	}
	return rs, nil
}

// putBackFileMarks is the marks feed's hook before a reload (final review
// 7e-1 C-1): every mark in the file at path that this process enforces and
// the store lacks is put back into st, before the reload reads it, and how
// many is returned. An etcd restore under a running port49d loses every
// mark made since its snapshot, and the reload would take each as lifted:
// a revoked principal would mint again until a restart. A mark the file
// holds and enforced does not was lifted on purpose, on this process or on
// another whose lift the feed delivered, and is not put back. A lift the
// feed did not deliver, made on another process while it was down, cannot
// be told from a mark the restore lost: it is put back, and the caller's
// line says to lift it again.
func putBackFileMarks(ctx context.Context, st store.Store, path string, enforced *store.Marks) (int, error) {
	rs, err := readRevocations(path)
	if err != nil {
		return 0, err
	}
	in, err := st.ListRevocations(ctx)
	if err != nil {
		return 0, err
	}
	stored := map[[2]string]bool{}
	for _, r := range in {
		stored[[2]string{r.Kind, r.Key}] = true
	}
	n := 0
	for i, r := range rs {
		if stored[[2]string{r.Kind, r.Key}] || !enforced.Holds(r.Kind, r.Key) {
			continue
		}
		if err := st.PutRevocation(ctx, r); err != nil {
			return n, fmt.Errorf("revocation %d: %w", i, err)
		}
		n++
	}
	return n, nil
}

// marksReloadHook is port49d's rescanned for the marks feed (store.
// FollowMarks): before a reload reads the store, a mark an etcd restore
// lost is put back from the file at path, not lifted (final review 7e-1
// C-1), and said on out. A put-back that fails (the broker's circuit open
// through the restore, or a file that does not load) refuses the reload:
// the feed is down, said once per run of failures, until it succeeds
// (re-review 1 C-2). Each call counts a rescan.
func marksReloadHook(ctx context.Context, st store.Store, path string, enforced *store.Marks,
	rescans prometheus.Counter, out io.Writer) func() error {
	return func() error {
		rescans.Inc()
		n, err := putBackFileMarks(ctx, st, path, enforced)
		if n > 0 {
			fmt.Fprintf(out, "port49d: broker: %d revocation(s) in broker.revocations_file %s were missing from "+
				"the store (an etcd restore?) and are put back; lift any lifted on purpose with port49 revoke "+
				"--lift\n", n, path)
		}
		if err != nil {
			return fmt.Errorf("broker: putting broker.revocations_file %s's marks back into the store before the "+
				"marks reload: %w; the marks are not reloaded until they are back", path, err)
		}
		return nil
	}
}

// withHeld is rs, the store's marks, and every mark in held (the file's)
// that the store lacks and enforced still holds, sorted by kind and key: a
// mark an etcd restore lost stays in the file until this process lifts it
// or the feed brings its lift (final review 7e-1 C-1). A write between the
// restore and the marks feed's reload, which puts it back from the file
// (putBackFileMarks), would otherwise drop it from both.
func withHeld(rs, held []store.Revocation, enforced *store.Marks) []store.Revocation {
	stored := map[[2]string]bool{}
	for _, r := range rs {
		stored[[2]string{r.Kind, r.Key}] = true
	}
	out := rs
	for _, r := range held {
		if !stored[[2]string{r.Kind, r.Key}] && enforced.Holds(r.Kind, r.Key) {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// writeRevocations is persister's write, swapped in tests; persistDeadline
// bounds one call of it. persistHook is called at the named points where a
// call gives up, so a test can hold it there; it does nothing in port49d.
var (
	writeRevocations = saveRevocations
	persistDeadline  = admin.PersistTimeout // the admin socket holds a revoke open for it
	persistHook      = func(point string) {}
)

// persister is Broker.Persist: it lists every mark in force and writes the
// file, one writer at a time and listing under the slot, so the last write
// holds every mark put before it. held is the file's marks as the start
// read them: a mark the file holds and the store lacks is kept while
// enforced, this process's marks, still holds it (withHeld; nil keeps
// none).
//
// A write to a hung mount (NFS, a blocked disk) blocks in the kernel, and
// Revoke waits on Persist before it deletes the mark's unspent tokens. So
// the write runs in a goroutine that holds the slot until it truly returns,
// and the call gives up at persistDeadline or when ctx ends, reporting the
// file unsaved and raising port49_revocations_file_failed; the mark stands
// in the store and the revocation goes on. A later call waits for the slot
// under its own deadline, so a write abandoned by one call can never land
// after a newer one and drop a mark.
//
// A call that gives up leaves the file behind the store (dirty), and the
// file is caught up without another revocation. Two steps are each taken
// under mu, so neither can fall between the other's parts: a pass's last
// look at dirty together with its giving back the slot and its answer, and
// a call's giving up together with its marking dirty and trying the slot.
// So a call that gives up either finds a pass yet to look, which then lists
// and writes again, or finds the slot free and starts that pass itself.
// The alarm is lowered only by a pass that wrote every mark in force and
// found nothing behind it; a call whose pass answered as its deadline
// struck takes the answer, not the timeout. It never calls Revoke or Lift,
// which hold the semaphore this is called under.
func persister(st store.Store, path string, held []store.Revocation, enforced *store.Marks,
	m *metrics.Metrics) func(context.Context) error {
	slot := make(chan struct{}, 1)
	var mu sync.Mutex // dirty, the alarm, and a pass's last look and release
	dirty := false
	// pass lists and writes, holding the slot, until a pass leaves nothing
	// behind, or one fails; then it gives back the slot and answers done.
	pass := func(ctx context.Context, deadline time.Duration, write func(string, []store.Revocation) error,
		done chan<- error) {
		for {
			mu.Lock()
			dirty = false
			mu.Unlock()
			pctx, cancel := context.WithTimeout(ctx, deadline)
			rs, err := st.ListRevocations(pctx)
			cancel()
			if err == nil {
				rs = withHeld(rs, held, enforced)
				if err = write(path, rs); err == nil {
					held = rs // passes run one at a time, under the slot
				}
			}
			mu.Lock()
			if err == nil && dirty {
				mu.Unlock()
				continue
			}
			if err != nil {
				m.RevocationsFileFailed.Set(1)
			} else {
				m.RevocationsFileFailed.Set(0)
			}
			<-slot
			done <- err // buffered: never blocks
			mu.Unlock()
			return
		}
	}
	return func(ctx context.Context) error {
		deadline, write, hook := persistDeadline, writeRevocations, persistHook // read before any goroutine: tests swap them
		ctx, cancel := context.WithTimeout(ctx, deadline)
		defer cancel()
		// A pass may outlive this call, so each is bounded on its own.
		detached := context.WithoutCancel(ctx)
		select {
		case slot <- struct{}{}:
		case <-ctx.Done():
			hook("slot_wait_gave_up")
			mu.Lock()
			dirty = true
			m.RevocationsFileFailed.Set(1)
			select {
			case slot <- struct{}{}:
				// The pass this call waited behind has finished: nothing
				// else will catch the file up, so this starts it.
				go pass(detached, deadline, write, make(chan error, 1))
			default:
			}
			mu.Unlock()
			return fmt.Errorf("%s: an earlier write has not returned (%w)", path, ctx.Err())
		}
		done := make(chan error, 1)
		go pass(detached, deadline, write, done)
		var err error
		select {
		case err = <-done:
		case <-ctx.Done():
			hook("write_wait_gave_up")
			mu.Lock()
			select {
			case err = <-done: // it answered as the deadline struck: its answer stands
				mu.Unlock()
			default:
				// The pass has yet to take its last look, so it sees this.
				dirty = true
				m.RevocationsFileFailed.Set(1)
				mu.Unlock()
				return fmt.Errorf("%s: the write did not return (%w)", path, ctx.Err())
			}
		}
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		return nil
	}
}

// adminRevoke is the admin socket's revoke op over brk (plan 7a). The
// record's origin is the uid the socket read off the caller.
func adminRevoke(brk *broker.Broker) func(context.Context, admin.RevokeOp) (string, bool, error) {
	return func(ctx context.Context, op admin.RevokeOp) (string, bool, error) {
		req := broker.RevokeRequest{Principal: op.Principal, Issuer: op.Issuer, Serial: op.Serial,
			Origin: fmt.Sprintf("admin_socket uid %d", op.UID)}
		if op.Lift {
			rep, err := brk.Lift(ctx, req)
			if err != nil {
				return "", false, err
			}
			return rep.LiftedText(), rep.Partial(), nil
		}
		rep, err := brk.Revoke(ctx, req)
		if err != nil {
			return "", false, err
		}
		return rep.Text(), rep.Partial(), nil
	}
}

// adminRevocations is the admin socket's revocations op.
func adminRevocations(st store.Store) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		rs, err := st.ListRevocations(ctx)
		if err != nil {
			return "", fmt.Errorf("broker: the revocations in force could not be read (%w)", err)
		}
		return broker.RevocationsText(rs), nil
	}
}
