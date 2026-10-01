package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/rhwendt/port49/internal/broker"
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

// loadRevocations reads the file behind the write fence, its own name never
// a link (fence.ReadNoLink): whoever could write it could lift a revocation
// at the next restart. The directory is fenced first, whether or not the
// file is there (fence.CheckDir): a missing directory, or one others can
// write, refuses the start. With neither the file nor its marker present it
// is the first start: the marker is written, then an empty file, and
// created is true. With the marker present a missing file refuses the
// start. A file that loads with no marker beside it (laid down by config
// management, or restored from a backup onto a new volume) is given one, so
// its later loss refuses the start too rather than reading as a first
// install. Anything else it cannot read whole is an error, which refuses it.
func loadRevocations(path string) ([]store.Revocation, bool, error) {
	if err := fence.CheckDir(path, "revocations file"); err != nil {
		return nil, false, err
	}
	raw, err := fence.ReadNoLink(path, maxRevocationsFile, "revocations file")
	if errors.Is(err, fs.ErrNotExist) {
		switch _, merr := os.Lstat(markerOf(path)); {
		case merr == nil:
			return nil, false, errors.New(`is missing; port49d will not start without the revocations it held: ` +
				`restore it, or write {"revocations": []} on purpose`)
		case !errors.Is(merr, fs.ErrNotExist):
			return nil, false, merr
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			return nil, false, err
		}
		// The marker first: a crash between the two leaves a marker and no
		// file, which refuses the next start, never one that reads as new.
		if err := writeMarker(abs); err != nil {
			return nil, false, err
		}
		if err := saveRevocations(abs, nil); err != nil {
			return nil, false, err
		}
		return nil, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	var f revocationsFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, false, fmt.Errorf("does not load as a revocations file (%v); port49d will not start without "+
			`the revocations it holds: restore it, or write {"revocations": []} on purpose`, err)
	}
	out := make([]store.Revocation, 0, len(f.Revocations))
	for i, e := range f.Revocations {
		at, err := time.Parse(time.RFC3339Nano, e.At)
		switch {
		case e.Kind != store.RevocationPrincipal && e.Kind != store.RevocationCert:
			return nil, false, fmt.Errorf("revocation %d: kind must be principal or cert", i)
		case e.Key == "" || len(e.Key) > 4096 || !utf8.ValidString(e.Key) ||
			strings.IndexFunc(e.Key, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0:
			return nil, false, fmt.Errorf("revocation %d: its key is empty, too long, or not printable", i)
		case err != nil:
			return nil, false, fmt.Errorf("revocation %d: at is not an RFC 3339 time", i)
		}
		out = append(out, store.Revocation{Kind: e.Kind, Key: e.Key, At: at, Origin: e.Origin})
	}
	switch _, err := os.Lstat(markerOf(path)); {
	case errors.Is(err, fs.ErrNotExist):
		abs, err := filepath.Abs(path)
		if err != nil {
			return nil, false, err
		}
		if err := writeMarker(abs); err != nil {
			return nil, false, err
		}
	case err != nil:
		return nil, false, err
	}
	return out, false, nil
}

// writeMarker writes the marker beside the file at abs, 0600, atomically.
func writeMarker(abs string) error {
	return inventory.WriteAtomic(filepath.Dir(abs), filepath.Base(markerOf(abs)),
		[]byte("port49d created "+filepath.Base(abs)+" at "+decision.FormatTime(time.Now())+"\n"), 0o600)
}

// saveRevocations writes rs whole, 0600, atomically: a reader sees the old
// file or the new one.
func saveRevocations(path string, rs []store.Revocation) error {
	f := revocationsFile{Revocations: []revocationEntry{}}
	for _, r := range rs {
		f.Revocations = append(f.Revocations, revocationEntry{Kind: r.Kind, Key: r.Key,
			At: decision.FormatTime(r.At), Origin: r.Origin})
	}
	body, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	return inventory.WriteAtomic(filepath.Dir(abs), filepath.Base(abs), append(body, '\n'), 0o600)
}

// restoreRevocations puts every mark in the file in force in st, before
// the broker serves a request, counts them, and returns them for the
// listener's copy. created is the first start's. A mark the store refuses
// (a certificate key with no issuer) is named by its index; run names the
// file.
func restoreRevocations(ctx context.Context, st store.Store, path string, m *metrics.Metrics) ([]store.Revocation, bool, error) {
	rs, created, err := loadRevocations(path)
	if err != nil {
		return nil, false, err
	}
	for i, r := range rs {
		if err := st.PutRevocation(ctx, r); err != nil {
			return nil, false, fmt.Errorf("revocation %d: %w", i, err)
		}
	}
	countRevocations(rs, m)
	return rs, created, nil
}

// writeRevocations is persister's write, swapped in tests; persistDeadline
// bounds one call of it. persistHook is called at the named points where a
// call gives up, so a test can hold it there; it does nothing in port49d.
var (
	writeRevocations = saveRevocations
	persistDeadline  = 5 * time.Second
	persistHook      = func(point string) {}
)

// persister is Broker.Persist: it lists every mark in force and writes the
// file, one writer at a time and listing under the slot, so the last write
// holds every mark put before it.
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
func persister(st store.Store, path string, m *metrics.Metrics) func(context.Context) error {
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
				countRevocations(rs, m)
				err = write(path, rs)
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

func countRevocations(rs []store.Revocation, m *metrics.Metrics) {
	n := map[string]int{store.RevocationPrincipal: 0, store.RevocationCert: 0}
	for _, r := range rs {
		n[r.Kind]++
	}
	for by, c := range n {
		m.RevocationsInForce.WithLabelValues(by).Set(float64(c))
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
			return "", err
		}
		return broker.RevocationsText(rs), nil
	}
}
