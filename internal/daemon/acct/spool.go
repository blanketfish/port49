package acct

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
)

var ErrSpoolFull = errors.New("acct: spool full")

// Spool is a durable, append-only file log (spec §5.8, §14): Offer returns nil
// only after the record has been written to the file, fsynced, and (when the
// file was just created) its parent directory entry fsynced too, so a
// SUCCESS reply built on that nil is backed by disk, not memory.
//
// Run drains the whole file to the sink in one streamed pass per wake-up, by
// renaming it aside (to path+".draining") under the same lock Offer uses,
// then reading and forwarding it line by line outside the lock so new offers
// are not blocked on delivery. capacity only bounds the constructor's `< 1`
// validation; it is reserved for a future batching sink and does not limit
// how much a pass drains today.
//
// Delivery is at-least-once: a crash between forwarding a record to the sink
// and removing the .draining file re-forwards that record the next time Run
// starts (TestSpoolResumesDrainingFile). Consumers of the sink must tolerate
// duplicates. Every error on the drain path is logged (path and error, never
// record contents). If a pass fully forwards .draining but cannot remove it
// (for example, the directory is not writable), the spool remembers that and
// retries only the removal on later passes — it never re-forwards records it
// already delivered — logging at most once per minute
// (TestDrainDoesNotReemitWhenRemoveFails). On a clean shutdown, Run keeps
// draining until the file is empty; if drainOnce fails three times in a row
// (for example .draining exists but cannot be read), Run logs that and gives
// up, leaving whatever is on disk for the next start — at-least-once still
// holds, since nothing durably written is ever deleted without having been
// forwarded first (TestShutdownGivesUpOnPersistentReadError).
type Spool struct {
	path     string
	sink     decision.Emitter
	metrics  *metrics.Metrics
	capacity int

	mu    sync.Mutex
	depth int // records durably written but not yet forwarded

	signal chan struct{}

	stuck        bool // .draining is fully forwarded; only removal is retried
	lastStuckLog time.Time
}

func NewSpool(capacity int, overflowPath string, sink decision.Emitter, m *metrics.Metrics) (*Spool, error) {
	if capacity < 1 {
		return nil, errors.New("acct: spool capacity must be at least 1")
	}
	s := &Spool{path: overflowPath, sink: sink, metrics: m, capacity: capacity, signal: make(chan struct{}, 1)}
	if n, err := countLines(overflowPath); err == nil {
		s.depth = n
	}
	if n, err := countLines(overflowPath + ".draining"); err == nil {
		s.depth += n
	}
	s.metrics.SpoolDepth.Set(float64(s.depth))
	return s, nil
}

func countLines(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	n := 0
	for sc.Scan() {
		if len(sc.Bytes()) > 0 {
			n++
		}
	}
	return n, nil
}

// Offer marshals r to one JSON line, appends it to the spool file, and syncs
// before returning. If this write created the file, it also syncs the
// parent directory so the new directory entry survives a crash (a data
// fsync alone does not guarantee the file is findable after one). It
// returns nil only once every one of those durable writes has succeeded;
// any error along the way counts a drop and returns ErrSpoolFull.
func (s *Spool) Offer(r decision.Record) error {
	b, err := json.Marshal(r)
	if err != nil {
		s.metrics.SpoolDrops.Inc()
		return ErrSpoolFull
	}
	b = append(b, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()

	_, statErr := os.Stat(s.path)
	isNew := os.IsNotExist(statErr)

	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		s.metrics.SpoolDrops.Inc()
		return ErrSpoolFull
	}
	_, werr := f.Write(b)
	var serr error
	if werr == nil {
		serr = f.Sync()
	}
	cerr := f.Close()
	if werr != nil || serr != nil {
		s.metrics.SpoolDrops.Inc()
		return ErrSpoolFull
	}
	_ = cerr // a close failure after a successful sync does not lose the write

	if isNew {
		if err := syncDir(filepath.Dir(s.path)); err != nil {
			s.metrics.SpoolDrops.Inc()
			return ErrSpoolFull
		}
	}

	s.depth++
	s.metrics.SpoolDepth.Set(float64(s.depth))

	select {
	case s.signal <- struct{}{}:
	default:
	}
	return nil
}

// syncDir fsyncs a directory's own entry so a file just created (or removed)
// inside it survives a crash, not only the file's own data.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Run drains the spool to the sink until ctx is done and the file (and any
// in-flight .draining file) is empty, or the shutdown drain gives up after
// repeated failures (see the package doc).
func (s *Spool) Run(ctx context.Context) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		s.drainOnce()
		select {
		case <-ctx.Done():
			s.drainUntilEmptyOrGiveUp()
			return
		case <-s.signal:
		case <-ticker.C:
		}
	}
}

// drainUntilEmptyOrGiveUp is Run's shutdown path. It keeps calling drainOnce
// until there is nothing left to forward. A failing drainOnce (an open or
// read error, or a stuck removal) is retried after a short sleep; three
// consecutive failures and it gives up, logging so the operator can see why
// records are still on disk. Giving up never deletes anything: at-least-once
// delivery holds across the next start.
func (s *Spool) drainUntilEmptyOrGiveUp() {
	failures := 0
	for {
		if s.drainOnce() {
			failures = 0
			if !s.hasWork() {
				return
			}
			continue
		}
		failures++
		if failures >= 3 {
			log.Printf("acct: spool giving up draining on shutdown after %d consecutive failures; records remain on disk for the next start", failures)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (s *Spool) hasWork() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.depth > 0
}

// markStuck records that .draining is fully forwarded but could not be
// removed, so later passes retry only the removal. It logs at most once per
// minute to avoid flooding the log while the underlying condition persists.
func (s *Spool) markStuck(path string, err error) {
	s.stuck = true
	if time.Since(s.lastStuckLog) >= time.Minute {
		log.Printf("acct: spool cannot remove drained file %s: %v", path, err)
		s.lastStuckLog = time.Now()
	}
}

// drainOnce renames the spool file aside (or picks up a leftover .draining
// file from a previous crash) and streams every record in it to the sink, in
// order, in one pass. It reports true on success (including when there was
// nothing to do) and false on an error, which it has already logged.
//
// If a previous pass forwarded every record but failed to remove .draining
// (s.stuck), this pass retries only the removal: it never re-opens or
// re-forwards a file it has already fully delivered.
func (s *Spool) drainOnce() bool {
	draining := s.path + ".draining"

	if s.stuck {
		if err := os.Remove(draining); err != nil {
			s.markStuck(draining, err)
			return false
		}
		s.stuck = false
		return true
	}

	s.mu.Lock()
	if _, err := os.Stat(draining); err != nil {
		if !os.IsNotExist(err) {
			s.mu.Unlock()
			log.Printf("acct: spool stat %s failed: %v", draining, err)
			return false
		}
		// No leftover .draining file: try to start a fresh one from path.
		if err := os.Rename(s.path, draining); err != nil {
			s.mu.Unlock()
			if os.IsNotExist(err) {
				return true // nothing pending
			}
			log.Printf("acct: spool rename %s -> %s failed: %v", s.path, draining, err)
			return false
		}
	}
	s.mu.Unlock()

	f, err := os.Open(draining)
	if err != nil {
		log.Printf("acct: spool open %s failed: %v", draining, err)
		return false
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	forwarded := 0
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var r decision.Record
		if err := r.UnmarshalJSON(line); err != nil {
			log.Printf("acct: dropping spool line that failed to unmarshal: %v", err)
			s.metrics.SpoolDrops.Inc()
			forwarded++
			continue
		}
		s.sink.Emit(r)
		forwarded++
	}
	scErr := sc.Err()
	f.Close()

	s.mu.Lock()
	s.depth -= forwarded
	if s.depth < 0 {
		s.depth = 0
	}
	s.metrics.SpoolDepth.Set(float64(s.depth))
	s.mu.Unlock()

	if scErr != nil {
		log.Printf("acct: spool read %s failed: %v", draining, scErr)
		return false
	}

	if err := os.Remove(draining); err != nil {
		s.markStuck(draining, err)
		return false
	}
	return true
}
