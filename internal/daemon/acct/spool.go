package acct

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
)

var ErrSpoolFull = errors.New("acct: spool full")

// maxLineBytes bounds a single spool line. It is not a hard read limit (see
// drainOnce): a longer line is still read, but dropped rather than treated
// as fatal, so one corrupt or pathological record can never block the drain.
const maxLineBytes = 1 << 20 // 1 MiB

// Spool is a durable, append-only file log (spec §5.8, §14): Offer returns nil
// only after the record has been written to the file, fsynced, and (when the
// file was just created) its parent directory entry fsynced too, so a
// SUCCESS reply built on that nil is backed by disk, not memory.
//
// Run drains the file to the sink by renaming it aside (to path+".draining")
// under the same lock Offer uses, then reading and forwarding it line by
// line outside the lock so new offers are not blocked on delivery. capacity
// only bounds the constructor's `< 1` validation; it is reserved for a
// future batching sink and does not limit how much a pass drains today.
//
// Delivery is at-least-once: a crash between forwarding a record to the sink
// and removing the .draining file re-forwards that record the next time Run
// starts (TestSpoolResumesDrainingFile). Consumers of the sink must tolerate
// duplicates. Every error on the drain path is logged (path and error, never
// record contents).
//
// A read error partway through .draining does not lose or repeat the prefix
// already forwarded: the spool remembers how many bytes of the file it has
// forwarded (drainOffset) and the next pass resumes there instead of
// re-reading from the start (TestDrainResumesAfterReadErrorWithoutDuplicates).
// If the same offset fails three passes in a row, the file is quarantined —
// renamed to <path>.draining.failed-<unix-seconds> — so the drain can
// continue with whatever comes after it; a quarantined file is left for an
// operator, never read or deleted automatically by this package.
//
// If a pass fully forwards .draining but cannot remove it (for example, the
// directory is not writable), the spool remembers that and retries only the
// removal on later passes — it never re-forwards records it already
// delivered — logging at most once per minute
// (TestDrainDoesNotReemitWhenRemoveFails). If .draining vanishes out from
// under a stuck removal, that counts as removed
// (TestStuckClearsWhenFileVanishes).
//
// On a clean shutdown, Run keeps draining until the file is empty; a pass
// that fails, or that succeeds without forwarding anything while work
// remains, counts toward a 3-strike give-up (with a short sleep between
// attempts either way) so shutdown can never spin. Giving up leaves whatever
// is on disk for the next start — at-least-once delivery still holds, since
// nothing durably written is ever deleted without having been forwarded
// first (TestShutdownGivesUpOnPersistentReadError).
type Spool struct {
	path     string
	sink     decision.Emitter
	metrics  *metrics.Metrics
	capacity int

	mu    sync.Mutex
	depth int // records durably written but not yet forwarded; shared with Offer, so mutex-protected

	signal chan struct{}

	// The rest belong exclusively to the single goroutine that calls
	// drainOnce (Run, or a test calling it directly with nothing else
	// running concurrently): no mutex, since nothing else ever touches them.
	stuck           bool // .draining is fully forwarded; only removal is retried
	lastStuckLog    time.Time
	drainOffset     int64 // bytes of .draining already forwarded; 0 for a file not yet started
	offsetFailAt    int64 // drainOffset at the last read failure
	offsetFailCount int   // consecutive read failures at offsetFailAt
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

// syncDir fsyncs a directory so a file Offer just created is durably
// findable in it after a crash: the file's own Sync commits its data, but
// not the parent directory's entry for it. It is called only right after
// Offer creates a brand-new spool file, never on removal.
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
// until there is nothing left to forward. A pass that fails, or that
// succeeds but forwards nothing while work remains (so it made no
// progress), sleeps briefly and counts toward a 3-strike give-up, which
// logs why records are left on disk. Giving up never deletes anything:
// at-least-once delivery holds across the next start.
func (s *Spool) drainUntilEmptyOrGiveUp() {
	failures := 0
	for {
		ok, forwarded := s.drainOnce()
		if ok && forwarded > 0 {
			failures = 0
		} else {
			failures++
		}
		if ok && !s.hasWork() {
			return
		}
		if failures >= 3 {
			log.Printf("acct: spool giving up draining on shutdown after %d consecutive non-progressing passes; records remain on disk for the next start", failures)
			return
		}
		if !ok || forwarded == 0 {
			time.Sleep(100 * time.Millisecond)
		}
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
// file from a previous crash, or resumes one this process already started
// forwarding) and streams records from it to the sink in order, from
// drainOffset. It reports whether the pass completed without error and how
// many records it consumed (forwarded to the sink, or dropped as
// unparseable/oversized — either way, no longer pending).
//
// If a previous pass forwarded every record but failed to remove .draining
// (s.stuck), this pass retries only the removal: it never re-opens or
// re-forwards a file it has already fully delivered. If the file has since
// vanished, that counts as removed.
func (s *Spool) drainOnce() (ok bool, forwarded int) {
	draining := s.path + ".draining"

	if s.stuck {
		if err := os.Remove(draining); err != nil {
			if os.IsNotExist(err) {
				s.stuck = false
				s.drainOffset = 0
				return true, 0
			}
			s.markStuck(draining, err)
			return false, 0
		}
		s.stuck = false
		s.drainOffset = 0
		return true, 0
	}

	s.mu.Lock()
	if _, err := os.Stat(draining); err != nil {
		if !os.IsNotExist(err) {
			s.mu.Unlock()
			log.Printf("acct: spool stat %s failed: %v", draining, err)
			return false, 0
		}
		// No leftover .draining file: try to start a fresh one from path.
		if err := os.Rename(s.path, draining); err != nil {
			s.mu.Unlock()
			if os.IsNotExist(err) {
				return true, 0 // nothing pending
			}
			log.Printf("acct: spool rename %s -> %s failed: %v", s.path, draining, err)
			return false, 0
		}
		s.drainOffset = 0
		s.offsetFailCount = 0
	}
	offset := s.drainOffset
	s.mu.Unlock()

	f, err := os.Open(draining)
	if err != nil {
		log.Printf("acct: spool open %s failed: %v", draining, err)
		return false, 0
	}
	defer f.Close()
	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			log.Printf("acct: spool seek %s to %d failed: %v", draining, offset, err)
			return false, 0
		}
	}

	br := bufio.NewReader(f)
	pos := offset
	for {
		line, rerr := br.ReadBytes('\n')
		if len(line) > 0 {
			s.deliverLine(bytes.TrimRight(line, "\n"))
			forwarded++
			pos += int64(len(line))
		}
		if rerr != nil {
			if rerr == io.EOF {
				break
			}
			s.applyForwarded(forwarded, pos)
			s.recordReadFailure(draining, pos)
			log.Printf("acct: spool read %s at offset %d failed: %v", draining, pos, rerr)
			return false, forwarded
		}
	}
	s.applyForwarded(forwarded, pos)
	s.offsetFailCount = 0

	if err := os.Remove(draining); err != nil {
		if os.IsNotExist(err) {
			s.drainOffset = 0
			return true, forwarded
		}
		s.markStuck(draining, err)
		return false, forwarded
	}
	s.drainOffset = 0
	return true, forwarded
}

// deliverLine unmarshals one record and forwards it, or logs and counts a
// drop for a line that is empty, too long (over maxLineBytes — never
// fatal, just skipped), or fails to unmarshal.
func (s *Spool) deliverLine(line []byte) {
	if len(line) == 0 {
		return
	}
	if len(line) > maxLineBytes {
		log.Printf("acct: dropping oversized spool line (%d bytes > %d max)", len(line), maxLineBytes)
		s.metrics.SpoolDrops.Inc()
		return
	}
	var r decision.Record
	if err := r.UnmarshalJSON(line); err != nil {
		log.Printf("acct: dropping spool line that failed to unmarshal: %v", err)
		s.metrics.SpoolDrops.Inc()
		return
	}
	s.sink.Emit(r)
}

// applyForwarded records this pass's progress: depth drops by the records
// consumed (mutex-protected, since Offer also touches depth), and
// drainOffset advances so a later pass — whether the next tick or a retry
// after an error — never re-reads what this pass already forwarded.
func (s *Spool) applyForwarded(forwarded int, pos int64) {
	s.mu.Lock()
	s.depth -= forwarded
	if s.depth < 0 {
		s.depth = 0
	}
	s.metrics.SpoolDepth.Set(float64(s.depth))
	s.mu.Unlock()
	s.drainOffset = pos
}

// recordReadFailure tracks consecutive read failures at the same offset. On
// the third, the file is quarantined so the drain can move on: no
// persistently unreadable file can block the spool forever. Records left in
// a quarantined file need an operator's attention; this package does not
// read or delete it.
func (s *Spool) recordReadFailure(draining string, offset int64) {
	if offset == s.offsetFailAt {
		s.offsetFailCount++
	} else {
		s.offsetFailAt = offset
		s.offsetFailCount = 1
	}
	if s.offsetFailCount < 3 {
		return
	}
	quarantine := fmt.Sprintf("%s.failed-%d", draining, time.Now().Unix())
	if err := os.Rename(draining, quarantine); err != nil {
		log.Printf("acct: spool could not quarantine unreadable %s: %v", draining, err)
		return
	}
	log.Printf("acct: spool quarantined %s after %d consecutive read failures at offset %d; it is left for an operator, not read or deleted automatically", quarantine, s.offsetFailCount, offset)
	s.drainOffset = 0
	s.offsetFailAt = 0
	s.offsetFailCount = 0
}
