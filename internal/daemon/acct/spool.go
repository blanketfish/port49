package acct

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"sync"
	"time"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
)

var ErrSpoolFull = errors.New("acct: spool full")

// Spool is a durable, append-only file log (spec §5.8, §14): Offer returns nil
// only after the record has been written to the file and fsynced, so a
// SUCCESS reply built on that nil is backed by disk, not memory. Run drains
// the file to the sink in order, in batches of up to capacity records per
// pass, by renaming it aside (to path+".draining") under the same lock Offer
// uses, then reading and forwarding it outside the lock so new offers are not
// blocked on delivery.
//
// Delivery is at-least-once: a crash between forwarding a record to the sink
// and removing the .draining file re-forwards that record the next time Run
// starts (TestSpoolResumesDrainingFile). Consumers of the sink must tolerate
// duplicates.
type Spool struct {
	path     string
	sink     decision.Emitter
	metrics  *metrics.Metrics
	capacity int

	mu    sync.Mutex
	depth int // records durably written but not yet forwarded

	signal chan struct{}
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
// before returning. It returns nil only once that durable write has
// succeeded; any open/write/sync error counts a drop and returns
// ErrSpoolFull.
func (s *Spool) Offer(r decision.Record) error {
	b, err := json.Marshal(r)
	if err != nil {
		s.metrics.SpoolDrops.Inc()
		return ErrSpoolFull
	}
	b = append(b, '\n')

	s.mu.Lock()
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		s.mu.Unlock()
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
		s.mu.Unlock()
		s.metrics.SpoolDrops.Inc()
		return ErrSpoolFull
	}
	_ = cerr // a close failure after a successful sync does not lose the write
	s.depth++
	s.metrics.SpoolDepth.Set(float64(s.depth))
	s.mu.Unlock()

	select {
	case s.signal <- struct{}{}:
	default:
	}
	return nil
}

// Run drains the spool to the sink until ctx is done and the file (and any
// in-flight .draining file) is empty.
func (s *Spool) Run(ctx context.Context) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		s.drainOnce()
		select {
		case <-ctx.Done():
			// Keep draining until every durably-written record has been
			// forwarded; a record already on disk must never be lost on
			// shutdown.
			for s.hasWork() {
				s.drainOnce()
			}
			return
		case <-s.signal:
		case <-ticker.C:
		}
	}
}

func (s *Spool) hasWork() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.depth > 0
}

// drainOnce renames the spool file aside (or picks up a leftover .draining
// file from a previous crash) and forwards up to capacity records from it to
// the sink, in order. Any records left over (more than capacity were
// pending) are written back to the .draining file so the next pass resumes
// where this one left off; a crash between forwarding and that rewrite (or
// the final removal) re-forwards the already-delivered records next start.
func (s *Spool) drainOnce() {
	draining := s.path + ".draining"

	s.mu.Lock()
	if _, err := os.Stat(draining); err != nil {
		// No leftover .draining file: try to start a fresh one from path.
		if err := os.Rename(s.path, draining); err != nil {
			s.mu.Unlock()
			return
		}
	}
	s.mu.Unlock()

	lines, err := readLines(draining)
	if err != nil {
		return
	}
	if len(lines) == 0 {
		os.Remove(draining)
		return
	}

	batch, rest := lines, []string(nil)
	if len(batch) > s.capacity {
		batch, rest = lines[:s.capacity], lines[s.capacity:]
	}

	forwarded := 0
	for _, line := range batch {
		var r decision.Record
		if err := r.UnmarshalJSON([]byte(line)); err != nil {
			log.Printf("acct: dropping spool line that failed to unmarshal")
			forwarded++
			continue
		}
		s.sink.Emit(r)
		forwarded++
	}

	if len(rest) == 0 {
		os.Remove(draining)
	} else {
		writeLines(draining, rest)
	}

	s.mu.Lock()
	s.depth -= forwarded
	if s.depth < 0 {
		s.depth = 0
	}
	s.metrics.SpoolDepth.Set(float64(s.depth))
	s.mu.Unlock()
}

// readLines reads path as newline-separated records, skipping blank lines.
func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	var lines []string
	for sc.Scan() {
		if line := sc.Text(); line != "" {
			lines = append(lines, line)
		}
	}
	return lines, sc.Err()
}

// writeLines atomically rewrites path with lines, fsynced before the rename
// so a crash mid-rewrite never leaves a truncated file the next pass trusts.
func writeLines(path string, lines []string) {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return
	}
	for _, line := range lines {
		if _, err := f.WriteString(line + "\n"); err != nil {
			f.Close()
			return
		}
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return
	}
	if err := f.Close(); err != nil {
		return
	}
	os.Rename(tmp, path)
}
