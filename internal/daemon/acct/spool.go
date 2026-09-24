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
	"sync/atomic"
	"time"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/platform"
)

var ErrSpoolFull = errors.New("acct: spool full")

// The stages a record can be dropped at, as the spool_drops_total{stage}
// label. They are different events: a record refused at Offer never became
// durable, so its device was answered ERROR and will send it again, while a
// record dropped at drain was durable, its device was answered SUCCESS, and
// it is gone. Alerting on their sum hides the second inside the first.
// A record set aside is a third event: durable, answered SUCCESS, never
// deliverable, and kept in a file beside the spool for an operator.
const (
	dropOfferRefused     = "offer_refused"
	dropDrainUnparseable = "drain_unparseable"
	dropDrainSetAside    = "drain_set_aside"
)

// maxLineBytes bounds how much of a single spool line is held in memory. It
// is not a hard read limit: a longer line is still fully consumed from the
// stream (see readBoundedLine), but dropped rather than treated as fatal, so
// one corrupt or pathological record can never block the drain, and reading
// it can never allocate more than roughly this many bytes.
const maxLineBytes = 1 << 20 // 1 MiB

// sinkRetryInterval paces Run after the sink refuses a record, doubling with
// each refusal in a row up to sinkRetryMax. Every refused write is a log line
// and one more port49_decision_log_write_failures_total in the decision
// package, so retrying on the drain's 100ms tick (or on every Offer) would
// bury stderr and make that counter climb ten times a second for records the
// spool still holds; a full disk for a day is then about 1,400 attempts, not
// 86,000.
const (
	sinkRetryInterval = time.Second
	sinkRetryMax      = time.Minute
)

// sinkBackoff is how long Run waits after the nth refusal in a row.
func sinkBackoff(n int) time.Duration {
	d := sinkRetryInterval
	for i := 1; i < n && d < sinkRetryMax; i++ {
		d *= 2
	}
	return min(d, sinkRetryMax)
}

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
// duplicates. The contract reaches across the last hop: a record the sink
// refuses stops the pass at that record, drainOffset stays at its first byte,
// and the next pass offers it again (TestARefusedRecordIsOfferedAgain). A
// refusal is not the file's fault, so it never counts toward quarantine, and
// it is retried with a backoff (sinkBackoff). A record the sink can never
// take — one that does not encode (decision.ErrUnencodable) — would hold
// every record behind it forever, so it is set aside instead: appended to
// <path>.unencodable for an operator, logged, and counted as
// spool_drops_total{stage="drain_set_aside"}, and the drain goes on
// (TestAnUnencodableRecordIsSetAside).
// Every error on the drain path is logged (path and error, never record
// contents), throttled to once a minute per failure kind once a condition
// persists, so a stuck filesystem cannot flood the log.
//
// A read error partway through .draining does not lose or repeat the prefix
// already forwarded: the spool remembers how many bytes of the file it has
// forwarded (drainOffset) and the next pass resumes there instead of
// re-reading from the start (TestDrainResumesAtOffsetWithoutDuplicates). A
// line over maxLineBytes is dropped, not treated as a read error
// (TestOversizedLineIsDroppedNotFatal). A genuine read error, or a
// stat/open/seek failure on .draining itself, counts toward the same
// 3-strikes-then-quarantine mechanism: on the third consecutive failure at
// the same point, the file is renamed to
// <path>.draining.failed-<unix-seconds> so the drain can continue with
// whatever comes after it; a quarantined file is left for an operator,
// never read or deleted automatically by this package
// (TestShutdownQuarantinesUnreadableDrainingFile).
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
// attempts either way) so shutdown can never spin
// (TestShutdownGivesUpAfterThreeStrikes). Giving up leaves whatever is on
// disk for the next start — at-least-once delivery still holds, since
// nothing durably written is ever deleted without having been forwarded
// first.
type Spool struct {
	path     string
	sink     decision.Sink
	metrics  *metrics.Metrics
	capacity int

	mu    sync.Mutex
	depth int // records durably written but not yet forwarded; shared with Offer, so mutex-protected

	// needNewline is set whenever the file may end mid-record: a write or sync
	// that failed, or an existing file whose last byte is not "\n" at
	// construction. The next Offer writes a leading newline so its record
	// starts on a line of its own. Guarded by mu, like depth.
	needNewline bool

	// lastOfferLog throttles the failing-Offer log. Guarded by mu, since Offer
	// holds it; the drain path's own throttles belong to its goroutine alone.
	lastOfferLog time.Time

	signal chan struct{}

	// redact is the redaction a drained record passes through before the
	// sink (WithRedactor); unset is the built-in patterns. Atomic because
	// port49d sets it once the policy is known, with the drain running.
	redact atomic.Pointer[platform.Redactor]

	// The rest belong exclusively to the single goroutine that calls
	// drainOnce (Run, or a test calling it directly with nothing else
	// running concurrently): no mutex, since nothing else ever touches them.
	stuck             bool // .draining is fully forwarded; only removal is retried
	lastStuckLog      time.Time
	lastStructLog     time.Time // throttles stat/open/seek/rename failure logs
	lastQuarantineLog time.Time // throttles a failing quarantine rename's log
	lastReadLog       time.Time // throttles the read-failure log
	lastSinkLog       time.Time // throttles the sink-refusal log
	sinkRefusals      int       // refusals since the last sink-refusal line
	sinkRefused       bool      // the last pass stopped at a record the sink refused; Run paces the retry
	refusedInARow     int       // passes in a row that stopped at a refusal; Run's backoff
	drainOffset       int64     // bytes of .draining already forwarded; 0 for a file not yet started
	offsetFailAt      int64     // drainOffset (or -1 for a structural failure) at the last failure
	offsetFailCount   int       // consecutive failures at offsetFailAt

	// Test-only hooks (see spool_test.go); both are zero-valued no-ops in
	// production.
	failAfterBytes int64 // >0: fail the read after this many bytes of .draining, once
	forceFail      bool  // true: drainOnce returns (false, 0) immediately, touching nothing
}

// NewSpool prepares the spool at overflowPath. It refuses a path it cannot
// create or append to, so an accounting directory that does not exist fails
// at start with one actionable line instead of becoming an ERROR reply per
// record once devices are live, and it notes whether the existing file ends
// mid-record so the first Offer does not append onto a fragment.
func NewSpool(capacity int, overflowPath string, sink decision.Sink, m *metrics.Metrics) (*Spool, error) {
	if capacity < 1 {
		return nil, errors.New("acct: spool capacity must be at least 1")
	}
	if err := probeWritable(overflowPath); err != nil {
		return nil, err
	}
	s := &Spool{path: overflowPath, sink: sink, metrics: m, capacity: capacity, signal: make(chan struct{}, 1)}
	s.needNewline = endsMidRecord(overflowPath)
	if n, err := countLines(overflowPath); err == nil {
		s.depth = n
	}
	if n, err := countLines(overflowPath + ".draining"); err == nil {
		s.depth += n
	}
	s.metrics.SpoolDepth.Set(float64(s.depth))
	return s, nil
}

// probeWritable checks at construction that the spool file can be created and
// appended to, so the commonest accounting misconfiguration there is — a
// spool_path whose directory does not exist, or one the daemon cannot write —
// fails at start with one line naming the path, rather than turning into an
// ERROR reply per accounting record once devices are live. It leaves the
// directory as it found it: a file it had to create is removed again, so
// Offer still sees a brand-new file and fsyncs the directory entry for it.
func probeWritable(path string) error {
	_, statErr := os.Stat(path)
	created := os.IsNotExist(statErr)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("acct: cannot write the accounting spool at %s: %w", path, err)
	}
	f.Close()
	if created {
		// A failure here leaves an empty spool file, which is harmless.
		_ = os.Remove(path)
	}
	return nil
}

// endsMidRecord reports whether path exists and its last byte is not a
// newline, which means a previous process died partway through an append (or
// filled the disk mid-record). The next Offer must then start on a line of its
// own rather than glue its record onto the fragment. A file that cannot be
// read at all answers false: Offer's own probe is what reports that.
func endsMidRecord(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || fi.Size() == 0 {
		return false
	}
	var last [1]byte
	if _, err := f.ReadAt(last[:], fi.Size()-1); err != nil {
		return false
	}
	return last[0] != '\n'
}

// countLines estimates how many records are already in path, using the same
// bounded line reader the drain itself uses, so an oversized or truncated
// (torn) line is counted as one line rather than aborting the count early —
// the drain will forward-or-drop it and adjust depth exactly when it does.
func countLines(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	br := bufio.NewReader(f)
	n := 0
	for {
		_, read, _, rerr := readBoundedLine(br)
		if read > 0 {
			n++
		}
		if rerr != nil {
			if rerr == io.EOF {
				return n, nil
			}
			return n, rerr
		}
	}
}

// readBoundedLine reads one newline-terminated line from br. It returns the
// line's content (nil if oversized — see below), the number of bytes
// actually consumed from br for this line (always accurate, even when
// oversized), whether the line exceeded maxLineBytes, and any error
// (often io.EOF once the stream is exhausted).
//
// A line longer than maxLineBytes is still fully consumed from the stream
// (so the caller's byte offset stays correct), but its content is dropped
// once the cap is crossed rather than accumulated, so peak memory for one
// line never grows much past maxLineBytes regardless of how long the actual
// line is.
func readBoundedLine(br *bufio.Reader) (line []byte, read int64, oversized bool, err error) {
	var buf []byte
	for {
		chunk, e := br.ReadSlice('\n')
		read += int64(len(chunk))
		if !oversized {
			if len(buf)+len(chunk) > maxLineBytes {
				oversized = true
				buf = nil
			} else {
				buf = append(buf, chunk...)
			}
		}
		if e == nil {
			return buf, read, oversized, nil
		}
		if e == bufio.ErrBufferFull {
			continue // delimiter not found yet within this line; keep reading it
		}
		return buf, read, oversized, e
	}
}

// Offer marshals r to one JSON line, appends it to the spool file, and syncs
// before returning. If this write created the file, it also syncs the
// parent directory so the new directory entry survives a crash (a data
// fsync alone does not guarantee the file is findable after one). It
// returns nil only once every one of those durable writes has succeeded;
// any error along the way counts a drop and returns ErrSpoolFull.
//
// A record is never appended to a line that may be incomplete. If the file
// ends mid-record — a short write when the disk filled, or a crash partway
// through one, detected here or at NewSpool — this record starts on a line of
// its own, leaving the fragment alone for the drain to drop. Without that,
// the fragment and this record would share a line, this Offer would return
// nil, its device would be told SUCCESS, and the drain would discard both
// (TestTornTailDoesNotSwallowTheNextRecord).
func (s *Spool) Offer(r decision.Record) error {
	b, err := json.Marshal(r)
	if err != nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.offerFailed("marshal", err)
		return ErrSpoolFull
	}
	b = append(b, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()

	_, statErr := os.Stat(s.path)
	isNew := os.IsNotExist(statErr)

	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		s.offerFailed("open", err)
		return ErrSpoolFull
	}
	if s.needNewline {
		// The file may end mid-record (a short write, or a crash during one).
		// Starting this record on its own line keeps the fragment a line of its
		// own, which the drain drops by itself, instead of gluing this record
		// onto it and losing a record that is about to be acknowledged.
		b = append([]byte{'\n'}, b...)
	}
	_, werr := f.Write(b)
	var serr error
	if werr == nil {
		serr = f.Sync()
	}
	cerr := f.Close()
	if werr != nil || serr != nil {
		// A partial write leaves the file ending mid-record; so does a write
		// whose sync never landed. Either way the next Offer must separate.
		s.needNewline = true
		if werr != nil {
			s.offerFailed("write", werr)
		} else {
			s.offerFailed("sync", serr)
		}
		return ErrSpoolFull
	}
	s.needNewline = false
	_ = cerr // a close failure after a successful sync does not lose the write

	if isNew {
		if err := syncDir(filepath.Dir(s.path)); err != nil {
			s.offerFailed("directory sync", err)
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

// offerFailed counts a drop and says why, at most once a minute: on a disk
// that stays full every record would otherwise print its own line. Without
// it, an operator sees spool_drops_total and requests_total{acct,error}
// climbing together and cannot tell ENOSPC from EACCES from a directory that
// was never created. The line names the stage, the path, and the OS error —
// never the record, which is device accounting like any other.
//
// Called with mu held.
func (s *Spool) offerFailed(stage string, err error) {
	s.metrics.SpoolDrops.WithLabelValues(dropOfferRefused).Inc()
	s.logThrottled(&s.lastOfferLog,
		"acct: spool %s failed on %s, accounting records are being refused: %v", stage, s.path, err)
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
		if s.sinkRefused {
			// Neither the tick nor an Offer can help a sink that just
			// refused, so wait out the backoff; a pending signal stays
			// buffered for the pass after.
			s.refusedInARow++
			select {
			case <-ctx.Done():
				s.drainUntilEmptyOrGiveUp()
				return
			case <-time.After(sinkBackoff(s.refusedInARow)):
			}
			continue
		}
		s.refusedInARow = 0
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

// logThrottled logs at most once per minute per call site (tracked via
// last), so a persistent failure condition cannot flood the log while
// drainOnce keeps retrying it every tick.
func (s *Spool) logThrottled(last *time.Time, format string, args ...any) {
	if time.Since(*last) >= time.Minute {
		log.Printf(format, args...)
		*last = time.Now()
	}
}

// markStuck records that .draining is fully forwarded but could not be
// removed, so later passes retry only the removal.
func (s *Spool) markStuck(path string, err error) {
	s.stuck = true
	s.logThrottled(&s.lastStuckLog, "acct: spool cannot remove drained file %s: %v", path, err)
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
	if s.forceFail { // test-only hook; see spool_test.go
		return false, 0
	}

	draining := s.path + ".draining"
	s.sinkRefused = false

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
			s.logThrottled(&s.lastStructLog, "acct: spool stat %s failed: %v", draining, err)
			s.recordReadFailure(draining, -1)
			return false, 0
		}
		// No leftover .draining file: try to start a fresh one from path.
		if err := os.Rename(s.path, draining); err != nil {
			s.mu.Unlock()
			if os.IsNotExist(err) {
				return true, 0 // nothing pending
			}
			s.logThrottled(&s.lastStructLog, "acct: spool rename %s -> %s failed: %v", s.path, draining, err)
			return false, 0
		}
		s.drainOffset = 0
		s.offsetFailCount = 0
	}
	offset := s.drainOffset
	s.mu.Unlock()

	f, err := os.Open(draining)
	if err != nil {
		s.logThrottled(&s.lastStructLog, "acct: spool open %s failed: %v", draining, err)
		s.recordReadFailure(draining, -1)
		return false, 0
	}
	defer f.Close()
	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			s.logThrottled(&s.lastStructLog, "acct: spool seek %s to %d failed: %v", draining, offset, err)
			s.recordReadFailure(draining, -1)
			return false, 0
		}
	}

	var r io.Reader = f
	if s.failAfterBytes > 0 { // test-only hook; see spool_test.go
		r = &failAfterReader{r: f, n: s.failAfterBytes}
	}
	br := bufio.NewReader(r)
	pos := offset
	for {
		line, n, oversized, rerr := readBoundedLine(br)
		if n > 0 {
			switch {
			case oversized:
				log.Printf("acct: dropping oversized spool line (over %d bytes)", maxLineBytes)
				s.metrics.SpoolDrops.WithLabelValues(dropDrainUnparseable).Inc()
			default:
				err := s.deliverLine(bytes.TrimRight(line, "\n"))
				if errors.Is(err, decision.ErrUnencodable) {
					// No retry will ever write it: set it aside, or it
					// holds every record behind it. If that fails, it is
					// retried like any refusal.
					if err = s.setAside(line); err == nil {
						log.Printf("acct: an accounting record the decision log cannot encode was set aside in %s",
							s.path+".unencodable")
						s.metrics.SpoolDrops.WithLabelValues(dropDrainSetAside).Inc()
					}
				}
				if err != nil {
					// The sink refused this record. Nothing past it is
					// forwarded and pos stays at its first byte, so the next
					// pass starts with it: at-least-once holds across the
					// sink, not only up to it (roadmap, plan 4). The record
					// is counted by the sink's own failure hook.
					s.applyForwarded(forwarded, pos)
					s.sinkRefused = true
					s.sinkRefusals++
					if time.Since(s.lastSinkLog) >= time.Minute {
						log.Printf("acct: the decision log sink refused an accounting record (%d refusals since "+
							"the last line); it stays in %s and is offered again, backing off to %s: %v",
							s.sinkRefusals, draining, sinkRetryMax, err)
						s.lastSinkLog, s.sinkRefusals = time.Now(), 0
					}
					return false, forwarded
				}
			}
			forwarded++
			pos += n
		}
		if rerr != nil {
			if rerr == io.EOF {
				break
			}
			s.applyForwarded(forwarded, pos)
			s.recordReadFailure(draining, pos)
			s.logThrottled(&s.lastReadLog, "acct: spool read %s at offset %d failed: %v", draining, pos, rerr)
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

// setAside appends one spool line to <path>.unencodable and syncs it, so a
// record the log will never take is kept for an operator, not lost.
func (s *Spool) setAside(line []byte) error {
	f, err := os.OpenFile(s.path+".unencodable", os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	if !bytes.HasSuffix(line, []byte("\n")) {
		line = append(line, '\n')
	}
	_, err = f.Write(line)
	if serr := f.Sync(); err == nil {
		err = serr
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// WithRedactor sets the redaction a drained record passes through before it
// reaches the sink: port49d passes the policy in force's.
func (s *Spool) WithRedactor(r platform.Redactor) *Spool {
	s.redact.Store(&r)
	return s
}

// redactAccount replaces the secrets of an account record's raw pairs and
// vector with «redacted» and says so (spec §5.8). nil is the built-in
// patterns.
func redactAccount(redact platform.Redactor, r *decision.Record) {
	if r.AcctRecord == nil || r.Device == nil {
		return
	}
	if redact == nil {
		redact = platform.BuiltInRedactor
	}
	if raw, v, ok := platform.RedactRecord(redact(r.Device.Platform), r.AcctRecord.Raw, r.AcctRecord.Vector); ok {
		a := *r.AcctRecord
		a.Raw, a.Vector, a.Redacted = raw, v, true
		r.AcctRecord = &a
	}
}

// deliverLine unmarshals one record and forwards it, or logs and counts a
// drop for a line that is empty or fails to unmarshal. An oversized line
// never reaches here — drainOnce handles that case itself, since
// readBoundedLine already discarded its content. The only error it returns
// is the sink's refusal: a line that will never parse is dropped, not
// retried, and a record the sink would not take is retried, not dropped.
func (s *Spool) deliverLine(line []byte) error {
	if len(line) == 0 {
		return nil
	}
	var r decision.Record
	if err := r.UnmarshalJSON(line); err != nil {
		log.Printf("acct: dropping spool line that failed to unmarshal: %v", err)
		s.metrics.SpoolDrops.WithLabelValues(dropDrainUnparseable).Inc()
		return nil
	}
	// Offer took the record already redacted, but a spool file an earlier
	// build left holds records it never redacted: the sink gets none of
	// them as they were.
	var redact platform.Redactor
	if p := s.redact.Load(); p != nil {
		redact = *p
	}
	redactAccount(redact, &r)
	return s.sink.Write(r)
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

// recordReadFailure tracks consecutive failures at the same point: either a
// genuine offset (>= 0) into .draining's content, or -1 for a
// stat/open/seek failure on .draining itself (which has no byte offset of
// its own). On the third consecutive failure at the same point, the file is
// quarantined so the drain can move on: no persistently unreadable file can
// block the spool forever. If the quarantine rename itself keeps failing,
// its log is throttled the same way a stuck removal's is. Records left in a
// quarantined file need an operator's attention; this package does not read
// or delete it.
func (s *Spool) recordReadFailure(draining string, at int64) {
	if at == s.offsetFailAt {
		s.offsetFailCount++
	} else {
		s.offsetFailAt = at
		s.offsetFailCount = 1
	}
	if s.offsetFailCount < 3 {
		return
	}
	quarantine := fmt.Sprintf("%s.failed-%d", draining, time.Now().Unix())
	if err := os.Rename(draining, quarantine); err != nil {
		s.logThrottled(&s.lastQuarantineLog, "acct: spool could not quarantine unreadable %s: %v", draining, err)
		return
	}
	s.metrics.SpoolQuarantines.Inc()
	log.Printf("acct: spool quarantined %s after %d consecutive failures; it is left for an operator, not read or deleted automatically", quarantine, s.offsetFailCount)
	s.drainOffset = 0
	s.offsetFailAt = 0
	s.offsetFailCount = 0
}

// failAfterReader wraps an io.Reader and fails with errInjectedFailure once
// more than n bytes have been read from it. It exists only so tests can
// force drainOnce's read-error path at an exact, deterministic byte offset
// without corrupting an actual file on disk (see spool_test.go).
type failAfterReader struct {
	r io.Reader
	n int64 // bytes still allowed before the injected failure
}

var errInjectedFailure = errors.New("acct: test-injected read failure")

func (f *failAfterReader) Read(p []byte) (int, error) {
	if f.n <= 0 {
		return 0, errInjectedFailure
	}
	if int64(len(p)) > f.n {
		p = p[:f.n]
	}
	n, err := f.r.Read(p)
	f.n -= int64(n)
	return n, err
}
