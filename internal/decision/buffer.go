package decision

import "sync"

// Buffer is an Emitter that keeps what it is given, for a caller that must
// not write while it holds a lock others wait on (plan 7e, Ruling 10): a
// mint holds the policy from its first resolution to its last token write,
// and a log sink that stalls there would stall every reload. The caller
// flushes it once it has let go. It is safe for concurrent use.
//
// A record's ts is taken when it is buffered, not when it is written, so
// records from concurrent buffers reach the log out of ts order: the log is
// in write order, and ts is not monotonic in it.
type Buffer struct {
	mu   sync.Mutex
	recs []Record
}

// NewBuffer is an empty buffer.
func NewBuffer() *Buffer { return &Buffer{} }

// Emit keeps r.
func (b *Buffer) Emit(r Record) {
	b.mu.Lock()
	b.recs = append(b.recs, r)
	b.mu.Unlock()
}

// Len is how many records it holds.
func (b *Buffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.recs)
}

// Flush writes every record it holds to to, in the order given, and tells
// landed of each with its write's error: Write's when to is a Sink, nil
// otherwise, since a plain Emitter cannot refuse. It leaves the buffer
// empty. landed may be nil.
func (b *Buffer) Flush(to Emitter, landed func(r Record, err error)) {
	b.mu.Lock()
	recs := b.recs
	b.recs = nil
	b.mu.Unlock()
	sink, isSink := to.(Sink)
	for _, r := range recs {
		var err error
		if isSink {
			err = sink.Write(r)
		} else {
			to.Emit(r)
		}
		if landed != nil {
			landed(r, err)
		}
	}
}
