package decision

import (
	"errors"
	"testing"
)

type recSink struct {
	got  []Record
	fail map[string]bool // by Event: Write refuses these
}

func (s *recSink) Emit(r Record) { _ = s.Write(r) }
func (s *recSink) Write(r Record) error {
	if s.fail[r.Event] {
		return errors.New("refused")
	}
	s.got = append(s.got, r)
	return nil
}

// A buffer writes what it was given in order, tells landed of each with
// its write's error, and is empty after.
func TestABufferFlushesInOrderAndSaysWhatLanded(t *testing.T) {
	b := NewBuffer()
	b.Emit(Record{Event: EventBlob})
	b.Emit(Record{Event: EventMint})
	b.Emit(Record{Event: "refused"})
	sink := &recSink{fail: map[string]bool{"refused": true}}
	var landed []string
	b.Flush(sink, func(r Record, err error) {
		if err == nil {
			landed = append(landed, r.Event)
		}
	})
	if len(sink.got) != 2 || sink.got[0].Event != EventBlob || sink.got[1].Event != EventMint {
		t.Fatalf("written %+v", sink.got)
	}
	if len(landed) != 2 || b.Len() != 0 {
		t.Fatalf("landed %v, left %d", landed, b.Len())
	}
}

// A plain Emitter cannot refuse, so every record is said to have landed.
func TestABufferFlushedToAnEmitterSaysEveryRecordLanded(t *testing.T) {
	b := NewBuffer()
	b.Emit(Record{Event: EventBlob})
	n := 0
	b.Flush(emitOnly{}, func(_ Record, err error) {
		if err == nil {
			n++
		}
	})
	if n != 1 {
		t.Fatalf("%d landed", n)
	}
}

type emitOnly struct{}

func (emitOnly) Emit(Record) {}
