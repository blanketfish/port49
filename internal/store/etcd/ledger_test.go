package etcd

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/blanketfish/port49/internal/store"
)

// The record raises and never lowers: a higher sequence replaces, a lower
// one is ignored, a later floor at the same sequence is kept, and a never
// context's mark has no lease (Ruling 4).
func TestTheLedgerRecordOnlyRaises(t *testing.T) {
	ctx := context.Background()
	s := onShared(t, time.Now)
	k := store.ContextKey{NAS: "leaf-01", Username: "netops"}
	until := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	put := func(m store.LedgerMark) {
		if _, err := s.PutLedgerMarks(ctx, []store.LedgerMark{m}); err != nil {
			t.Fatal(err)
		}
	}
	put(store.LedgerMark{Key: k, Seq: 100, Until: until})
	before, _ := s.ctx.Get(ctx, s.k.ledgerOf(k))
	put(store.LedgerMark{Key: k, Seq: 50, Until: until})  // lower: ignored
	put(store.LedgerMark{Key: k, Seq: 100, Until: until}) // the same: nothing written
	if after, _ := s.ctx.Get(ctx, s.k.ledgerOf(k)); after.Kvs[0].ModRevision != before.Kvs[0].ModRevision {
		t.Fatalf("a mark that raised nothing was written: revision %d, then %d", before.Kvs[0].ModRevision,
			after.Kvs[0].ModRevision)
	}
	put(store.LedgerMark{Key: k, Seq: 100, RevokedAt: until.Add(-time.Hour), FloorSeq: 100,
		Until: until}) // a floor at the same sequence
	rev, ms, err := s.LedgerMarks(ctx)
	if err != nil || rev == 0 || len(ms) != 1 || ms[0].Seq != 100 || ms[0].RevokedAt.IsZero() {
		t.Fatalf("rev %d marks %+v: %v", rev, ms, err)
	}
	put(store.LedgerMark{Key: k, Seq: 101}) // a never context: no lease
	_, ms, _ = s.LedgerMarks(ctx)
	if ms[0].Seq != 101 || !ms[0].Until.IsZero() || !ms[0].RevokedAt.IsZero() {
		t.Fatalf("after a higher sequence: %+v", ms[0])
	}
	resp, err := s.ctx.Get(ctx, s.k.ledgerOf(k))
	if err != nil || len(resp.Kvs) != 1 || resp.Kvs[0].Lease != 0 {
		t.Fatalf("a never context's mark: %v %v", resp, err)
	}
}

// Two keepers raising one key at once (a runner paused past its fence, and
// the one that took over) both land, and the higher stands.
func TestTheLedgerRecordRaceKeepsTheHigher(t *testing.T) {
	ctx := context.Background()
	s := onShared(t, time.Now)
	k := store.ContextKey{NAS: "leaf-01", Username: "netops"}
	var wg sync.WaitGroup
	for _, run := range [][2]int{{1, 1}, {200, -1}} { // one counts up, one down
		wg.Add(1)
		go func(seq, step int) {
			defer wg.Done()
			for i := 0; i < 200; i, seq = i+1, seq+step {
				if _, err := s.PutLedgerMarks(ctx, []store.LedgerMark{{Key: k, Seq: uint64(seq)}}); err != nil {
					t.Error(err)
					return
				}
			}
		}(run[0], run[1])
	}
	wg.Wait()
	if _, ms, err := s.LedgerMarks(ctx); err != nil || len(ms) != 1 || ms[0].Seq != 200 {
		t.Fatalf("after the race: %+v %v", ms, err)
	}
}

// A floor is kept with the sequence it holds through (C1), and a mark
// above that clears it; one at or below it keeps it, from whichever write
// it came. A mark's lease is its Until.
func TestTheLedgerRecordKeepsTheFloorThroughItsSequence(t *testing.T) {
	ctx := context.Background()
	s := onShared(t, time.Now)
	k := store.ContextKey{NAS: "leaf-01", Username: "netops"}
	at := time.Now().UTC().Truncate(time.Second)
	until := at.Add(48 * time.Hour)
	get := func() store.LedgerMark {
		t.Helper()
		_, ms, err := s.LedgerMarks(ctx)
		if err != nil || len(ms) != 1 {
			t.Fatalf("%+v %v", ms, err)
		}
		return ms[0]
	}
	put := func(m store.LedgerMark) {
		t.Helper()
		if _, err := s.PutLedgerMarks(ctx, []store.LedgerMark{m}); err != nil {
			t.Fatal(err)
		}
	}
	put(store.LedgerMark{Key: k, Seq: 100, RevokedAt: at, FloorSeq: 150, Until: until})
	if m := get(); m.Seq != 100 || !m.RevokedAt.Equal(at) || m.FloorSeq != 150 || !m.Until.Equal(until) {
		t.Fatalf("the floor round trip: %+v", m)
	}
	resp, _ := s.ctx.Get(ctx, s.k.ledgerOf(k))
	ttl, err := s.ctx.TimeToLive(ctx, clientv3.LeaseID(resp.Kvs[0].Lease))
	if err != nil || time.Duration(ttl.TTL)*time.Second < 47*time.Hour {
		t.Fatalf("a mark's lease: %ds %v", ttl.TTL, err)
	}
	put(store.LedgerMark{Key: k, Seq: 140, Until: until}) // a later write the floor holds through
	if m := get(); m.Seq != 140 || !m.RevokedAt.Equal(at) || m.FloorSeq != 150 {
		t.Fatalf("a mark at or below the floor's sequence cleared it: %+v", m)
	}
	put(store.LedgerMark{Key: k, Seq: 140, RevokedAt: at.Add(-time.Hour), FloorSeq: 140, Until: until})
	if m := get(); !m.RevokedAt.Equal(at) || m.FloorSeq != 150 {
		t.Fatalf("an earlier floor lowered the record's: %+v", m)
	}
	put(store.LedgerMark{Key: k, Seq: 151, Until: until})
	if m := get(); m.Seq != 151 || !m.RevokedAt.IsZero() || m.FloorSeq != 0 {
		t.Fatalf("a mark past the floor's sequence kept it: %+v", m)
	}
	put(store.LedgerMark{Key: k, Seq: 151, FloorSeq: 200, Until: until.Add(-time.Hour)})
	if m := get(); m.FloorSeq != 0 || !m.Until.Equal(until) {
		t.Fatalf("a mark with no floor, or an earlier keep, at the same sequence moved the record: %+v", m)
	}
	put(store.LedgerMark{Key: k, Seq: 151}) // a never context at the same sequence: kept for good
	put(store.LedgerMark{Key: k, Seq: 151, Until: until})
	if m := get(); !m.Until.IsZero() {
		t.Fatalf("a keep replaced a never context's: %+v", m)
	}
}

// A record that does not decode is an error naming its key, never a key
// skipped: skipped, a start would admit a put-back there.
func TestAnUndecodableLedgerRecordIsAnError(t *testing.T) {
	ctx := context.Background()
	s := onShared(t, time.Now)
	k := store.ContextKey{NAS: "leaf-01", Username: "netops"}
	if _, err := s.ctx.Put(ctx, s.k.ledgerOf(k), "{"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.LedgerMarks(ctx); err == nil || !strings.Contains(err.Error(), "delete that key as etcd's root") {
		t.Fatalf("an undecodable ledger record was read, or its error names no remedy: %v", err)
	}
	// A keeper's write stops at it, and says how many landed before it, so
	// only the rest is owed again (review I-2, M-4).
	before := store.ContextKey{NAS: "leaf-00", Username: "a"}
	after := store.ContextKey{NAS: "leaf-02", Username: "b"}
	n, err := s.PutLedgerMarks(ctx, []store.LedgerMark{{Key: before, Seq: 5}, {Key: k, Seq: 5}, {Key: after, Seq: 5}})
	if err == nil || n != 1 {
		t.Fatalf("a write over an undecodable record: %d landed, %v", n, err)
	}
}

// A write that lands every mark says so.
func TestALedgerWriteSaysHowManyLanded(t *testing.T) {
	ctx := context.Background()
	s := onShared(t, time.Now)
	ms := []store.LedgerMark{{Key: store.ContextKey{NAS: "leaf-01", Username: "a"}, Seq: 5},
		{Key: store.ContextKey{NAS: "leaf-01", Username: "b"}, Seq: 6}}
	if n, err := s.PutLedgerMarks(ctx, ms); err != nil || n != 2 {
		t.Fatalf("%d landed: %v", n, err)
	}
	if n, err := s.PutLedgerMarks(ctx, ms); err != nil || n != 2 { // raising nothing lands too
		t.Fatalf("again: %d landed: %v", n, err)
	}
}

// The record reads a page at a time at one revision: more marks than a
// page all come back.
func TestTheLedgerRecordReadsPages(t *testing.T) {
	ctx := context.Background()
	s := onShared(t, time.Now)
	var ms []store.LedgerMark
	for i := range 501 {
		ms = append(ms, store.LedgerMark{Key: store.ContextKey{NAS: "leaf-01", Username: "u" + string(rune('a'+i%26)) +
			string(rune('a'+i/26))}, Seq: uint64(i + 1)})
	}
	if _, err := s.PutLedgerMarks(ctx, ms); err != nil {
		t.Fatal(err)
	}
	if _, got, err := s.LedgerMarks(ctx); err != nil || len(got) != 501 {
		t.Fatalf("%d marks: %v", len(got), err)
	}
}
