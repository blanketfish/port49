package etcd

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"sync/atomic"
	"time"

	"go.etcd.io/etcd/api/v3/v3rpc/rpctypes"
	clientv3 "go.etcd.io/etcd/client/v3"
	"google.golang.org/grpc/metadata"

	"github.com/blanketfish/port49/internal/store"
)

// The feeds that gate a decision (the context feed's fence, the marks feed's
// revocations) each run as two legs: two watches of the same range on two
// different members, merged into one. A watch on a member that is paused or
// cut off stays up until keepalive fails its connection, 10 to 12 s on, and
// says nothing in the meantime: a quiet family looks the same. With one leg
// that member refused every login behind the fence for that long (CI
// 41732782845), and a revocation reached the process just as late. With two, the
// feed is as far along as the faster leg, so one dark member costs nothing; a
// leg quiet for feedStall while the store answers a read is ended and opened
// again on a member neither leg is on.
//
// The merge: both legs see the same events in revision order, so a response's
// events at or below `through`, the highest revision delivered (an event's,
// or a progress notification's, which says every event through it was
// sent), were delivered by the other leg and are dropped. Nothing is
// delivered twice and nothing goes back. That holds while a revision's
// events arrive in one response and the legs are not fragmented: etcd splits
// a response only for a watch created WithFragment, which legOpts never sets
// and notFragmented checks.
var (
	feedIdle  = time.Second     // a leg this quiet asks for its progress
	feedStall = 2 * time.Second // and one this quiet, with the store answering a read, is opened again
)

// legRetry is how long a leg that failed waits before it is opened again.
var legRetry = time.Second

// legOpts are the options of one leg, built here and nowhere else.
func legOpts(from int64, keysOnly bool) []clientv3.OpOption {
	o := []clientv3.OpOption{clientv3.WithPrefix(), clientv3.WithRev(from), clientv3.WithProgressNotify()}
	if keysOnly {
		o = append(o, clientv3.WithKeysOnly())
	}
	return o
}

// notFragmented reports false for a watch op that asks etcd to split its
// responses. The flag is unexported in clientv3, so it is read by name; a
// release that renames it reads as not fragmented here, and
// TestTheLegsAreNotFragmented fails then.
func notFragmented(opts []clientv3.OpOption) bool {
	f := reflect.ValueOf(clientv3.OpGet("k", opts...)).FieldByName("fragment")
	return !f.IsValid() || !f.Bool()
}

// legSource is what watchLegs runs on. Its methods are called from one
// goroutine, in turn. open starts leg i's watch (opening number gen) from
// revision from, and returns its responses and a cancel that ends it;
// progress sends a progress request on leg i's current stream; probe is a
// read on the same client, answered while the store is.
type legSource interface {
	open(ctx context.Context, i, gen int, from int64) (<-chan clientv3.WatchResponse, context.CancelFunc)
	progress(i int) error
	probe(ctx context.Context) error
}

type legMsg struct {
	leg, gen int
	resp     clientv3.WatchResponse
	ok       bool
}

type leg struct {
	gen      int
	cancel   context.CancelFunc
	heard    time.Time
	failed   bool
	reopenAt time.Time
}

// watchLegs merges two legs of one watch into one channel of responses, which
// it closes when the watch is over: ctx ended, a leg's compaction (the
// response is passed on, its Err says so), or both legs failed at once (the
// last failure is passed on). A leg that fails alone is opened again after
// legRetry and the watch goes on. asks has each leg send a progress request.
// after is the revision the watch follows from, as WatchContexts has it; saw
// is told every response's header revision, those it drops included.
func watchLegs(ctx context.Context, src legSource, after uint64, asks <-chan struct{}, saw func(int64),
	logf func(string, ...any)) <-chan clientv3.WatchResponse {
	out := make(chan clientv3.WatchResponse)
	go func() {
		defer close(out)
		defer func() { traceLeg("watch", 0, 0, "ended") }()
		in := make(chan legMsg)
		var legs [2]leg
		through := int64(after)
		start := func(i int) {
			l := &legs[i]
			l.gen++
			l.failed, l.heard = false, time.Now()
			ch, cancel := src.open(ctx, i, l.gen, through+1)
			l.cancel = cancel
			gen := l.gen
			go func() {
				for resp := range ch {
					select {
					case in <- legMsg{i, gen, resp, true}:
					case <-ctx.Done():
						return
					}
				}
				select {
				case in <- legMsg{i, gen, clientv3.WatchResponse{}, false}:
				case <-ctx.Done():
				}
			}()
		}
		defer func() {
			for i := range legs {
				if legs[i].cancel != nil {
					legs[i].cancel()
				}
			}
		}()
		emit := func(r clientv3.WatchResponse) bool {
			select {
			case out <- r:
				return true
			case <-ctx.Done():
				return false
			}
		}
		// fail ends leg i; false when the other has failed too and the watch is over.
		fail := func(i int, r clientv3.WatchResponse, why string) bool {
			l := &legs[i]
			l.failed, l.reopenAt = true, time.Now().Add(legRetry)
			l.cancel()
			traceLeg("ended", i, l.gen, why)
			if legs[1-i].failed {
				if r.Err() != nil {
					emit(r)
				}
				return false
			}
			logf("etcd: a leg of a watch ended (%s); the other follows, and it is opened again in %v", why, legRetry)
			return true
		}
		start(0)
		start(1)
		tick := time.NewTicker(feedIdle / 2)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-asks:
				for i := range legs {
					if !legs[i].failed {
						src.progress(i)
					}
				}
			case m := <-in:
				l := &legs[m.leg]
				if m.gen != l.gen || l.failed {
					continue // a leg already ended
				}
				if !m.ok {
					if !fail(m.leg, clientv3.WatchResponse{}, "its stream closed") {
						return
					}
					continue
				}
				l.heard = time.Now()
				r := m.resp
				if len(r.Events) > 0 {
					traceLeg("events", m.leg, m.gen, fmt.Sprintf("through revision %d", r.Events[len(r.Events)-1].Kv.ModRevision))
				}
				saw(r.Header.Revision)
				if err := r.Err(); err != nil {
					if r.CompactRevision > 0 || errors.Is(err, rpctypes.ErrCompacted) {
						emit(r)
						return
					}
					if !fail(m.leg, r, err.Error()) {
						return
					}
					continue
				}
				if r.IsProgressNotify() {
					if r.Header.Revision <= through {
						continue
					}
					through = r.Header.Revision
					if !emit(r) {
						return
					}
					continue
				}
				kept := make([]*clientv3.Event, 0, len(r.Events))
				for _, ev := range r.Events {
					if ev.Kv.ModRevision > through {
						kept = append(kept, ev)
					}
				}
				if len(kept) == 0 {
					continue // the other leg delivered these
				}
				for _, ev := range kept {
					through = max(through, ev.Kv.ModRevision)
				}
				r.Events = kept
				if !emit(r) {
					return
				}
			case <-tick.C:
				now := time.Now()
				for i := range legs {
					l := &legs[i]
					switch quiet := now.Sub(l.heard); {
					case l.failed:
						if !now.Before(l.reopenAt) {
							start(i)
						}
					case quiet >= feedStall:
						// Only while the store answers a read: with every member dark
						// (no quorum, a network out) every leg is as quiet as this
						// one, the stream revives when the store returns, and ending
						// it would only add a retry to the recovery.
						pc, pcancel := context.WithTimeout(ctx, feedStall/2)
						err := src.probe(pc)
						pcancel()
						if err == nil {
							logf("etcd: a leg of a watch heard nothing for %v while the store answers; it is opened again on another member",
								quiet.Round(100*time.Millisecond))
							l.cancel()
							traceLeg("quiet, opened again", i, l.gen, fmt.Sprintf("after %v", quiet.Round(10*time.Millisecond)))
							start(i)
						}
					case quiet >= feedIdle:
						src.progress(i)
					}
				}
			}
		}
	}()
	return out
}

// clientLegs is the legSource of a client's Watch. Each leg is on its own
// gRPC stream (clientv3 keys streams by their outgoing metadata, and each
// opening has a new key, so a stream being closed is never reused), placed
// by the balancer on a member the other leg and this leg's last opening are
// not on.
type clientLegs struct {
	cl       *clientv3.Client
	key      string
	keysOnly bool
	probeFn  func(context.Context) error
	trs      [2]*tried
	ctxs     [2]context.Context
}

// legTrace, when set by a test, is told each opening of a leg (with the member
// it was placed on) and each response of events a leg delivers (with their
// highest revision, never a key or a value). Nil in production.
var legTrace atomic.Pointer[func(ev string, leg, gen int, detail string)]

func traceLeg(ev string, leg, gen int, detail string) {
	if f := legTrace.Load(); f != nil {
		(*f)(ev, leg, gen, detail)
	}
}

func (c *clientLegs) open(ctx context.Context, i, gen int, from int64) (<-chan clientv3.WatchResponse, context.CancelFunc) {
	tr := &tried{used: map[string]bool{}}
	if prev := c.trs[i]; prev != nil && prev.lastMember() != "" {
		tr.used[prev.lastMember()] = true
	}
	tr.peer = c.trs[1-i]
	wctx, cancel := context.WithCancel(withTriedSet(clientv3.WithRequireLeader(ctx), tr))
	wctx = metadata.AppendToOutgoingContext(wctx, "port49-leg", strconv.Itoa(i)+"."+strconv.Itoa(gen))
	c.trs[i], c.ctxs[i] = tr, wctx
	if p := c.trs[1-i]; p != nil {
		p.peer = tr
	}
	ch := c.cl.Watch(wctx, c.key, legOpts(from, c.keysOnly)...)
	// The next opening waits for this one's placement, so the two legs do not
	// both pick before either has: at most 300 ms.
	for end := time.Now().Add(300 * time.Millisecond); tr.lastMember() == "" && time.Now().Before(end); {
		time.Sleep(5 * time.Millisecond)
	}
	peer := ""
	if p := c.trs[1-i]; p != nil {
		peer = p.lastMember()
	}
	traceLeg("open", i, gen, "on "+tr.lastMember()+", the other on "+peer)
	return ch, cancel
}

func (c *clientLegs) progress(i int) error { return c.cl.RequestProgress(c.ctxs[i]) }

func (c *clientLegs) probe(ctx context.Context) error { return c.probeFn(ctx) }

// followLegs is the two-leg watch of key's range on client cl, from revision
// after: the channel of merged responses a handler ranges over as it would a
// single Watch's. probe is a one-key read on cl.
func (s *Store) followLegs(ctx context.Context, cl *clientv3.Client, key string, after uint64, keysOnly bool,
	probe func(context.Context) error, asks <-chan struct{}) (<-chan clientv3.WatchResponse, error) {
	if !notFragmented(legOpts(1, keysOnly)) {
		return nil, fmt.Errorf("%w: a watch leg is set to fragment its responses, which the merge cannot drop", store.ErrUnavailable)
	}
	src := &clientLegs{cl: cl, key: key, keysOnly: keysOnly, probeFn: probe}
	return watchLegs(ctx, src, after, asks, s.saw, s.logf), nil
}
