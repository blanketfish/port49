package etcd

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"sync"
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

// relocateMin and relocateMax bound the wait before legs found on one member
// are moved apart: relocateMin after they are first found together, doubling
// at each move that leaves them together, to relocateMax.
var (
	relocateMin = 2 * time.Second
	relocateMax = 30 * time.Second
)

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
	// member is the member leg i is on, "" while it is not placed.
	member(i int) string
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
	// placed is set once the leg's opening has returned: until then it has no
	// stream to ask for progress on.
	placed *atomic.Bool
	// closed is set by the leg's goroutine, before it sends its stream's
	// end: a progress request on a closed stream would have clientv3 open a
	// new stream, keyed by the leg's context, that nothing ends.
	closed *atomic.Bool
}

// watchLegs merges two legs of one watch into one channel of responses, which
// it closes when the watch is over: ctx ended, a leg's compaction (the
// response is passed on, its Err says so), or both legs failed at once (the
// last failure is passed on). single is true when the client has one endpoint:
// the legs can only share its member, which is no fault, so they are never
// moved and colo is never told. A leg that fails alone is opened again after
// legRetry and the watch goes on. asks has each leg send a progress request.
// after is the revision the watch follows from, as WatchContexts has it; saw
// is told every response's header revision, those it drops included.
func watchLegs(ctx context.Context, src legSource, after uint64, asks <-chan struct{}, saw func(int64),
	logf func(string, ...any), colo func(on bool, member string), single bool) <-chan clientv3.WatchResponse {
	out := make(chan clientv3.WatchResponse)
	go func() {
		defer close(out)
		defer func() { traceLeg("watch", 0, 0, "ended") }()
		in := make(chan legMsg)
		var legs [2]leg
		notify := func(on bool, member string) {
			if colo != nil {
				colo(on, member)
			}
		}
		if single {
			logf("etcd: the client has one endpoint, so both legs of a watch share one member; they are not moved apart")
		}
		through := int64(after)
		start := func(i int) {
			l := &legs[i]
			l.gen++
			l.failed, l.heard = false, time.Now()
			// The opening runs apart from this goroutine: a Watch waits for a
			// connection, and the other leg's events must not wait with it.
			lctx, cancel := context.WithCancel(ctx)
			l.cancel = cancel
			l.placed, l.closed = new(atomic.Bool), new(atomic.Bool)
			placed, closed, gen, from := l.placed, l.closed, l.gen, through+1
			go func() {
				defer cancel()
				ch, ocancel := src.open(lctx, i, gen, from)
				defer ocancel()
				placed.Store(true)
				for resp := range ch {
					select {
					case in <- legMsg{i, gen, resp, true}:
					case <-lctx.Done():
						return
					}
				}
				closed.Store(true)
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
		// Both legs on one member go dark together. The balancer shares a
		// member only when every other member's connection has failed (a leg
		// waits for one still connecting: balancer.go, #64), so a pair found on
		// one is opened apart again once another is back: leg 1, from
		// through+1, on whichever member is then free, and if none is, on the
		// same again. The tries back off, so a cluster with one live member is
		// not churned.
		var (
			together bool
			wait     = relocateMin
			tryAt    time.Time
			apartAt  time.Time
		)
		defer func() {
			if together {
				notify(false, "") // the watch is over: the gauge does not stay at 1
			}
		}()
		check := func(now time.Time) {
			// A leg that failed is about to be opened again where it was, or
			// elsewhere; one being opened has no member yet. The state holds
			// through both, so a stream breaking now and then neither says
			// "apart again" nor drops the gauge to bring it back a second on.
			if single || legs[0].failed || legs[1].failed {
				return
			}
			m0, m1 := src.member(0), src.member(1)
			if m0 == "" || m1 == "" {
				return
			}
			on := m0 == m1
			switch {
			case on && !together:
				together, tryAt = true, now.Add(wait)
				traceLeg("together", 1, legs[1].gen, "on "+m0)
				notify(true, m0)
			case !on && together:
				together, apartAt = false, now
				notify(false, m1)
			case on && !now.Before(tryAt):
				wait = min(wait*2, relocateMax)
				tryAt = now.Add(wait)
				l := &legs[1]
				l.cancel()
				traceLeg("moved", 1, l.gen, "off "+m0)
				start(1)
			case !on && !together && !apartAt.IsZero() && now.Sub(apartAt) >= relocateMax:
				wait = relocateMin // apart for long: the next time is a new one
			}
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
					if !legs[i].failed && legs[i].placed.Load() && !legs[i].closed.Load() {
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
					case quiet >= feedStall && src.member(i) != "":
						// (A leg with no member yet is waiting for a connection
						// at the pick: opening it again would pick no sooner.)
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
					case quiet >= feedIdle && l.placed.Load() && !l.closed.Load():
						src.progress(i)
					}
				}
				check(now)
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
	// watch is cl.Watch; a test sets its own.
	watch func(ctx context.Context, key string, opts ...clientv3.OpOption) clientv3.WatchChan
	// openMu serializes the openings, so that the second leg's pick comes
	// after the first's placement is recorded; an opening can wait on a
	// connection, and holds it meanwhile. mu guards trs and ctxs, briefly: the
	// merge loop reads them.
	openMu sync.Mutex
	mu     sync.Mutex
	trs    [2]*tried
	ctxs   [2]context.Context
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
	c.openMu.Lock()
	locked := true
	defer func() {
		if locked {
			c.openMu.Unlock()
		}
	}()
	if ctx.Err() != nil {
		// The leg was ended while this opening waited its turn: its placement
		// is not recorded over the one that has replaced it.
		ch := make(chan clientv3.WatchResponse)
		close(ch)
		return ch, func() {}
	}
	tr := &tried{used: map[string]bool{}}
	c.mu.Lock()
	if prev := c.trs[i]; prev != nil && prev.lastMember() != "" {
		tr.used[prev.lastMember()] = true
	}
	other := c.trs[1-i]
	wctx, cancel := context.WithCancel(withTriedSet(clientv3.WithRequireLeader(ctx), tr))
	wctx = metadata.AppendToOutgoingContext(wctx, "port49-leg", strconv.Itoa(i)+"."+strconv.Itoa(gen))
	c.trs[i], c.ctxs[i] = tr, wctx
	c.mu.Unlock()
	tr.peer.Store(other)
	if other != nil {
		other.peer.Store(tr)
	}
	// Watch returns only after the server's Created, which a member that is
	// ready and hung does not send for 10 to 12 s. The lock is held to the
	// pick, which records the placement the other leg avoids (at most 300 ms
	// when the pick waits for a connection), and not to Created.
	got := make(chan clientv3.WatchChan, 1)
	go func() { got <- c.watchFn()(wctx, c.key, legOpts(from, c.keysOnly)...) }()
	for end := time.Now().Add(300 * time.Millisecond); tr.lastMember() == "" && time.Now().Before(end); {
		time.Sleep(5 * time.Millisecond)
		if len(got) > 0 {
			break
		}
	}
	locked = false
	c.openMu.Unlock()
	ch := <-got
	peer := ""
	if other != nil {
		peer = other.lastMember()
	}
	traceLeg("open", i, gen, "on "+tr.lastMember()+", the other on "+peer)
	return ch, cancel
}

func (c *clientLegs) watchFn() func(context.Context, string, ...clientv3.OpOption) clientv3.WatchChan {
	if c.watch != nil {
		return c.watch
	}
	return c.cl.Watch
}

func (c *clientLegs) progress(i int) error {
	c.mu.Lock()
	ctx := c.ctxs[i]
	c.mu.Unlock()
	return c.cl.RequestProgress(ctx)
}

func (c *clientLegs) probe(ctx context.Context) error { return c.probeFn(ctx) }

func (c *clientLegs) member(i int) string {
	c.mu.Lock()
	tr := c.trs[i]
	c.mu.Unlock()
	if tr != nil {
		return tr.lastMember()
	}
	return ""
}

// followLegs is the two-leg watch of feed (contexts or marks), of key's range on client cl, from revision
// after: the channel of merged responses a handler ranges over as it would a
// single Watch's. probe is a one-key read on cl.
func (s *Store) followLegs(ctx context.Context, feed string, cl *clientv3.Client, key string, after uint64, keysOnly bool,
	probe func(context.Context) error, asks <-chan struct{}) (<-chan clientv3.WatchResponse, error) {
	if !notFragmented(legOpts(1, keysOnly)) {
		return nil, fmt.Errorf("%w: a watch leg is set to fragment its responses, which the merge cannot drop", store.ErrUnavailable)
	}
	src := &clientLegs{cl: cl, key: key, keysOnly: keysOnly, probeFn: probe}
	colo := func(on bool, member string) {
		if on {
			s.logf("etcd: both legs of the %s watch are on one member (%s): it going dark would stall the feed; one leg is moved when another member is ready", feed, member)
		} else if member != "" {
			s.logf("etcd: the legs of the %s watch are on different members again", feed)
		}
		if s.legsColocated != nil {
			s.legsColocated(feed, on)
		}
	}
	return watchLegs(ctx, src, after, asks, s.saw, s.logf, colo, len(cl.Endpoints()) == 1), nil
}
