package inventory

import (
	"context"
	"sync"
	"time"
)

// Debouncer turns webhook deliveries into syncs of their source (decision
// 31). The first delivery is synced settle after it, so a burst is one
// sync; a source is synced from webhooks no sooner than gap after its last
// webhook sync began; a delivery during a sync brings one more after it,
// since the change it announces may have come after the sync read the
// source. At most one sync per source is pending, so a flood of authentic
// deliveries costs one sync per gap and queues nothing.
type Debouncer struct {
	settle, gap time.Duration
	fire        func(ctx context.Context, source string)
	kick        map[string]chan struct{}
}

func NewDebouncer(sources []string, settle, gap time.Duration, fire func(context.Context, string)) *Debouncer {
	d := &Debouncer{settle: settle, gap: gap, fire: fire, kick: map[string]chan struct{}{}}
	for _, s := range sources {
		d.kick[s] = make(chan struct{}, 1)
	}
	return d
}

// Notify asks for a sync of source. It never blocks: a source with a sync
// pending is not asked twice, and one Run does not know is ignored.
func (d *Debouncer) Notify(source string) {
	if ch, ok := d.kick[source]; ok {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// Run starts one goroutine per source, each added to wg and ended by ctx.
func (d *Debouncer) Run(ctx context.Context, wg *sync.WaitGroup) {
	for name, ch := range d.kick {
		wg.Add(1)
		go func(name string, ch chan struct{}) {
			defer wg.Done()
			var last time.Time
			for {
				select {
				case <-ctx.Done():
					return
				case <-ch:
				}
				wait := d.settle
				if !last.IsZero() {
					if g := time.Until(last.Add(d.gap)); g > wait {
						wait = g
					}
				}
				t := time.NewTimer(wait)
				select {
				case <-ctx.Done():
					t.Stop()
					return
				case <-t.C:
				}
				// Deliveries during the wait are covered by the sync about to
				// start; only those during the sync bring another.
				select {
				case <-ch:
				default:
				}
				last = time.Now()
				d.fire(ctx, name)
			}
		}(name, ch)
	}
}
