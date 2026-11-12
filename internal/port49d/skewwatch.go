package port49d

import (
	"fmt"
	"io"
	"sync"
	"time"
)

// skewWindow is how long the watch stays quiet after it speaks.
const skewWindow = 10 * time.Minute

// skewWatch says, at most once a skewWindow, that a token was minted ahead of
// this host's clock (authen.SkewWatch). Expiry on etcd is the record's, read
// against port49d's clock (design §12), so the broker's clock running ahead
// lengthens every token by the skew; running behind shortens it, and a token
// 30s behind is dead on arrival, which no lookup can see. The counter
// port49_token_minted_ahead_total moves on every lookup; this line is for the
// operator who reads the log.
type skewWatch struct {
	out  io.Writer
	now  func() time.Time
	proc string

	mu   sync.Mutex
	next time.Time
}

func newSkewWatch(out io.Writer, now func() time.Time, proc string) *skewWatch {
	return &skewWatch{out: out, now: now, proc: proc}
}

// Ahead is told that a token's minted_at is by ahead of this clock.
func (w *skewWatch) Ahead(by time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.now()
	if now.Before(w.next) {
		return
	}
	w.next = now.Add(skewWindow)
	fmt.Fprintf(w.out, "%s: clock: a token was minted %s ahead of this host's clock: the broker's clock runs ahead of this "+
		"host's, so every token lives that much longer here, and a broker clock behind this one by more than a token_ttl "+
		"mints tokens that are dead on arrival (token_not_found). Keep every broker and port49d host on NTP\n",
		w.proc, by.Round(time.Second))
}
