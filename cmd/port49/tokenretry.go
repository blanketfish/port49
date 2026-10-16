package main

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/broker/api"
)

// storeRetryBudget is how long `port49 token` keeps trying a mint refused
// store_unavailable, and storeRetryDefault the wait when the reply names none.
const (
	storeRetryBudget  = 30 * time.Second
	storeRetryDefault = 5 * time.Second
)

// retryClock is the time `port49 token` waits by; tests replace it so no test
// sleeps.
type retryClock struct {
	now   func() time.Time
	sleep func(time.Duration)
}

var tokenRetryClock = retryClock{now: time.Now, sleep: time.Sleep}

// mintRetrying is mint, run again while the broker refuses it
// store_unavailable (its start gate after a restart, spec §5.7): after the
// reply's Retry-After, 5s when it carries none, for up to 30s from the first
// try. It retries no other failure, and a wait that would pass the 30s is not
// made: the last error stands, as it did before the retry existed.
func mintRetrying(mint func() (api.MintItem, error), clk retryClock, cmd string, stderr io.Writer) (api.MintItem, error) {
	start := clk.now()
	for {
		item, err := mint()
		var su *agent.StoreUnavailableError
		if !errors.As(err, &su) {
			return item, err
		}
		wait := cmp.Or(su.RetryAfter, storeRetryDefault)
		if wait > storeRetryBudget-clk.now().Sub(start) {
			return item, err
		}
		fmt.Fprintf(stderr, "%s: the broker is not ready yet; trying again in %ds\n", cmd, int(wait/time.Second))
		clk.sleep(wait)
	}
}
