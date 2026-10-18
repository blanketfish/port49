package port49d

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/store"
)

// directoryCheckEvery is how often a process reads the directory store to
// confirm its copy (plan 11a, R17); a variable so a test can shorten it.
var directoryCheckEvery = time.Second

// keepFresh reads the directory store every directoryCheckEvery, each read
// within timeout, and tells fresh; it says on out, begun with proc, when the
// directory stops answering and when it answers again, with the copy's age,
// until ctx ends. A handle not yet opened does not answer.
func keepFresh(ctx context.Context, h *dirHandle, fresh *store.Freshness, timeout time.Duration, out io.Writer,
	proc string, shared bool) {
	t := time.NewTicker(directoryCheckEvery)
	defer t.Stop()
	for {
		err := errNoDirectory
		if s := h.get(); s != nil {
			cctx, cancel := context.WithTimeout(ctx, timeout)
			err = s.Ping(cctx)
			cancel()
		}
		if ctx.Err() != nil {
			return
		}
		age, ok := fresh.Age()
		switch fresh.Checked(err) {
		case store.Stopped:
			if shared {
				fmt.Fprintln(out, sharedDownLine(proc, err))
				break
			}
			fmt.Fprintf(out, "%s: directory store: not answering (%s): serving from the cache %s; revocations, "+
				"lifts, enrollments, unlocks and second-factor resets are refused until it answers\n", proc,
				printsafeErr(err), confirmedText(age, ok))
		case store.Resumed:
			if shared {
				fmt.Fprintln(out, sharedUpLine(proc))
				break
			}
			fmt.Fprintf(out, "%s: directory store: answering again; the cache was %s\n", proc, oldText(age, ok))
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// sharedDownLine and sharedUpLine are the outage lines of a one-store
// deployment: there is no cache to serve from, so the broker refuses what
// needs the store (the API answers 503 store_unavailable) until it answers.
func sharedDownLine(proc string, err error) string {
	return proc + ": store: not answering (" + outageCause(err) + "): this broker refuses requests until it returns"
}

// outageCause is the closed-set cause of a failed read, never the error's
// text, which can echo what a peer sent.
func outageCause(err error) string {
	switch {
	case errors.Is(err, errNoDirectory):
		return "not opened yet"
	case errors.Is(err, context.DeadlineExceeded):
		return "timed out"
	default:
		return "unreachable"
	}
}

func sharedUpLine(proc string) string { return proc + ": store: answering again" }

// ageText is d as port49 store status prints a cache age: tenths of a
// second under a minute, whole seconds above.
func ageText(d time.Duration) string {
	if d < time.Minute {
		return strconv.FormatFloat(d.Seconds(), 'f', 1, 64) + "s"
	}
	return d.Round(time.Second).String()
}

func confirmedText(age time.Duration, ok bool) string {
	if !ok {
		return "never confirmed"
	}
	return "confirmed " + ageText(age) + " ago"
}

func oldText(age time.Duration, ok bool) string {
	if !ok {
		return "never confirmed"
	}
	return ageText(age) + " old"
}

// tellFresh has fresh tell m's two directory gauges (plan 11a, R17).
func tellFresh(fresh *store.Freshness, m *metrics.Metrics) {
	fresh.Tell(func(at time.Time) { m.StoreDirectoryConfirmed.Set(float64(at.Unix())) },
		func(r bool) { m.StoreDirectoryReachable.Set(b2f(r)) })
}
