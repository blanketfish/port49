package port49d

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// keyRetryInterval is how often a policy refused because a key's secret
// could not be read is tried again: half kubelet's default Secret sync period
// (60s), so a key a Secret volume or an agent renders is in force within
// about half a minute of its file appearing, at the cost of one open per
// unread reference per try.
const keyRetryInterval = 30 * time.Second

// keyRetrySayEvery bounds how often a try that fails again is said.
const keyRetrySayEvery = 10 * time.Minute

// keyWait is a policy version refused because a key's secret could not be
// read. It is tried again until it loads or the file holds another version.
type keyWait struct {
	v     string    // the policy version waiting
	next  time.Time // when the poll tries it again
	said  time.Time // when its refusal was last said
	tries int       // tries since then
}

// waitForKeys records a refusal of version v for err and reports whether to
// say it, with the note to add: a key secret that could not be read is said
// in full the first time and on SIGHUP, and then at most every
// keyRetrySayEvery; any other refusal is said as before and not retried.
func (r *reloader) waitForKeys(v, trigger string, err error) (say bool, note string) {
	var unread *keyUnreadError
	if !errors.As(err, &unread) {
		r.keyWait = keyWait{}
		return true, ""
	}
	now := r.now()
	if r.keyWait.v != v {
		r.keyWait = keyWait{v: v, next: now.Add(keyRetryInterval), said: now}
		return true, fmt.Sprintf("; tried again every %v until it can be read or the policy changes",
			keyRetryInterval)
	}
	r.keyWait.tries++
	r.keyWait.next = now.Add(keyRetryInterval)
	if trigger != "SIGHUP" && now.Sub(r.keyWait.said) < keyRetrySayEvery {
		return false, ""
	}
	note = fmt.Sprintf("; still waiting: %d tries since %s, every %v", r.keyWait.tries,
		r.keyWait.said.UTC().Format(time.RFC3339), keyRetryInterval)
	r.keyWait.said, r.keyWait.tries = now, 0
	return true, note
}

// retryKeys tries the waiting policy again: at once for a trigger, else when
// due. A file that now holds another version ends the wait; the watch loads
// that one.
func (r *reloader) retryKeys(ctx context.Context, trigger string) {
	w := r.keyWait
	if w.v == "" {
		return
	}
	if w.v != r.refused {
		r.keyWait = keyWait{}
		return
	}
	if trigger == "" {
		if r.now().Before(w.next) {
			return
		}
		trigger = "key secret retry"
	}
	raw, v, err := policyVersion(r.cfg.Policy.File)
	if err != nil || v != w.v {
		r.keyWait = keyWait{}
		return
	}
	if r.load(ctx, trigger, raw, v, nil) {
		r.keyWait = keyWait{}
		r.retryInventory(ctx, trigger)
	}
}
