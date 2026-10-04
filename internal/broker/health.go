package broker

import (
	"fmt"
	"net/http"
)

// The lines /readyz answers (design §17). Readiness is whether the broker
// serves, and nothing else: store health, certificate status and
// broker.revocations_file's health are alarms, never readiness, or a store
// fault would take every replica out at once (design §12; decision 34).
// The one exception is a mint gate shut on a swap's mark (ReadyFlagging):
// that replica mints nothing at all until its mark lands, and only the
// replicas whose swap is not yet marked are out.
const (
	ReadyStarting = "starting: the broker is not serving yet"
	ReadyServing  = "serving"
	ReadyDraining = "draining: port49d is shutting down"
	// ReadyFlagging is a serving broker whose mint gate refuses the policy
	// in force (MintGate): it mints nothing, so a load balancer sends mints
	// elsewhere (Task 15a re-review 2, M-8).
	ReadyFlagging = "flagging: the broker mints nothing until the store records the bundle it serves"
)

// ReadyDrainingOf is ReadyDraining for the process named proc: "port49d"
// or "port49-broker".
func ReadyDrainingOf(proc string) string { return "draining: " + proc + " is shutting down" }

// SetReady sets what /readyz answers: 200 for ReadyServing, 503 with the line
// for anything else. Before the first call it answers ReadyStarting.
func (b *Broker) SetReady(state string) { b.ready.Store(&state) }

// healthz answers 200 while the handler answers. It needs no certificate,
// reads nothing, and writes no record.
func (b *Broker) healthz(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") }

// readyz answers SetReady's state, with no certificate and no record;
// serving, it answers ReadyFlagging while the mint gate refuses the policy
// in force.
func (b *Broker) readyz(w http.ResponseWriter, _ *http.Request) {
	why := ReadyStarting
	if p := b.ready.Load(); p != nil {
		why = *p
	}
	if why == ReadyServing && b.MintGate != nil && b.MintGate(b.Policy.Load()) != nil {
		why = ReadyFlagging
	}
	if why == ReadyServing {
		fmt.Fprintln(w, why)
		return
	}
	http.Error(w, why, http.StatusServiceUnavailable)
}
