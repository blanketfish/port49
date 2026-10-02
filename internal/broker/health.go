package broker

import (
	"fmt"
	"net/http"
)

// The lines /readyz answers (design §17). Readiness is whether the broker
// serves, and nothing else: store health, certificate status and
// broker.revocations_file's health are alarms, never readiness, or a store
// fault would take every replica out at once (design §12; decision 34).
const (
	ReadyStarting = "starting: the broker is not serving yet"
	ReadyServing  = "serving"
	ReadyDraining = "draining: port49d is shutting down"
)

// SetReady sets what /readyz answers: 200 for ReadyServing, 503 with the line
// for anything else. Before the first call it answers ReadyStarting.
func (b *Broker) SetReady(state string) { b.ready.Store(&state) }

// healthz answers 200 while the handler answers. It needs no certificate,
// reads nothing, and writes no record.
func (b *Broker) healthz(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") }

// readyz answers SetReady's state, with no certificate and no record.
func (b *Broker) readyz(w http.ResponseWriter, _ *http.Request) {
	why := ReadyStarting
	if p := b.ready.Load(); p != nil {
		why = *p
	}
	if why == ReadyServing {
		fmt.Fprintln(w, why)
		return
	}
	http.Error(w, why, http.StatusServiceUnavailable)
}
