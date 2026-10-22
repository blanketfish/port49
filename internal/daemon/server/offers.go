package server

import (
	"net/netip"
	"sync"

	"github.com/rhwendt/port49/internal/admission"
)

// offers counts, per source, the open connections port49 offered
// single-connect to on the RFC 9887 listener (spec §13 decision 50 ruling
// 20). A device that honors the offer keeps the one connection; a second
// one while it is open is the sign the device ignored it, counted at Accept
// as single_connect_second_connection, long before its connections reach the
// per-source cap. A connection counts from its first packet, when the offer
// is made, so one still in its handshake is not counted against itself.
type offers struct {
	mu sync.Mutex
	n  map[netip.Addr]int
}

func newOffers() *offers { return &offers{n: map[netip.Addr]int{}} }

// open counts an offered connection from src.
func (o *offers) open(src netip.Addr) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.n[src]++
}

// close releases what open counted, with the connection's slot.
func (o *offers) close(src netip.Addr) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.n[src]--; o.n[src] <= 0 {
		delete(o.n, src)
	}
}

// any reports whether src has an offered connection open.
func (o *offers) any(src netip.Addr) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.n[src] > 0
}

// wirePlatform is the shipped platform whose wire facts dev is read by: its
// own, or its `based_on:` base (spec §8).
func wirePlatform(dev admission.Resolved) string {
	if dev.WirePlatform != "" {
		return dev.WirePlatform
	}
	return dev.Device.Platform
}
