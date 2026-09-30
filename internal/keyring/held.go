package keyring

import (
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/rhwendt/port49/internal/tacacs/wire"
)

// Held keeps, per admitted device, the last packet no key it is assigned
// validated: the header and the body as it arrived, obfuscated. It is what
// `port49 keys diagnose` tries other material on, by hand (spec §10); nothing
// tries it automatically. It is in memory only and never logged — the body is
// attacker-controlled bytes — and one entry per device bounds it by the
// inventory.
type Held struct {
	mu sync.Mutex
	m  map[string]HeldPacket
}

// HeldPacket is one held packet.
type HeldPacket struct {
	Source netip.Addr
	Header wire.Header
	Body   []byte
	At     time.Time
}

// Put holds a copy of body as device's latest unvalidated packet.
func (h *Held) Put(device string, src netip.Addr, hdr wire.Header, body []byte, at time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.m == nil {
		h.m = map[string]HeldPacket{}
	}
	h.m[device] = HeldPacket{Source: src, Header: hdr, Body: slices.Clone(body), At: at}
}

// Get is device's held packet.
func (h *Held) Get(device string) (HeldPacket, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	p, ok := h.m[device]
	return p, ok
}

// Keep drops the packet of every device assigned, the bundle in force's
// key_ref for a device, says is no longer admitted (""), so keys diagnose
// answers only for a device port49d admits. A re-keyed device's packet is
// kept: diagnose tries every key port49d holds (plan 6a final review m6).
func (h *Held) Keep(assigned func(device string) string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for d := range h.m {
		if assigned(d) == "" {
			delete(h.m, d)
		}
	}
}
