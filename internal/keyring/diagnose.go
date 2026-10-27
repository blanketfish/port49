package keyring

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/tacacs/wire"
)

// Match is one key version a held packet validates under.
type Match struct {
	KeyRef  string `json:"key_ref"`
	Version int    `json:"version"`
	State   string `json:"state"`
}

// Finding is what the trial found for one device. It names versions, never
// material: no secret and no byte of the held body is in it.
type Finding struct {
	Device   string    `json:"device"`
	Source   string    `json:"source"`
	HeldAt   time.Time `json:"held_at"`
	Assigned string    `json:"assigned"`
	Matches  []Match   `json:"matches"`
}

// Diagnose tries every version of every set — retired ones and other groups'
// included — on device's held packet (spec §10, "Cross-group probing is
// manual"). false is no packet held for it.
func Diagnose(held *Held, sets map[string]Set, device, assigned string, now time.Time) (Finding, bool) {
	p, ok := held.Get(device)
	if !ok {
		return Finding{}, false
	}
	f := Finding{Device: device, Source: p.Source.String(), HeldAt: p.At, Assigned: assigned}
	refs := make([]string, 0, len(sets))
	for ref := range sets {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	for _, ref := range refs {
		s := sets[ref]
		for i, v := range s.Versions {
			if Validates(p.Header, wire.Obfuscate(p.Header, v.Secret.Bytes(), p.Body)) {
				f.Matches = append(f.Matches, Match{KeyRef: ref, Version: v.Number, State: s.State(i, now)})
			}
		}
	}
	return f, true
}

// Text is the finding in one line. It claims no cause the packet cannot
// support: nothing matching may be the device's key or port49d's material,
// and it says so (spec §10, "What this cannot distinguish").
func (f Finding) Text(now time.Time) string {
	head := fmt.Sprintf("%s (%s), packet held %s ago", f.Device, f.Source, now.Sub(f.HeldAt).Round(time.Second))
	if len(f.Matches) == 0 {
		return head + ": validates under nothing port49d holds; the device's key, or the secret port49d reads for " +
			f.Assigned + ", is wrong, and a packet cannot say which (spec §10)"
	}
	parts := make([]string, len(f.Matches))
	for i, m := range f.Matches {
		parts[i] = fmt.Sprintf("%s v%d (%s)", m.KeyRef, m.Version, m.State)
	}
	text := head + ": validates under " + strings.Join(parts, ", ") + "; it is assigned " + f.Assigned
	// The verdict reads the assigned group's match when there is one: two
	// groups sharing a secret is not the device holding another group's key.
	m := f.Matches[0]
	for _, c := range f.Matches {
		if c.KeyRef == f.Assigned {
			m = c
			break
		}
	}
	switch {
	case m.KeyRef == f.Assigned && m.State == "retired":
		text += ": the device was missed in the rotation"
	case m.KeyRef != f.Assigned:
		text += fmt.Sprintf(": the device holds %s's key, another group's", m.KeyRef)
	}
	return text
}
