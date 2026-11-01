package keyring

import (
	"sort"
	"time"

	"github.com/blanketfish/port49/internal/tacacs/wire"
)

// Match is one key version a packet validates under.
type Match struct {
	KeyRef  string `json:"key_ref"`
	Version int    `json:"version"`
	State   string `json:"state"`
}

// Try tries every version of every set — retired ones and other groups'
// included — on one packet (spec §10, "Cross-group probing is manual"), and
// names the versions it validates under, by key_ref then version. It names
// versions, never material: no secret and no byte of body is in a Match. It
// holds nothing: `port49d keys-diagnose` calls it on a packet read from a
// capture, offline.
func Try(h wire.Header, body []byte, sets map[string]Set, now time.Time) []Match {
	refs := make([]string, 0, len(sets))
	for ref := range sets {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	var out []Match
	for _, ref := range refs {
		s := sets[ref]
		for i, v := range s.Versions {
			if Validates(h, wire.Obfuscate(h, v.Secret.Bytes(), body)) {
				out = append(out, Match{KeyRef: ref, Version: v.Number, State: s.State(i, now)})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].KeyRef != out[j].KeyRef {
			return out[i].KeyRef < out[j].KeyRef
		}
		return out[i].Version < out[j].Version
	})
	return out
}
