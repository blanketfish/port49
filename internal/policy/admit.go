package policy

import (
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"github.com/rhwendt/port49/internal/admission"
)

// buildKeyGroups reads key_groups (spec §10). A group matches on a CIDR or on
// attributes, never both, since each tier is its own rule. Two groups that tie
// for every device they could match — one prefix twice, one attribute set
// twice — are the policy's own error and refused, naming both; a tie only
// some devices meet refuses those devices (admit; plan 6a owner decision 1).
func (p *Policy) buildKeyGroups(f file) error {
	switch {
	case len(f.KeyGroups) > 0 && len(p.env.InventoryKeyGroups) > 0:
		// Mid-migration: this file's block wins, so a reload or restart
		// between adding it here and deleting it there loads (plan 6a C3).
		p.notices = append(p.notices, fmt.Sprintf("key_groups: the inventory file's block (%d group(s)) is "+
			"ignored, since the policy file has its own; delete it from the inventory file (spec §10)",
			len(p.env.InventoryKeyGroups)))
	case len(f.KeyGroups) == 0:
		p.keyGroups = slices.Clone(p.env.InventoryKeyGroups)
		if len(p.keyGroups) > 0 {
			p.notices = append(p.notices, "key_groups are read from the inventory file; move the block into "+
				"the policy file, where key assignment is reviewed (spec §10)")
		}
		return nil
	}
	cidrs := map[netip.Prefix]string{}
	attrs := map[string]string{}
	for i, g := range f.KeyGroups {
		at := fmt.Sprintf("key_groups[%d]", i)
		if g.KeyRef == "" {
			return fmt.Errorf("%s: key_ref is required: every group names the key it admits", at)
		}
		kg := admission.KeyGroup{Attributes: g.Match.Attributes, KeyRef: g.KeyRef}
		if g.Match.CIDR != "" {
			pfx, err := netip.ParsePrefix(g.Match.CIDR)
			if err != nil {
				return fmt.Errorf("%s: %w", at, err)
			}
			if pfx != pfx.Masked() {
				return fmt.Errorf("%s: cidr %s has host bits set; write %s", at, pfx, pfx.Masked())
			}
			kg.CIDR = pfx
		}
		switch {
		case kg.CIDR.IsValid() && len(kg.Attributes) > 0:
			return fmt.Errorf("%s: match on cidr or on attributes, not both: each tier is its own group (spec §10)", at)
		case !kg.CIDR.IsValid() && len(kg.Attributes) == 0:
			return fmt.Errorf("%s: matches on neither cidr nor attributes, so it would admit the whole fleet under %s; "+
				"give it one", at, kg.KeyRef)
		case kg.CIDR.IsValid():
			if prev, dup := cidrs[kg.CIDR]; dup {
				return fmt.Errorf("%s: %s and %s tie for every device in %s (spec §10); keep one", at, prev, kg, kg.CIDR)
			}
			cidrs[kg.CIDR] = kg.String()
		default:
			key := matchKey(kg.Attributes)
			if prev, dup := attrs[key]; dup {
				return fmt.Errorf("%s: %s and %s tie for every device they match (spec §10); keep one", at, prev, kg)
			}
			attrs[key] = kg.String()
		}
		p.keyGroups = append(p.keyGroups, kg)
	}
	return nil
}

// matchKey is an attribute set in one spelling, so two groups naming the
// same pairs in another order are seen to tie.
func matchKey(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%q=%q;", k, m[k])
	}
	return b.String()
}

// admit decides each inventory device's admission (spec §10): its key_ref by
// tier, or why it is refused — a transport port49d does not serve, no group
// matches it, two tie on it (admission.Resolve), or its key_ref is not one
// port49d.yaml defines (Env.KeyRefs). A refused device is refused alone; the
// policy and the rest of the fleet load (plan 6a Decided 5).
// It is a Parse step, after buildKeyGroups and before buildTests.
func (p *Policy) admit(file) error {
	p.admitted = make(map[string]admission.Resolved, len(p.env.Devices))
	p.assigned = make(map[string]admission.Assignment, len(p.env.Devices))
	entries := make([]admission.Resolved, 0, len(p.env.Devices))
	for _, d := range p.env.Devices {
		r := admission.Resolve(d, p.keyGroups)
		if r.Refused == "" && p.env.KeyRefs != nil && !slices.Contains(p.env.KeyRefs, r.KeyRef) {
			// A refused entry carries no key_ref, since a reader takes one as
			// admitted; the text names the key instead (Task 3 review M3).
			r.Refused, r.Refusal = fmt.Sprintf("is assigned key_ref %s, which port49d.yaml defines no key for, so "+
				"it fails closed (spec §10)", r.KeyRef), admission.RefusedUnknownKey
			r.KeyRef = ""
		}
		// How the key_ref was chosen, for `port49 keys show`; a tie has none.
		if as, err := admission.Assign(d, p.keyGroups); err == nil {
			p.assigned[d.Name] = as
		}
		p.admitted[d.Name] = r
		entries = append(entries, r)
	}
	trie, err := admission.NewTrie(entries)
	if err != nil {
		return err
	}
	p.trie = trie
	return nil
}

// Admission is the address index port49d admits from: every inventory
// device, a refused one with its cause (spec §10).
func (p *Policy) Admission() *admission.Trie { return p.trie }

// Admitted is one device's admission, by inventory name.
func (p *Policy) Admitted(name string) (admission.Resolved, bool) {
	r, ok := p.admitted[name]
	return r, ok
}

// AdmissionRefusals are the inventory devices admission refuses, by name. It
// is meaningful only where AdmissionAssessed: on an unassessed policy every
// device is refused no_key_group, and nothing acts on it.
func (p *Policy) AdmissionRefusals() []admission.Resolved {
	var out []admission.Resolved
	for _, name := range sortedKeys(p.admitted) {
		if r := p.admitted[name]; r.Refused != "" {
			out = append(out, r)
		}
	}
	return out
}

// KeyAssignment is how a device's key_ref was chosen, for `port49 keys show`:
// not whether it is admitted, since a device refused for an unknown key or
// its transport still has one. Read Admitted for that.
func (p *Policy) KeyAssignment(name string) (admission.Assignment, bool) {
	as, ok := p.assigned[name]
	return as, ok
}

// KeyGroups are the groups in force, whichever file they came from.
func (p *Policy) KeyGroups() []admission.KeyGroup { return slices.Clone(p.keyGroups) }

// Notices are what the load says without refusing: port49d prints each at
// start and at every reload that loads.
func (p *Policy) Notices() []string { return slices.Clone(p.notices) }

// AdmissionAssessed reports whether admission decides anything here: key
// groups are declared, in either file, or port49d's key names are known
// (Env.KeyRefs, which port49d always sets). An offline tool given neither —
// most of the test corpus — resolves every device as before.
func (p *Policy) AdmissionAssessed() bool { return len(p.keyGroups) > 0 || p.env.KeyRefs != nil }
