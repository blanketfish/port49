package policy

import (
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"github.com/rhwendt/port49/internal/admission"
)

// buildKeyGroups reads key_groups (spec §10). A group matches on exactly one
// of a device name, a CIDR or attributes, since each tier is its own rule. Two
// groups that tie for every device they could match — one name twice, one
// prefix twice, one attribute set twice — are the policy's own error and
// refused, naming both; a tie only some devices meet refuses those devices
// (admit; plan 6a owner decision 1). A name group naming a device the
// inventory lacks is kept, as a scope's pinned name is: a device racked later
// takes it.
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
	names := map[string]string{}
	cidrs := map[netip.Prefix]string{}
	attrs := map[string]string{}
	for i, g := range f.KeyGroups {
		at := fmt.Sprintf("key_groups[%d]", i)
		if g.KeyRef == "" {
			return fmt.Errorf("%s: key_ref is required: every group names the key it admits", at)
		}
		if !admission.KeyRefShape.MatchString(g.KeyRef) {
			return fmt.Errorf("%s: key_ref is not a valid key_ref name (%s): it names the key, never holds it",
				at, admission.KeyRefShapeRule)
		}
		kg := admission.KeyGroup{Name: g.Match.Name, Attributes: g.Match.Attributes, KeyRef: g.KeyRef}
		// Not quoted: a value that is no name is not echoed. 253 is the
		// broker's maxDeviceName (a DNS name's length); broker imports this
		// package, so the two are kept equal by hand.
		if kg.Name != "" && (len(kg.Name) > 253 ||
			strings.IndexFunc(kg.Name, func(r rune) bool { return r < 0x21 || r > 0x7e }) >= 0) {
			return fmt.Errorf("%s: match.name is not a device name", at)
		}
		if g.Match.CIDR != "" {
			// netip's error quotes the value; the position says where it is.
			pfx, err := netip.ParsePrefix(g.Match.CIDR)
			if err != nil {
				return fmt.Errorf("%s: match.cidr is not a CIDR prefix", at)
			}
			if pfx != pfx.Masked() {
				return fmt.Errorf("%s: cidr %s has host bits set; write %s", at, pfx, pfx.Masked())
			}
			kg.CIDR = pfx
		}
		terms := 0
		for _, given := range []bool{kg.Name != "", kg.CIDR.IsValid(), len(kg.Attributes) > 0} {
			if given {
				terms++
			}
		}
		switch {
		case terms > 1:
			return fmt.Errorf("%s: match on exactly one of name, cidr or attributes: each tier is its own group (spec §10)", at)
		case terms == 0:
			return fmt.Errorf("%s: matches on neither name, cidr nor attributes, so it would admit the whole fleet under %s; "+
				"give it one", at, kg.KeyRef)
		case kg.Name != "":
			if prev, dup := names[kg.Name]; dup {
				return fmt.Errorf("%s: %s and %s tie for device %s (spec §10); keep one", at, prev, kg, kg.Name)
			}
			names[kg.Name] = kg.String()
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
// tier, or why it is refused — a transport that is neither tcp nor tls, no group
// matches it, two tie on it (admission.Resolve), or its key_ref is not one
// port49d.yaml defines (Env.KeyRefs). A refused device is refused alone; the
// policy and the rest of the fleet load (plan 6a Decided 5).
// It is a Parse step, after buildKeyGroups and before buildTests.
func (p *Policy) admit(file) error {
	p.admitted = make(map[string]admission.Resolved, len(p.env.Devices))
	p.assigned = make(map[string]admission.Assignment, len(p.env.Devices))
	entries := make([]admission.Resolved, 0, len(p.env.Devices))
	clashes := admission.TLSNameClashes(p.env.Devices)
	for _, d := range p.env.Devices {
		r := admission.Resolve(d, p.keyGroups)
		if why, clash := clashes[d.Name]; clash {
			r.Refused, r.Refusal = why, admission.RefusedTLSNameClash
		}
		r.WirePlatform = p.WirePlatform(d.Platform)
		if r.Refused == "" && d.EffectiveTransport() != admission.TransportTLS && p.env.KeyRefs != nil &&
			!slices.Contains(p.env.KeyRefs, r.KeyRef) {
			// A refused entry carries no key_ref, since a reader takes one as
			// admitted; the text names the key instead (Task 3 review M3).
			r.Refused, r.Refusal = fmt.Sprintf("is assigned key_ref %s, which port49d.yaml defines no key for, so "+
				"it fails closed (spec §10)", r.KeyRef), admission.RefusedUnknownKey
			r.KeyRef = ""
		}
		// How the key_ref was chosen, for `port49 keys show`; a tie has none,
		// and a TLS device takes no key (decision 50 ruling 3).
		if d.EffectiveTransport() != admission.TransportTLS {
			if as, err := admission.Assign(d, p.keyGroups); err == nil {
				p.assigned[d.Name] = as
			}
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

// AdmissionRefusals are the inventory devices admission refuses, by name. On
// an unassessed policy — no key groups and no Env.KeyRefs — every device not
// pinned on its record is refused no_key_group, which is what port49d, always
// assessing, would refuse; an offline tool reads it so (plan 6a, I1).
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

// Raw is the policy file's bytes as loaded.
func (p *Policy) Raw() []byte { return slices.Clone(p.raw) }

// Inventory is the inventory this policy was loaded against, as read: the
// devices and any key groups the inventory file still carried.
func (p *Policy) Inventory() admission.Inventory {
	return admission.Inventory{Devices: slices.Clone(p.env.Devices), KeyGroups: slices.Clone(p.env.InventoryKeyGroups)}
}

// WirePlatform is the shipped platform whose facts port49 reads for name
// (spec §8): the one a `based_on:` block names, or name itself. A variant
// is the same device under another name, so its session services, exec
// records, system users, session discriminator, built-in redaction and
// keyword tree are its base's.
func (p *Policy) WirePlatform(name string) string {
	if b, ok := p.overrides[name]; ok && b.BasedOn != "" {
		return b.BasedOn
	}
	return name
}
