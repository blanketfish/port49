package bundle

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/policy"
)

// What a swap can change about a device (spec §10), as `port49 inventory
// diff` prints them and inventory_change records name the security ones.
const (
	DeviceAdded       = "device_added"
	DeviceRemoved     = "device_removed"
	PlatformChanged   = "platform_changed"
	AttributesChanged = "attributes_changed"
	AddressAdded      = "address_added"
	AddressRemoved    = "address_removed"
	KeyRefChanged     = "key_ref_changed"
	AdmissionChanged  = "admission_changed"
	ScopeJoined       = "scope_joined"
	ScopeLeft         = "scope_left"
)

// Change is one thing a swap changed. From and To are the before and after
// where the kind has them.
type Change struct {
	Kind     string `json:"kind,omitempty"`
	Device   string `json:"device,omitempty"`
	Platform string `json:"platform,omitempty"`
	Scope    string `json:"scope,omitempty"`
	Address  string `json:"address,omitempty"`
	From     string `json:"from,omitempty"`
	To       string `json:"to,omitempty"`
	// Security marks what the log must carry as an inventory_change record:
	// an address added to a device already in inventory — the mint response
	// hands it to an SSH client, so a rogue one is a credential-capture path —
	// a device joining or leaving a scope with security_log: true (spec §5.5,
	// §10), a device's key_ref changing, and a device becoming admitted.
	Security bool `json:"security"`
}

// Line is c on one line, `!` first where the log would carry it as a
// security event. addresses is the device's in the new inventory, for an
// added device: each is a new place a mint sends an operator. Empty, where
// the caller has none to give, the line leaves them out.
func (c Change) Line(addresses string) string {
	mark := " "
	if c.Security {
		mark = "!"
	}
	switch c.Kind {
	case DeviceAdded:
		if addresses == "" {
			return fmt.Sprintf("%s device added %s (%s): %s", mark, c.Device, c.Platform, c.To)
		}
		return fmt.Sprintf("%s device added %s (%s) at %s: %s", mark, c.Device, c.Platform, addresses, c.To)
	case DeviceRemoved:
		return fmt.Sprintf("%s device removed %s (%s)", mark, c.Device, c.Platform)
	case AddressAdded:
		return fmt.Sprintf("%s address added %s: %s", mark, c.Device, c.Address)
	case AddressRemoved:
		return fmt.Sprintf("%s address removed %s: %s", mark, c.Device, c.Address)
	case ScopeJoined, ScopeLeft:
		verb, tag := "joined", ""
		if c.Kind == ScopeLeft {
			verb = "left"
		}
		if c.Security {
			tag = " (security_log)"
		}
		return fmt.Sprintf("%s scope %s%s: %s %s", mark, c.Scope, tag, c.Device, verb)
	}
	return fmt.Sprintf("%s %s %s: %s → %s", mark, c.Kind, c.Device, c.From, c.To)
}

// Report is what one swap changed.
type Report struct {
	From, To                string
	Added, Removed, Changed int
	Changes                 []Change
}

// Diff compares two bundles. A scope is compared only where both declare it:
// a scope a policy edit added or removed is the policy diff's (spec §12).
func Diff(old, new *policy.Policy, now time.Time) Report {
	rep := Report{From: old.Bundle, To: new.Bundle}
	before, after := byName(old.Devices()), byName(new.Devices())
	names := unionNames(before, after)
	changed := map[string]bool{}
	add := func(c Change) {
		rep.Changes = append(rep.Changes, c)
		if _, was := before[c.Device]; was {
			if _, is := after[c.Device]; is {
				changed[c.Device] = true
			}
		}
	}
	for _, name := range names {
		o, inOld := before[name]
		n, inNew := after[name]
		switch {
		case !inOld:
			rep.Added++
			// An added device that is admitted starts being answered, and its
			// addresses are new capture targets: a security change, as a
			// device already in inventory becoming admitted is (N5).
			state := admissionState(new, name, now)
			add(Change{Kind: DeviceAdded, Device: name, Platform: n.Platform, To: state, Security: state == "admitted"})
		case !inNew:
			rep.Removed++
			add(Change{Kind: DeviceRemoved, Device: name, Platform: o.Platform})
		default:
			if o.Platform != n.Platform {
				add(Change{Kind: PlatformChanged, Device: name, Platform: n.Platform, From: o.Platform, To: n.Platform})
			}
			if !maps.Equal(o.Attributes, n.Attributes) {
				add(Change{Kind: AttributesChanged, Device: name, Platform: n.Platform, From: attrs(o.Attributes),
					To: attrs(n.Attributes)})
			}
			for _, a := range minus(n.Addresses, o.Addresses) {
				add(Change{Kind: AddressAdded, Device: name, Platform: n.Platform, Address: a.String(), Security: true})
			}
			for _, a := range minus(o.Addresses, n.Addresses) {
				add(Change{Kind: AddressRemoved, Device: name, Platform: n.Platform, Address: a.String()})
			}
			ro, _ := old.Admitted(name)
			rn, _ := new.Admitted(name)
			// A key_ref change moves the device onto another key — a pin in
			// the inventory can pick a weaker or a shared one — and a device
			// becoming admitted starts being answered: both are security
			// changes (plan 6a, I5). A refused entry carries no key_ref, so
			// the keys are compared only where both sides admit the device;
			// a flip is the admission_changed below.
			if ro.Refused == "" && rn.Refused == "" && ro.KeyRef != rn.KeyRef {
				add(Change{Kind: KeyRefChanged, Device: name, Platform: n.Platform, From: ro.KeyRef, To: rn.KeyRef,
					Security: true})
			}
			if so, sn := admissionState(old, name, now), admissionState(new, name, now); so != sn {
				add(Change{Kind: AdmissionChanged, Device: name, Platform: n.Platform, From: so, To: sn,
					Security: sn == "admitted"})
			}
		}
	}
	oldScopes := map[string]*policy.Scope{}
	for _, s := range old.Scopes() {
		oldScopes[s.Name] = s
	}
	for _, s := range new.Scopes() {
		os, ok := oldScopes[s.Name]
		if !ok {
			continue
		}
		security := s.SecurityLog || os.SecurityLog
		for _, name := range names {
			var was, is bool
			platform := ""
			if d, ok := before[name]; ok {
				was, platform = os.Selects(d), d.Platform
			}
			if d, ok := after[name]; ok {
				is, platform = s.Selects(d), d.Platform
			}
			switch {
			case is && !was:
				add(Change{Kind: ScopeJoined, Device: name, Platform: platform, Scope: s.Name, Security: security})
			case was && !is:
				add(Change{Kind: ScopeLeft, Device: name, Platform: platform, Scope: s.Name, Security: security})
			}
		}
	}
	rep.Changed = len(changed)
	return rep
}

// Summary is the one line port49d writes for a swap (spec §10, "Every swap
// logs a summary").
func (r Report) Summary() string {
	return fmt.Sprintf("bundle %s → %s: +%d device(s), -%d, %d changed", r.From, r.To, r.Added, r.Removed, r.Changed)
}

// Security is the changes the log carries as inventory_change records.
func (r Report) Security() []Change {
	var out []Change
	for _, c := range r.Changes {
		if c.Security {
			out = append(out, c)
		}
	}
	return out
}

// Check is what port49d refuses a new inventory for beyond Parse's refusals
// (spec §10, bounded change): an inventory with no device, and one that
// takes more than maxRemovedPercent of the devices in old out of service —
// removed, or kept and newly refused admission, which a dropped key-group
// block or a mistyped pin does to a whole fleet (plan 6a, I4), or kept with
// no address left (Unaddressed; plan 6c, pre-flight I2). 100 turns the
// share off; nothing turns the empty check off.
func Check(old, new *policy.Policy, maxRemovedPercent int) error {
	return CheckFrom(old, new, maxRemovedPercent, "fix the file")
}

// CheckFrom is Check with fix, what the bound's refusal tells the operator to
// fix: "fix the file" for inventory_file, "fix the source of truth" for the
// inventory service's document (spec §10). The hint that key_groups was
// deleted from the inventory file is given only when the inventory in force
// carries key groups: a document from the service never does, and the hint
// would send an operator looking for a file there is none of.
func CheckFrom(old, new *policy.Policy, maxRemovedPercent int, fix string) error {
	if len(new.Devices()) == 0 {
		return errors.New("the new inventory names no device; an empty inventory admits nothing, so it is never " +
			"loaded (spec §10)")
	}
	hint := len(old.Inventory().KeyGroups) > 0
	if err := admitsNone("inventory", new, hint); err != nil {
		return err
	}
	was := len(old.Devices())
	if was == 0 || maxRemovedPercent >= 100 {
		return nil
	}
	after := byName(new.Devices())
	removed := 0
	for _, d := range old.Devices() {
		if _, ok := after[d.Name]; !ok {
			removed++
		}
	}
	refused := NewlyRefused(old, new)
	bare := Unaddressed(old, new)
	if gone := removed + len(refused) + len(bare); gone*100 > was*maxRemovedPercent {
		msg := fmt.Sprintf("the new inventory removes %d of %d devices and refuses %d more", removed, was, len(refused))
		if len(bare) > 0 {
			msg += fmt.Sprintf(" and leaves %d more with no address", len(bare))
		}
		msg += fmt.Sprintf(" (%d%%), more than inventory.max_removed_percent (%d%%)", gone*100/was, maxRemovedPercent)
		if len(bare) > 0 {
			msg += "; left with no address: " + nameList(bare)
		}
		if len(refused) > 0 {
			msg += "; newly refused: " + names(refused)
			if hint {
				msg += " (if key_groups was deleted from the inventory file, add it to the policy file first)"
			}
		}
		return errors.New(msg + "; " + fix + ", or, if the change is meant, raise inventory.max_removed_percent " +
			"in port49d.yaml and send SIGHUP, which re-reads it with the reload")
	}
	return nil
}

// CheckAdmission is a policy reload's bound (plan 6a, N1). Key groups are
// policy, so a policy edit can refuse the fleet — a CIDR typo, or the block
// deleted — and a refused device's contexts are revoked and its tokens
// deleted (I2): unbounded, one bad edit is a fleet-wide logout that a revert
// does not undo. It refuses a policy that newly refuses more than
// maxRemovedPercent of the devices admitted under old, naming them.
func CheckAdmission(old, new *policy.Policy, maxRemovedPercent int) error {
	if err := admitsNone("policy", new, false); err != nil {
		return err
	}
	// The share is of the devices the policy in force admits (spec §10).
	was := len(old.Devices())
	if old.AdmissionAssessed() {
		was -= len(old.AdmissionRefusals())
	}
	refused := NewlyRefused(old, new)
	if was == 0 || maxRemovedPercent >= 100 || len(refused)*100 <= was*maxRemovedPercent {
		return nil
	}
	return fmt.Errorf("the new policy refuses admission to %d of %d devices (%d%%), more than "+
		"inventory.max_removed_percent (%d%%): %s; check key_groups, or, if the change is meant, raise "+
		"inventory.max_removed_percent in port49d.yaml and send SIGHUP, which re-reads it with the reload",
		len(refused), was, len(refused)*100/was, maxRemovedPercent, names(refused))
}

// admitsNone refuses a bundle that admits no device of a non-empty inventory,
// whatever the bound, as a start is (spec §10): that is no device's fault, and
// taking the whole fleet off is done by stopping port49d, not by a reload.
// what is the file the reload read: "inventory" or "policy"; hint adds the
// key-group move done in the wrong order, for an inventory in force that
// carries key groups. A bundle an offline tool loaded unassessed — no key
// groups, no key_refs — is read as port49d, always assessing, reads it: only
// its pinned devices are admitted (AdmissionRefusals; plan 6a, I1), as
// `policy test` judges it.
func admitsNone(what string, p *policy.Policy, hint bool) error {
	n := len(p.Devices())
	if n == 0 || len(p.AdmissionRefusals()) < n {
		return nil
	}
	check := "check key_groups and the key_refs port49d.yaml defines"
	if hint {
		// The key-group move done in the wrong order (plan 6a, C3).
		check += " (if key_groups was deleted from the inventory file, add it to the policy file first)"
	}
	return fmt.Errorf("the new %s admits none of the %d device(s) in the inventory; a reload that refuses the "+
		"whole fleet is never loaded, whatever inventory.max_removed_percent says (spec §10); %s, or, to take "+
		"the whole fleet off deliberately, stop port49d", what, n, check)
}

// NewlyRefused is every device in both bundles that old admits and new
// refuses, by name. A new bundle that does not assess admission — no key
// groups, and no key_refs, as only an offline tool loads one — is read as
// port49d reads it: a device no group admits and no pin assigns is refused
// (I1), so the edit that deletes key_groups is seen.
func NewlyRefused(old, new *policy.Policy) []admission.Resolved {
	var out []admission.Resolved
	for _, r := range new.AdmissionRefusals() {
		if ro, ok := old.Admitted(r.Device.Name); ok && ro.Refused == "" {
			out = append(out, r)
		}
	}
	return out
}

// Unaddressed is every device, by name and sorted, that old gives at least
// one address and new keeps under its name with none, and that new does not
// newly refuse (NewlyRefused counts those). port49d admits a connection by
// its source address, so such a device is out of service even while an
// attribute key group keeps it "admitted" (plan 6c, pre-flight I2).
func Unaddressed(old, new *policy.Policy) []string {
	before := byName(old.Devices())
	refused := map[string]bool{}
	for _, r := range NewlyRefused(old, new) {
		refused[r.Device.Name] = true
	}
	var out []string
	for _, d := range new.Devices() {
		if o, ok := before[d.Name]; ok && len(o.Addresses) > 0 && len(d.Addresses) == 0 && !refused[d.Name] {
			out = append(out, d.Name)
		}
	}
	slices.Sort(out)
	return out
}

// nameList is up to five names, and how many more.
func nameList(ns []string) string {
	if len(ns) > 5 {
		return strings.Join(ns[:5], ", ") + fmt.Sprintf(" and %d more", len(ns)-5)
	}
	return strings.Join(ns, ", ")
}

// names is up to five devices by name, and how many more.
func names(rs []admission.Resolved) string {
	var n []string
	for i, r := range rs {
		if i == 5 {
			return strings.Join(n, ", ") + fmt.Sprintf(" and %d more", len(rs)-5)
		}
		n = append(n, r.Device.Name)
	}
	return strings.Join(n, ", ")
}

// admissionState is a device's admission in one word. On a policy that does
// not assess admission every device reads as refused, which nothing acts on,
// so it is read as admitted: a change there is never classed benign by it.
func admissionState(p *policy.Policy, name string, now time.Time) string {
	if r, _ := p.Admitted(name); r.Refused != "" && p.AdmissionAssessed() {
		return "refused"
	}
	if _, q := p.Quarantined(name, now); q {
		return "quarantined"
	}
	return "admitted"
}

func byName(devices []admission.Device) map[string]admission.Device {
	out := make(map[string]admission.Device, len(devices))
	for _, d := range devices {
		out[d.Name] = d
	}
	return out
}

func unionNames(a, b map[string]admission.Device) []string {
	seen := map[string]bool{}
	for n := range a {
		seen[n] = true
	}
	for n := range b {
		seen[n] = true
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// minus is the addresses in a and not in b, sorted.
func minus(a, b []netip.Addr) []netip.Addr {
	var out []netip.Addr
	for _, x := range a {
		if !slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	slices.SortFunc(out, func(x, y netip.Addr) int { return x.Compare(y) })
	return out
}

func attrs(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + ": " + m[k]
	}
	return "{" + strings.Join(parts, ", ") + "}"
}
