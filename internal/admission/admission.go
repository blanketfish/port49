// Package admission answers "which device is this address, and which key_ref
// admits it" from a file inventory and reviewed key groups (spec §10).
package admission

import (
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/blanketfish/port49/internal/yamlfault"
)

// Transport is how a device speaks TACACS+ (spec §10: a device record MUST
// be able to express both).
const (
	TransportTCP = "tcp" // RFC 8907, obfuscated under a shared key; the default
	TransportTLS = "tls" // RFC 9887, mutual TLS; no shared key (spec §13 decision 50)
)

type Device struct {
	Name       string
	Platform   string
	Addresses  []netip.Addr
	Attributes map[string]string
	KeyRef     string // tier 1 pin; empty when not pinned
	Transport  string // "" is TransportTCP
}

// EffectiveTransport is the device's transport with the default applied:
// "" is TransportTCP (spec §10).
func (d Device) EffectiveTransport() string {
	if d.Transport == "" {
		return TransportTCP
	}
	return d.Transport
}

type KeyGroup struct {
	// Name matches one device by its inventory name: the pin, in the
	// reviewed policy, at tier 1 (spec §10; plan 6b owner decision 3). A
	// group matches on exactly one of Name, CIDR and Attributes.
	Name       string
	CIDR       netip.Prefix // zero value when this is an attribute group
	Attributes map[string]string
	KeyRef     string
}

type Inventory struct {
	Devices   []Device
	KeyGroups []KeyGroup
}

type Resolved struct {
	Device Device
	KeyRef string
	// WirePlatform is the shipped platform whose wire facts port49d reads for
	// this device (spec §8): its own, or the one a `based_on:` variant names.
	// Empty is Device.Platform.
	WirePlatform string
	// Refused says why a device in the inventory is not admitted — its
	// transport is neither tcp nor tls, no key group matches it, two
	// tie on it, or its key_ref is one port49d holds no key for (spec §10).
	// Empty is admitted. A refused device is in the index all the same, so its packets are told apart from an unknown source's.
	Refused string
	// Refusal is which of the five it is (RefusedTransport, RefusedNoGroup,
	// RefusedTie, RefusedUnknownKey, RefusedTLSNameClash), for a reader that decides by it. `port49 policy
	// test` fails on every one (plan 6a, N1).
	Refusal string
}

// Why admission refused a device (spec §10).
const (
	RefusedTransport  = "refused_transport"
	RefusedNoGroup    = "no_key_group"
	RefusedTie        = "key_group_tie"
	RefusedUnknownKey = "key_ref_undefined"
	// RefusedTLSNameClash is two tls devices whose names are equal under ASCII
	// case folding (decision 50 ruling 6). A tls device has no key group, so
	// it is not RefusedTie.
	RefusedTLSNameClash = "tls_name_clash"
)

// KeyRefShape is what a key_ref looks like wherever one is named: port49d.yaml's
// keys, a policy's key_groups. A key_ref is the name every report prints, so
// one that is not a name, most likely a secret pasted where the name goes, is
// refused without being printed. A secret that is all lowercase hex and at
// most 64 characters matches the shape and cannot be told apart from a name.
var KeyRefShape = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// KeyRefShapeRule is KeyRefShape in words, for the refusal.
const KeyRefShapeRule = "lowercase letters, digits and _, starting with a letter; at most 64"

// Tier is which rule assigned a device its key_ref, most specific first
// (spec §10, "Key group matching is deterministic").
type Tier string

const (
	TierPin       Tier = "pin"
	TierAttribute Tier = "attribute"
	TierCIDR      Tier = "cidr"
)

// Assignment is a device's key_ref, the tier that chose it and the rule that
// did, as `port49 keys show` prints it.
type Assignment struct {
	KeyRef string
	Tier   Tier
	Group  string
}

// String renders a group as `keys show` and the refusal lines name it.
func (g KeyGroup) String() string {
	if g.Name != "" {
		return fmt.Sprintf("name %s → %s", g.Name, g.KeyRef)
	}
	if g.CIDR.IsValid() {
		return fmt.Sprintf("cidr %s → %s", g.CIDR, g.KeyRef)
	}
	keys := make([]string, 0, len(g.Attributes))
	for k := range g.Attributes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + ": " + g.Attributes[k]
	}
	return fmt.Sprintf("attributes {%s} → %s", strings.Join(parts, ", "), g.KeyRef)
}

// Trie is a map from address to resolved device; the key_ref is decided at build
// time so Lookup is a single map read on the hot path.
type Trie struct {
	byAddr map[netip.Addr]Resolved
}

// Validate refuses an inventory that cannot be used at all: a device with no
// name or a name used twice, and one address claimed by two devices.
//
// The device name is a namespace, not a label: store.TokenKey and
// store.ContextKey are keyed on it, so two devices sharing a name (the empty
// string included) share a token namespace, and a token minted for one
// redeems on the other. An address claimed twice would bind one device's
// sessions to another in every record (spec §10, "Addresses must resolve to
// one device"): the snapshot is refused, never a winner picked.
func Validate(devices []Device) error {
	named := make(map[string]bool, len(devices))
	for _, d := range devices {
		if d.Name == "" {
			return fmt.Errorf("admission: a device with addresses %v has no name; give every device a unique name", d.Addresses)
		}
		if named[d.Name] {
			return fmt.Errorf("admission: two devices are both named %q; device names are token namespaces and must be unique", d.Name)
		}
		named[d.Name] = true
	}
	owner := make(map[netip.Addr]string)
	for _, d := range devices {
		for _, a := range d.Addresses {
			if prev, dup := owner[a]; dup {
				return fmt.Errorf("admission: address %s claimed by both %q and %q", a, prev, d.Name)
			}
			owner[a] = d.Name
		}
	}
	return nil
}

// Assign is d's key_ref by tier (spec §10): a pin — on the record, or a group
// matching the device's name — then an attribute group, then the longest
// matching CIDR, which every one of the device's addresses must agree on. No
// group matching is the zero Assignment, and the caller refuses the device.
// Two groups tying in one tier is an error naming both: refusing to guess is
// the only conservative answer, since a device admitted under the wrong group
// is admitted under the wrong key.
func Assign(d Device, groups []KeyGroup) (Assignment, error) {
	// Tier 1: a pin, on the record (inventory_file) or as a policy group
	// matching the name. Two that name different keys are a tie, refused:
	// guessing between two reviewed pins would admit under the wrong key.
	var named []KeyGroup
	for _, g := range groups {
		if g.Name != "" && g.Name == d.Name {
			named = append(named, g)
		}
	}
	if len(named) > 1 {
		return Assignment{}, fmt.Errorf("admission: device %q matches key groups %s and %s in the pin tier", d.Name,
			named[0], named[1])
	}
	if d.KeyRef != "" {
		if len(named) == 1 && named[0].KeyRef != d.KeyRef {
			// The record's key_ref is not printed: a pin is where a secret
			// gets pasted.
			return Assignment{}, fmt.Errorf("admission: device %q is pinned on its record and by key group %s, "+
				"to different keys, in the pin tier", d.Name, named[0])
		}
		return Assignment{KeyRef: d.KeyRef, Tier: TierPin, Group: "key_ref pinned on the device record"}, nil
	}
	if len(named) == 1 {
		return Assignment{KeyRef: named[0].KeyRef, Tier: TierPin, Group: named[0].String()}, nil
	}
	var attrHits []KeyGroup
	for _, g := range groups {
		if len(g.Attributes) > 0 && attrsMatch(d.Attributes, g.Attributes) {
			attrHits = append(attrHits, g)
		}
	}
	if len(attrHits) > 1 {
		return Assignment{}, fmt.Errorf("admission: device %q matches key groups %s and %s in the attribute tier", d.Name, attrHits[0], attrHits[1])
	}
	if len(attrHits) == 1 {
		return Assignment{KeyRef: attrHits[0].KeyRef, Tier: TierAttribute, Group: attrHits[0].String()}, nil // tier 2
	}
	// Tier 3: each address resolves to its longest matching CIDR group, and
	// every address that matched must resolve to the same key_ref.
	var winners []KeyGroup
	for _, a := range d.Addresses {
		var hits []KeyGroup
		for _, g := range groups {
			if g.CIDR.IsValid() && g.CIDR.Contains(a) {
				hits = append(hits, g)
			}
		}
		sort.Slice(hits, func(i, j int) bool { return hits[i].CIDR.Bits() > hits[j].CIDR.Bits() })
		if len(hits) == 0 {
			continue
		}
		if len(hits) > 1 && hits[0].CIDR.Bits() == hits[1].CIDR.Bits() {
			return Assignment{}, fmt.Errorf("admission: device %q address %s matches key groups %s and %s at equal prefix length", d.Name, a, hits[0], hits[1])
		}
		winners = append(winners, hits[0])
	}
	if len(winners) == 0 {
		return Assignment{}, nil
	}
	for _, w := range winners[1:] {
		if w.KeyRef != winners[0].KeyRef {
			return Assignment{}, fmt.Errorf("admission: device %q: addresses resolve to different keys: %s (%s) and %s (%s)", d.Name, winners[0].CIDR, winners[0].KeyRef, w.CIDR, w.KeyRef)
		}
	}
	return Assignment{KeyRef: winners[0].KeyRef, Tier: TierCIDR, Group: winners[0].String()}, nil
}

// transportRefusal is why a device's transport is no transport at all, or ""
// for tcp and tls. Which listener serves a device is decided per connection,
// never here (spec §13 decision 50 ruling 4). It refuses the device, never
// the file: a sync can write one, and refusing the file would stop every
// inventory change fleet-wide (spec §10).
func transportRefusal(d Device) string {
	switch d.Transport {
	case "", TransportTCP, TransportTLS:
		return ""
	default:
		return fmt.Sprintf("has transport %q, which is not tcp or tls", d.Transport)
	}
}

// pinRefusal is why d's pinned key_ref cannot be used, or "" when it has none
// or it is a key_ref name (KeyRefShape). The pin is not in the text: one that
// is not a name is most likely a secret pasted where the name goes.
func pinRefusal(d Device) string {
	if d.KeyRef == "" || KeyRefShape.MatchString(d.KeyRef) {
		return ""
	}
	return "pins a key_ref that is not a valid key_ref name (" + KeyRefShapeRule + "), so it fails closed; " +
		"the pin is not shown, since it may be a secret pasted there (spec §10)"
}

// Resolve is one device's admission from its record and the key groups: its
// key_ref, or why it is refused — a transport that is neither tcp nor tls, two
// groups tying on it, or no group matching it (spec §10). It fails closed: a
// refused entry carries no key_ref. Whether port49d holds a key for the
// key_ref is the caller's to check (RefusedUnknownKey).
func Resolve(d Device, groups []KeyGroup) Resolved {
	r := Resolved{Device: d}
	if why := transportRefusal(d); why != "" {
		r.Refused, r.Refusal = why, RefusedTransport
		return r
	}
	if d.EffectiveTransport() == TransportTLS {
		// Mutual TLS replaces the shared key: no group, tie or pin applies,
		// and the record's key_ref, if any, is ignored (decision 50 ruling 3).
		return r
	}
	if why := pinRefusal(d); why != "" {
		r.Refused, r.Refusal = why, RefusedUnknownKey
		return r
	}
	as, err := Assign(d, groups)
	switch {
	case err != nil:
		r.Refused, r.Refusal = strings.TrimPrefix(err.Error(), "admission: "), RefusedTie
	case as.KeyRef == "":
		r.Refused, r.Refusal = "matches no key group, so no key admits it (spec §10)", RefusedNoGroup
	default:
		r.KeyRef = as.KeyRef
	}
	return r
}

// TLSNameClashes are the tls devices whose names are equal under ASCII case
// folding, by name, each with the refusal text. A certificate names a device by
// its name compared that way (decision 50 ruling 6), so such a pair would admit
// each other's certificates: both are refused, and nothing else in the load
// fails. A tcp device is unaffected. Callers set Refusal to
// RefusedTLSNameClash.
func TLSNameClashes(devices []Device) map[string]string {
	byFold := map[string][]string{}
	for _, d := range devices {
		if d.EffectiveTransport() != TransportTLS || transportRefusal(d) != "" {
			continue
		}
		f, ascii := FoldASCII(d.Name)
		if !ascii {
			continue // never matches a certificate, so nothing to tell apart
		}
		byFold[f] = append(byFold[f], d.Name)
	}
	out := map[string]string{}
	for _, names := range byFold {
		if len(names) < 2 {
			continue
		}
		for _, n := range names {
			out[n] = fmt.Sprintf("is one of tls devices %q whose names are equal under ASCII case folding, so a "+
				"certificate could not tell them apart and all are refused (decision 50 ruling 6)", names)
		}
	}
	return out
}

// FoldASCII lower-cases A-Z and nothing else. ok is false when s holds a
// non-ASCII byte: such a name never matches, since Unicode folding would
// let a Kelvin sign stand for a k (decision 50 ruling 6).
func FoldASCII(s string) (folded string, ok bool) {
	b := []byte(s)
	for i, c := range b {
		switch {
		case c >= 0x80:
			return "", false
		case c >= 'A' && c <= 'Z':
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b), true
}

// NewTrie indexes entries by every address each carries, a refused entry's
// included. Two entries on one address is an error: Validate refuses that
// inventory first, so reaching it here is a caller's defect.
func NewTrie(entries []Resolved) (*Trie, error) {
	t := &Trie{byAddr: make(map[netip.Addr]Resolved)}
	for _, r := range entries {
		for _, a := range r.Device.Addresses {
			if prev, dup := t.byAddr[a]; dup {
				return nil, fmt.Errorf("admission: address %s claimed by both %q and %q", a, prev.Device.Name, r.Device.Name)
			}
			t.byAddr[a] = r
		}
	}
	return t, nil
}

// Build is the admission index port49d with no broker reads (plan 1): the
// inventory file's own key groups, a tie refused whole, and a device no
// group admits, or whose transport is neither tcp nor tls, left out of the
// index, as it always was. A tls device is indexed with no key_ref. With a
// broker, the policy file assigns keys and refuses a device on its own
// (policy.Policy.Admission).
func Build(inv Inventory) (*Trie, error) {
	if err := Validate(inv.Devices); err != nil {
		return nil, err
	}
	entries := make([]Resolved, 0, len(inv.Devices))
	clashes := TLSNameClashes(inv.Devices)
	for _, d := range inv.Devices {
		if transportRefusal(d) != "" {
			continue // refused alone (spec §10)
		}
		if _, clash := clashes[d.Name]; clash {
			continue // both refused, nothing else (decision 50 ruling 6)
		}
		if d.EffectiveTransport() == TransportTLS {
			entries = append(entries, Resolved{Device: d}) // admitted, no key (decision 50 ruling 18)
			continue
		}
		if pinRefusal(d) != "" {
			continue
		}
		as, err := Assign(d, inv.KeyGroups)
		if err != nil {
			return nil, err
		}
		if as.KeyRef == "" {
			continue // in inventory, but no group admits it: refused (spec §10)
		}
		entries = append(entries, Resolved{Device: d, KeyRef: as.KeyRef})
	}
	return NewTrie(entries)
}

func (t *Trie) Lookup(a netip.Addr) (Resolved, bool) {
	r, ok := t.byAddr[a]
	return r, ok
}

func attrsMatch(have, want map[string]string) bool {
	for k, v := range want {
		if have[k] != v {
			return false
		}
	}
	return true
}

// File schema (snake_case).
type fileInventory struct {
	Devices []struct {
		Name       string            `yaml:"name"`
		Platform   string            `yaml:"platform"`
		Addresses  []string          `yaml:"addresses"`
		Attributes map[string]string `yaml:"attributes"`
		KeyRef     string            `yaml:"key_ref"`
		Transport  string            `yaml:"transport"`
	} `yaml:"devices"`
	KeyGroups []struct {
		Match struct {
			CIDR       string            `yaml:"cidr"`
			Attributes map[string]string `yaml:"attributes"`
		} `yaml:"match"`
		KeyRef string `yaml:"key_ref"`
	} `yaml:"key_groups"`
}

func LoadFile(path string) (Inventory, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Inventory{}, err
	}
	return ParseFile(raw, path)
}

// ParseFile is LoadFile for bytes already read, named by path in its errors:
// port49d loads exactly the bytes its watch agreed on (plan 6a). An empty
// path names nothing, for a caller whose own error already names the file.
func ParseFile(raw []byte, path string) (Inventory, error) {
	at := ""
	if path != "" {
		at = path + ": "
	}
	// KnownFields: an unknown key here is a typo with teeth. `keyref:` for
	// `key_ref:` silently un-pins a device onto a group key, and the first
	// packet from it reads `no_known_key_matches` — the 3am discovery this
	// package's doc says cannot happen.
	var f fileInventory
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && err != io.EOF {
		// A line and a category, never the file's text: a record's key_ref
		// pin is where a secret gets pasted (yamlfault).
		return Inventory{}, fmt.Errorf("admission: %s%w; check the key spelling against the inventory schema", at,
			yamlfault.Of(err))
	}
	if err := yamlfault.OneDocument(dec); err != nil {
		return Inventory{}, fmt.Errorf("admission: %s%w; the inventory is one document", at, err)
	}
	var inv Inventory
	for n, d := range f.Devices {
		// An unsupported transport is kept as written: Resolve refuses the
		// device, not the file. Absent is tcp, in one spelling.
		if d.Transport == "" {
			d.Transport = TransportTCP
		}
		dev := Device{Name: d.Name, Platform: d.Platform, Attributes: d.Attributes, KeyRef: d.KeyRef, Transport: d.Transport}
		for i, s := range d.Addresses {
			// netip's error quotes the value, and the name has passed no
			// shape check: positions say where it is.
			a, err := netip.ParseAddr(s)
			if err != nil {
				return Inventory{}, fmt.Errorf("admission: %sdevices[%d]: addresses[%d] is not an IP address", at,
					n, i)
			}
			dev.Addresses = append(dev.Addresses, a)
		}
		inv.Devices = append(inv.Devices, dev)
	}
	for i, g := range f.KeyGroups {
		if g.KeyRef != "" && !KeyRefShape.MatchString(g.KeyRef) {
			return Inventory{}, fmt.Errorf("admission: %skey_groups[%d]: key_ref is not a valid key_ref name (%s): "+
				"it names the key, never holds it", at, i, KeyRefShapeRule)
		}
		kg := KeyGroup{Attributes: g.Match.Attributes, KeyRef: g.KeyRef}
		if g.Match.CIDR != "" {
			p, err := netip.ParsePrefix(g.Match.CIDR)
			if err != nil {
				return Inventory{}, fmt.Errorf("admission: %skey_groups[%d] (%s): match.cidr is not a CIDR prefix",
					at, i, g.KeyRef)
			}
			kg.CIDR = p
		}
		if kg.KeyRef == "" {
			return Inventory{}, fmt.Errorf("admission: %sa key group has no key_ref; every group must name the key it admits", at)
		}
		// A group with neither match term is not a narrow group, it is a
		// catch-all: attrsMatch against an empty want is vacuously true, so it
		// would claim every device in the attribute tier and quietly admit the
		// fleet under one key.
		if !kg.CIDR.IsValid() && len(kg.Attributes) == 0 {
			return Inventory{}, fmt.Errorf("admission: %skey group %q matches on neither cidr nor attributes; give it one or remove it", at, kg.KeyRef)
		}
		inv.KeyGroups = append(inv.KeyGroups, kg)
	}
	return inv, nil
}
