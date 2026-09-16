// Package admission answers "which device is this address, and which key_ref
// admits it" from a file inventory and reviewed key groups (spec §10).
package admission

import (
	"fmt"
	"net/netip"
	"os"
	"sort"

	"gopkg.in/yaml.v3"
)

type Device struct {
	Name       string
	Platform   string
	Addresses  []netip.Addr
	Attributes map[string]string
	KeyRef     string // tier 1 pin; empty when not pinned
}

type KeyGroup struct {
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
}

// Trie is a map from address to resolved device; the key_ref is decided at build
// time so Lookup is a single map read on the hot path.
type Trie struct {
	byAddr map[netip.Addr]Resolved
}

func Build(inv Inventory) (*Trie, error) {
	t := &Trie{byAddr: make(map[netip.Addr]Resolved)}
	owner := make(map[netip.Addr]string)
	for _, d := range inv.Devices {
		keyRef, err := resolveKeyRef(d, inv.KeyGroups)
		if err != nil {
			return nil, err
		}
		for _, a := range d.Addresses {
			if prev, dup := owner[a]; dup {
				return nil, fmt.Errorf("admission: address %s claimed by both %q and %q", a, prev, d.Name)
			}
			owner[a] = d.Name
			if keyRef == "" {
				continue // in inventory, but no group admits it: refused (spec §10)
			}
			t.byAddr[a] = Resolved{Device: d, KeyRef: keyRef}
		}
	}
	return t, nil
}

func (t *Trie) Lookup(a netip.Addr) (Resolved, bool) {
	r, ok := t.byAddr[a]
	return r, ok
}

func resolveKeyRef(d Device, groups []KeyGroup) (string, error) {
	if d.KeyRef != "" {
		return d.KeyRef, nil // tier 1
	}
	var attrHits []KeyGroup
	for _, g := range groups {
		if len(g.Attributes) > 0 && attrsMatch(d.Attributes, g.Attributes) {
			attrHits = append(attrHits, g)
		}
	}
	if len(attrHits) > 1 {
		return "", fmt.Errorf("admission: device %q matches key groups %q and %q in the attribute tier", d.Name, attrHits[0].KeyRef, attrHits[1].KeyRef)
	}
	if len(attrHits) == 1 {
		return attrHits[0].KeyRef, nil // tier 2
	}
	// Tier 3: longest prefix across all the device's addresses must agree.
	best := ""
	bestBits := -1
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
			return "", fmt.Errorf("admission: device %q address %s matches key groups %q and %q at equal prefix length", d.Name, a, hits[0].KeyRef, hits[1].KeyRef)
		}
		if hits[0].CIDR.Bits() > bestBits {
			best, bestBits = hits[0].KeyRef, hits[0].CIDR.Bits()
		}
	}
	return best, nil
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
	var f fileInventory
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return Inventory{}, fmt.Errorf("admission: %s: %w", path, err)
	}
	var inv Inventory
	for _, d := range f.Devices {
		dev := Device{Name: d.Name, Platform: d.Platform, Attributes: d.Attributes, KeyRef: d.KeyRef}
		for _, s := range d.Addresses {
			a, err := netip.ParseAddr(s)
			if err != nil {
				return Inventory{}, fmt.Errorf("admission: device %q: %w", d.Name, err)
			}
			dev.Addresses = append(dev.Addresses, a)
		}
		inv.Devices = append(inv.Devices, dev)
	}
	for _, g := range f.KeyGroups {
		kg := KeyGroup{Attributes: g.Match.Attributes, KeyRef: g.KeyRef}
		if g.Match.CIDR != "" {
			p, err := netip.ParsePrefix(g.Match.CIDR)
			if err != nil {
				return Inventory{}, fmt.Errorf("admission: key group %q: %w", g.KeyRef, err)
			}
			kg.CIDR = p
		}
		if kg.KeyRef == "" {
			return Inventory{}, fmt.Errorf("admission: key group without key_ref")
		}
		inv.KeyGroups = append(inv.KeyGroups, kg)
	}
	return inv, nil
}
