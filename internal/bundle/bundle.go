// Package bundle names and builds the bundle port49 runs on (spec §10; §13
// decision 28): the policy loaded against the inventory, which carries the
// admission index, the device table and the quarantine with it, and which
// policy.Live swaps whole. port49d builds it from inventory_file and
// broker.policy_file; plan 6b's inventory service publishes it. Diff and
// Check are what a swap and a review read.
package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/policy"
)

// ID names a bundle: "sha256:" over the policy file's sha256 and the
// inventory's canonical form, so every port49d reading the same two files
// names the same bundle, and a reformatted inventory file is the same bundle
// (spec §10). The platform set is the policy's pin, so the policy's hash
// covers it. port49d.yaml's keys are not in it: which key_refs port49d holds
// keys for, and the keys themselves, are the daemon's, so two daemons with
// different keys name one bundle and may admit differently from it (spec §10).
func ID(policyRaw []byte, inv admission.Inventory) string {
	sum := sha256.Sum256([]byte(engine.HashOf(policyRaw) + "\n" + engine.HashOf(Canonical(inv))))
	return "sha256:" + hex.EncodeToString(sum[:])
}

type canonDevice struct {
	Name       string            `json:"name"`
	Platform   string            `json:"platform"`
	Addresses  []string          `json:"addresses"`
	Attributes map[string]string `json:"attributes,omitempty"`
	KeyRef     string            `json:"key_ref,omitempty"`
	Transport  string            `json:"transport,omitempty"`
}

type canonGroup struct {
	Name       string            `json:"name,omitempty"`
	CIDR       string            `json:"cidr,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
	KeyRef     string            `json:"key_ref"`
}

// key orders groups by their whole content.
func (g canonGroup) key() string {
	b, _ := json.Marshal(g)
	return string(b)
}

// Canonical is the inventory in one spelling: devices by name, each one's
// addresses sorted, an empty attribute map as none and `tcp` as the default
// it is, and key groups sorted with each CIDR masked: admission.Assign
// refuses a tie rather than take the first group, and a prefix contains what
// its masked form does, so neither decides access (Task 6 review M1).
// encoding/json writes map keys sorted.
func Canonical(inv admission.Inventory) []byte {
	devs := make([]canonDevice, 0, len(inv.Devices))
	for _, d := range inv.Devices {
		addrs := slices.Clone(d.Addresses)
		slices.SortFunc(addrs, func(a, b netip.Addr) int { return a.Compare(b) })
		c := canonDevice{Name: d.Name, Platform: d.Platform, KeyRef: d.KeyRef, Addresses: make([]string, len(addrs))}
		for i, a := range addrs {
			c.Addresses[i] = a.String()
		}
		if len(d.Attributes) > 0 {
			c.Attributes = d.Attributes
		}
		if d.Transport != admission.TransportTCP {
			c.Transport = d.Transport
		}
		devs = append(devs, c)
	}
	slices.SortFunc(devs, func(a, b canonDevice) int { return strings.Compare(a.Name, b.Name) })
	groups := make([]canonGroup, len(inv.KeyGroups))
	for i, g := range inv.KeyGroups {
		groups[i] = canonGroup{Name: g.Name, KeyRef: g.KeyRef}
		if g.CIDR.IsValid() {
			groups[i].CIDR = g.CIDR.Masked().String()
		}
		if len(g.Attributes) > 0 {
			groups[i].Attributes = g.Attributes
		}
	}
	slices.SortFunc(groups, func(a, b canonGroup) int { return strings.Compare(a.key(), b.key()) })
	b, err := json.Marshal(struct {
		Format    string        `json:"format"`
		Devices   []canonDevice `json:"devices"`
		KeyGroups []canonGroup  `json:"key_groups"`
	}{"port49-inventory/1", devs, groups})
	if err != nil {
		// Strings, and maps of strings, always encode.
		panic("bundle: an inventory does not encode: " + err.Error())
	}
	return b
}

// Parse builds the bundle: the inventory validated (admission.Validate), and
// the policy loaded against it under the bundle's name. env's Devices,
// InventoryKeyGroups and Bundle are set here; the caller sets the rest
// (KeyRefs, Now).
func Parse(policyRaw []byte, inv admission.Inventory, env policy.Env) (*policy.Policy, error) {
	if err := admission.Validate(inv.Devices); err != nil {
		return nil, err
	}
	env.Devices, env.InventoryKeyGroups, env.Bundle = inv.Devices, inv.KeyGroups, ID(policyRaw, inv)
	env.DNSSuffixes = inv.DNSSuffixes
	return policy.Parse(policyRaw, env)
}

// InventoryError is a fault in the inventory file — unreadable, malformed, or
// refused by admission.Validate — named by the file's path, so the operator is
// sent to the inventory, not the policy (plan 6a pre-flight M5).
type InventoryError struct {
	Path string
	Err  error
}

func (e *InventoryError) Error() string { return "inventory_file " + e.Path + ": " + e.Err.Error() }
func (e *InventoryError) Unwrap() error { return e.Err }

// LoadInventory reads and validates the inventory file, as Parse would: every
// tool that reads it before loading the policy reads it here, so its fault is
// an *InventoryError naming the file, not a policy that does not load.
func LoadInventory(path string) (admission.Inventory, error) {
	inv, err := admission.LoadFile(path)
	if err == nil {
		err = admission.Validate(inv.Devices)
	}
	if err != nil {
		return admission.Inventory{}, &InventoryError{Path: path, Err: err}
	}
	return inv, nil
}

// Load reads the two files and builds the bundle, as every offline tool does,
// so the bundle it names is the one port49d's records carry for those files.
// An inventory fault is an *InventoryError.
func Load(policyPath, inventoryPath string, env policy.Env) (*policy.Policy, error) {
	inv, err := LoadInventory(inventoryPath)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(policyPath)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	p, err := Parse(raw, inv, env)
	if err != nil {
		return nil, fmt.Errorf("policy: %s: %w", policyPath, err)
	}
	return p, nil
}
