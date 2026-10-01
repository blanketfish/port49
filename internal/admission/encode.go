package admission

import (
	"errors"
	"net/netip"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// EncodeFile is inv as an inventory file, the schema ParseFile reads:
// devices in name order, each one's addresses sorted, its transport left out
// when it is tcp. ParseFile reads it back to the same devices. Key groups are
// not written: the one caller, `port49 inventory export`, writes a bundle
// document's inventory, which carries none (spec §13, decision 30), so an
// inventory with key groups is an error rather than a file that drops them.
func EncodeFile(inv Inventory) ([]byte, error) {
	if len(inv.KeyGroups) > 0 {
		return nil, errors.New("admission: EncodeFile writes devices only, and this inventory carries key_groups")
	}
	type device struct {
		Name       string            `yaml:"name"`
		Platform   string            `yaml:"platform"`
		Addresses  []string          `yaml:"addresses"`
		Attributes map[string]string `yaml:"attributes,omitempty"`
		KeyRef     string            `yaml:"key_ref,omitempty"`
		Transport  string            `yaml:"transport,omitempty"`
	}
	out := struct {
		Devices []device `yaml:"devices"`
	}{Devices: []device{}}
	devs := slices.Clone(inv.Devices)
	slices.SortFunc(devs, func(a, b Device) int { return strings.Compare(a.Name, b.Name) })
	for _, d := range devs {
		e := device{Name: d.Name, Platform: d.Platform, Addresses: []string{}, Attributes: d.Attributes, KeyRef: d.KeyRef}
		if d.Transport != "" && d.Transport != TransportTCP {
			e.Transport = d.Transport
		}
		addrs := slices.Clone(d.Addresses)
		slices.SortFunc(addrs, func(a, b netip.Addr) int { return a.Compare(b) })
		for _, a := range addrs {
			e.Addresses = append(e.Addresses, a.String())
		}
		out.Devices = append(out.Devices, e)
	}
	return yaml.Marshal(out)
}
