package sot

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/bundle"
)

// Mapping is how a source's devices become port49's (decision 31): which
// are kept (Filter), which facts become attributes (Map), which addresses
// each has (Addresses), and how a platform slug becomes a platform name
// (Aliases, over the built-in table).
type Mapping struct {
	// Map is attribute → path; the attribute "platform" is the device's
	// platform. Empty is the profile's default.
	Map       map[string]string
	Filter    Filter
	Addresses Addresses
	// Aliases are the source's platform_aliases, keys in lower case.
	Aliases map[string]string
}

// Filter keeps a device only when every rule set holds.
type Filter struct {
	// Status is the statuses kept, lower case; empty keeps every status.
	Status []string
	// Tags are tags a device must carry, every one.
	Tags         []string
	HasPrimaryIP bool
}

// Addresses is which of a device's addresses admit it.
type Addresses struct {
	Primary       bool
	Interfaces    []string
	AllInterfaces bool
}

func (m Mapping) needsInterfaces() bool {
	return m.Addresses.AllInterfaces || len(m.Addresses.Interfaces) > 0
}

// mapOf is the map in force on p.
func (m Mapping) mapOf(p Profile) map[string]string {
	if len(m.Map) > 0 {
		return m.Map
	}
	return p.defaultMap
}

// check says what m asks of p that p does not give over api, before
// anything is read: a path the profile does not record, one it gives over
// GraphQL only, or interfaces over REST.
func (m Mapping) check(p Profile, api string) error {
	if api == "rest" && m.needsInterfaces() {
		return fmt.Errorf("addresses names interfaces, which REST does not give in the device list (L27): use api: " +
			"graphql, or addresses: {primary: true}")
	}
	mp := m.mapOf(p)
	for _, attr := range sortedKeys(mp) {
		path := mp[attr]
		if path == "status" || customKey.MatchString(path) {
			continue
		}
		f, ok := p.fields[path]
		if !ok {
			return fmt.Errorf("map.%s: %s is not read on profile %s; it reads %s", attr, path, p.Name,
				strings.Join(p.paths(), ", "))
		}
		if f.over(api) == nil {
			return fmt.Errorf("map.%s: %s is not read over REST on profile %s; read GraphQL, or map another path",
				attr, path, p.Name)
		}
	}
	return nil
}

// selection is what a GraphQL read asks for under m: id (the list's key,
// L32), name, status, the primary addresses, and only what the map, the
// filter and the address rule read.
func (m Mapping) selection(p Profile) selection {
	s := selection{}
	s.add([]string{"id"})
	s.add([]string{"name"})
	s.add(p.status.graphql)
	s.add([]string{"primary_ip4", "address"})
	s.add([]string{"primary_ip6", "address"})
	if len(m.Filter.Tags) > 0 {
		s.add([]string{"tags", p.tagKey})
	}
	if m.needsInterfaces() {
		s.add([]string{"interfaces", "name"})
		s.add([]string{"interfaces", "ip_addresses", "address"})
	}
	for _, path := range m.mapOf(p) {
		switch {
		case path == "status":
		case customKey.MatchString(path):
			s.add(p.customFields.graphql)
		default:
			s.add(p.fields[path].graphql)
		}
	}
	return s
}

// device is one source device as port49's, and whether the filter keeps it.
// notes are what could not be read, said once each by the caller; each
// names the device by its name only where the name can reach a line. A
// device never carries a key assignment (spec §13, decision 30).
func (m Mapping) device(p Profile, api string, raw map[string]any) (admission.Device, bool, []string) {
	name, _ := raw["name"].(string)
	d := admission.Device{Name: name, Transport: admission.TransportTCP}
	label := name
	if !bundle.NameOK(name) {
		label = "with an unusable name"
	}
	var notes []string
	status := strings.ToLower(str(lookup(raw, p.status.over(api))))
	if len(m.Filter.Status) > 0 && !slices.Contains(m.Filter.Status, status) {
		return d, false, nil
	}
	if len(m.Filter.Tags) > 0 {
		have := map[string]bool{}
		for _, tag := range list(raw["tags"]) {
			have[str(lookup(asMap(tag), []string{p.tagKey}))] = true
		}
		for _, want := range m.Filter.Tags {
			if !have[want] {
				return d, false, nil
			}
		}
	}
	p4 := str(lookup(raw, []string{"primary_ip4", "address"}))
	p6 := str(lookup(raw, []string{"primary_ip6", "address"}))
	if m.Filter.HasPrimaryIP && p4 == "" && p6 == "" {
		return d, false, nil
	}
	seen := map[netip.Addr]bool{}
	add := func(s, where string) {
		if s == "" {
			return
		}
		a, err := addrOf(s)
		if err != nil {
			notes = append(notes, fmt.Sprintf("device %s: %s %v; it is left out of the device's addresses", label,
				where, err))
			return
		}
		if !seen[a] {
			seen[a] = true
			d.Addresses = append(d.Addresses, a)
		}
	}
	if m.Addresses.Primary {
		add(p4, "primary_ip4")
		add(p6, "primary_ip6")
	}
	if m.needsInterfaces() {
		skipped := 0
		for i, itf := range list(raw["interfaces"]) {
			im := asMap(itf)
			if !m.Addresses.AllInterfaces && !slices.Contains(m.Addresses.Interfaces, str(im["name"])) {
				continue
			}
			for j, ip := range list(im["ip_addresses"]) {
				s := str(asMap(ip)["address"])
				// Pre-flight M13: an address that cannot source TACACS+ to
				// port49d, and that every device may hold, is left out; kept,
				// two devices sharing one would refuse every sync. A
				// link-local is judged without its zone, so fe80::1%eth0 is
				// one of these, not a device's note.
				if a, err := addrOf(unzoned(s)); err == nil && !sourceable(a) {
					skipped++
					continue
				}
				add(s, fmt.Sprintf("interfaces[%d].ip_addresses[%d]", i, j))
			}
		}
		if skipped > 0 {
			notes = append(notes, "interface addresses that cannot source TACACS+ (loopback, link-local, "+
				"multicast, unspecified) are left out of every device's addresses")
		}
	}
	slices.SortFunc(d.Addresses, func(a, b netip.Addr) int { return a.Compare(b) })
	mp := m.mapOf(p)
	for _, attr := range sortedKeys(mp) {
		path := mp[attr]
		var v string
		switch {
		case path == "status":
			v = status
		case customKey.MatchString(path):
			key := strings.TrimPrefix(path, "custom_fields.")
			cv, present := asMap(lookup(raw, p.customFields.over(api)))[key]
			var ok bool
			if v, ok = scalar(cv); present && cv != nil && !ok {
				notes = append(notes, fmt.Sprintf("device %s: custom field %s is not a string, number or boolean; "+
					"attribute %s is left unset", label, key, attr))
			}
		default:
			v = str(lookup(raw, p.fields[path].over(api)))
		}
		if v == "" {
			continue // unset: spec §5.5's on_missing decides what that means
		}
		if attr == "platform" {
			d.Platform = platformName(v, m.Aliases)
			continue
		}
		if d.Attributes == nil {
			d.Attributes = map[string]string{}
		}
		d.Attributes[attr] = v
	}
	return d, true, notes
}

// sourceable is whether a can be the source address of a device's TACACS+
// connection to port49d: not loopback (127/8, ::1), link-local (fe80::/10,
// 169.254/16), multicast or unspecified. Private and global unicast are.
func sourceable(a netip.Addr) bool {
	return !a.IsLoopback() && !a.IsLinkLocalUnicast() && !a.IsMulticast() && !a.IsLinkLocalMulticast() &&
		!a.IsInterfaceLocalMulticast() && !a.IsUnspecified()
}

var (
	errNotIP = errors.New("is not an IP address")
	errZoned = errors.New("has a zone, which no source carries")
)

// addrOf is an address as the products write one, with or without its
// prefix length (L27: "10.0.1.5/32"), as the one host it names: the prefix
// length is whatever the operator typed, and never widens it to a range or
// refuses it. An IPv4-mapped address is its IPv4 address, as port49d unmaps
// a source, so two devices sharing one collide. A zone (free text to netip,
// "/64" included) is the one thing refused.
func addrOf(s string) (netip.Addr, error) {
	if strings.Contains(s, "%") {
		return netip.Addr{}, errZoned
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Addr().Unmap(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, errNotIP
	}
	return a.Unmap(), nil
}

// unzoned is s without its zone, its prefix length kept.
func unzoned(s string) string {
	i := strings.IndexByte(s, '%')
	if i < 0 {
		return s
	}
	if j := strings.IndexByte(s[i:], '/'); j >= 0 {
		return s[:i] + s[i+j:]
	}
	return s[:i]
}

func lookup(v any, path []string) any {
	for _, k := range path {
		v = asMap(v)[k]
	}
	return v
}

func asMap(v any) map[string]any { m, _ := v.(map[string]any); return m }

func list(v any) []any { l, _ := v.([]any); return l }

func str(v any) string { s, _ := v.(string); return s }

// scalar is v as an attribute value: a string as it is, a number as its
// text, a boolean as true or false. Anything else is not one.
func scalar(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case json.Number:
		return x.String(), true
	case bool:
		return strconv.FormatBool(x), true
	}
	return "", false
}
