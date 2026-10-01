package sot

import (
	"regexp"
	"sort"
	"strings"
)

// PlatformNameShape is a platform name as the policy writes one; an alias
// override maps to one.
var PlatformNameShape = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// builtinAliases maps the spellings real installations use to port49's
// platform names (spec §10, "Platform slug translation"): spec §10's own,
// the vendors' hyphenated slugs, and the netutils drivers Nautobot reports
// in platform.network_driver (L27: "arista_eos"). Classic IOS (cisco_ios) is
// not IOS-XE and is not here: a slug the table does not know is kept and
// said, never guessed.
var builtinAliases = map[string]string{
	"arista_eos": "arista_eos", "arista-eos": "arista_eos", "eos": "arista_eos", "veos": "arista_eos",
	"ceos":        "arista_eos",
	"cisco_iosxe": "cisco_iosxe", "cisco_xe": "cisco_iosxe", "cisco-ios-xe": "cisco_iosxe",
	"cisco_ios_xe": "cisco_iosxe", "ios-xe": "cisco_iosxe", "iosxe": "cisco_iosxe",
	"cisco_nxos": "cisco_nxos", "cisco-nxos": "cisco_nxos", "cisco-nx-os": "cisco_nxos", "cisco_nx_os": "cisco_nxos",
	"nx-os": "cisco_nxos", "nxos": "cisco_nxos",
	"juniper_junos": "juniper_junos", "juniper-junos": "juniper_junos", "junos": "juniper_junos",
}

// platformName is slug as port49 names the platform: a source's override
// first, then the built-in table, compared in lower case; a slug neither
// knows is kept, lower-cased, so the device is served by the generic
// adapter and the syncer says so (spec §8, "Unknown platforms").
func platformName(slug string, overrides map[string]string) string {
	s := strings.ToLower(slug)
	if name, ok := overrides[s]; ok {
		return name
	}
	if name, ok := builtinAliases[s]; ok {
		return name
	}
	return s
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
