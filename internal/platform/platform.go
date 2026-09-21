// Package platform is the built-in platform table (spec §8): the names port49
// ships an adapter for, and what each adapter says.
//
// Plan 1 reads exactly one adapter field, `session_services`, so this package
// is one map and three functions. Plan 5 builds §8 in full — privilege levels,
// entity classes, projection, user overrides and layering — and this table
// becomes one column of it. The names are deliberately the ones an inventory's
// `platform:` field already carries (`internal/admission`), because the daemon
// looks a platform up by the string the device resolved to and nothing
// translates between two spellings.
package platform

import "sort"

// sessionServices is the authorization `service` value each platform's
// sessions arrive with. Every entry is measured, not assumed (spec §15, L10):
//
//   - `shell` on EOS, NX-OS and IOS-XE — tests/lab/results/L10-arista_eos.md,
//     L10-cisco_nxos.md, L10-cisco_iosxe.md.
//   - `junos-exec` on Junos, on an interactive login and on a NETCONF session
//     alike — L10-juniper_vsrx.md, L10-juniper_vjunos-router.md,
//     netconf-juniper_vsrx.md.
//
// It is a list rather than a string because on Junos the name is a device
// setting: `set system tacplus-options service-name junos-exec-fw` renames it,
// and SRX fleets that have done so are real. So `junos-exec` is this
// platform's default, not its constant, and an operator sets
// `platforms.juniper_junos.session_services` for a fleet that renamed it
// (spec §5.2, §8).
var sessionServices = map[string][]string{
	"arista_eos":    {"shell"},
	"cisco_iosxe":   {"shell"},
	"cisco_nxos":    {"shell"},
	"juniper_junos": {"junos-exec"},
}

// fallback is what a platform with no entry above authorizes. It is `shell`,
// which is what port49 required of every platform before this table existed,
// so adding the table denies nothing that used to work. Spec §8 "Unknown
// platforms" is the reason it is not "deny everything": an unmodeled platform
// is a missing dialect file, not a device to fail closed on, and someone will
// always rack something unmodeled.
var fallback = []string{"shell"}

// Known reports whether name has an entry in the table. Configuration refuses
// a `platforms:` key that is not Known, so `junos` written for `juniper_junos`
// is a load error rather than a block that quietly governs no device.
func Known(name string) bool {
	_, ok := sessionServices[name]
	return ok
}

// Names lists the known platforms in sorted order. It exists for the load
// error above: an operator who mistyped a platform name is owed the list of
// what they could have typed.
func Names() []string {
	out := make([]string, 0, len(sessionServices))
	for name := range sessionServices {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// SessionServices returns the built-in service list for name, or the fallback
// for a platform with no entry. The result is a fresh slice: callers store it
// in a resolved table and must not be able to edit this one through it.
func SessionServices(name string) []string {
	s, ok := sessionServices[name]
	if !ok {
		s = fallback
	}
	return append([]string(nil), s...)
}

// Defaults is the whole table, copied: the resolved session-service map a
// daemon runs with when no operator override is configured.
func Defaults() map[string][]string {
	out := make(map[string][]string, len(sessionServices))
	for name := range sessionServices {
		out[name] = SessionServices(name)
	}
	return out
}
