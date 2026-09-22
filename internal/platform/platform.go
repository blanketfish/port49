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

// EnableUsername is what a platform's enable START carries in the `user`
// field. Every platform measured carries the operator's own username:
// vEOS 4.32.2F and Catalyst 8000V 17.13.01a, both with service=enable
// (tests/lab/results/L3-arista_eos.md, L3-cisco_iosxe.md), and NX-OS 10.x has
// no enable exchange at all (L3-nxos-cisco_nxos.md). No device in this lab has
// been observed sending $enab{level}$.
//
// EnableEnab exists so the shape has a name and a refusal rather than an
// implementation nothing has ever exercised. config.Load refuses it.
const (
	EnablePrincipal = "principal"
	EnableEnab      = "enab"
)

// EnableUsernames is the built-in table: every known platform, principal.
func EnableUsernames() map[string]string {
	out := make(map[string]string, len(sessionServices))
	for name := range sessionServices {
		out[name] = EnablePrincipal
	}
	return out
}

// KnownEnableUsername reports whether v is a value config.Load will accept
// for `platforms.<name>.enable_username` — either the shipping default or the
// refused-but-named `enab` — as opposed to a typo, which is a different error.
func KnownEnableUsername(v string) bool { return v == EnablePrincipal || v == EnableEnab }

// sessionDiscriminators names the AV pair whose value separates two sessions of
// one user on one device, per platform (spec §5.8). Every entry is measured:
//
//   - juniper_junos: session_pid. NOT task_id — it restarts at 1 per session on
//     both Junos images, so two concurrent logins both sent task_id=1 while
//     session_pid was 31048/31050 on vSRX and 17244/17246 on vJunos-router
//     (tests/lab/results/L17-juniper_vsrx.md, L17-juniper_vjunos-router.md).
//   - arista_eos: task_id, 27 and 28 across two concurrent sessions and stable
//     start to stop (tests/lab/results/L1-arista_eos.md).
//   - cisco_nxos: task_id, which is `<addr>@pts/<n>` and differed across two
//     concurrent sessions (tests/lab/results/L1-cisco_nxos.md).
//   - cisco_iosxe: task_id, 4033 and 4034 across two concurrent sessions
//     (tests/lab/results/L1-cisco_iosxe.md).
//
// Unmeasured: durability across a reboot or a pid wrap, behaviour under load,
// and every non-SSH transport. A platform with no entry binds nothing and takes
// §5.8's username-only branch, which is the safe direction.
var sessionDiscriminators = map[string]string{
	"arista_eos":    "task_id",
	"cisco_iosxe":   "task_id",
	"cisco_nxos":    "task_id",
	"juniper_junos": "session_pid",
}

// SessionDiscriminator returns the AV pair whose value separates two sessions
// of one user on one device, and whether this platform has one.
func SessionDiscriminator(platformName string) (string, bool) {
	av, ok := sessionDiscriminators[platformName]
	return av, ok
}

// execCommands names the `cmd` values that mark a record as the session's own
// exec record on platforms that put a command there at all. It is per platform
// because the shape is:
//
//   - arista_eos, cisco_nxos, cisco_iosxe: the exec START and STOP carry no
//     `cmd` argument, so "no command" identifies them
//     (tests/lab/results/L6-arista_eos.md, L6-cisco_nxos.md, L6-cisco_iosxe.md,
//     and the packet dumps in L1-*).
//   - juniper_junos: they carry `cmd=login` and `cmd=logout`, alongside
//     per-command records carrying the typed command
//     (tests/lab/results/L6-juniper_vsrx.md, L6-juniper_vjunos-router.md:
//     "an exec record is one that carries no command at all, as on EOS, or
//     carries only `login` or `logout`, as on Junos").
//
// A reader that knows only the first shape annotates nothing whatsoever on
// Junos, and does so silently — every Junos session takes the unset branch.
var execCommands = map[string][]string{
	"juniper_junos": {"login", "logout"},
}

// IsExecRecord reports whether an accounting record carrying this `cmd` is the
// session's own exec record rather than a per-command one, on platformName.
// Only exec records annotate login context (spec §5.8).
//
// An unmodeled platform gets the majority shape — no `cmd` at all — rather
// than Junos's, because guessing the other way would treat a device that
// really does send `cmd=login` as a command as an exec record and clear a
// live session's accounting_state on it.
func IsExecRecord(platformName, cmd string) bool {
	if cmd == "" {
		return true
	}
	for _, c := range execCommands[platformName] {
		if c == cmd {
			return true
		}
	}
	return false
}

// systemUsers are the usernames a platform's own machinery writes accounting
// under. It is EMPTY for every shipped platform and stays that way until a
// tests/lab/results/ note measures one: the Junos lab measured the opposite,
// every record naming the logged-in operator and none naming root under this
// lab's accounting event list (L17-juniper_vsrx.md, L17-juniper_vjunos-router.md).
// Two production observations — a Junos RPC-driven `show` as root, and an NX-OS
// admin record with task_id=vsh.bin.$port after a cancelled sudo — are
// unmeasured in this lab and are recorded as such in spec §5.8; neither is
// entered here. Plan 5's adapters own the list; the rule that reads it is
// plan 2's.
var systemUsers = map[string][]string{}

// SystemUsers is the per-platform table of usernames a platform's own
// machinery writes accounting under. It returns a copy, and every shipped
// platform's entry is empty.
//
// main.go hands it to acct.New; the handler never reads this package at
// request time, so there is no global for a test to mutate and no lock to get
// wrong under -race.
func SystemUsers() map[string][]string {
	out := make(map[string][]string, len(systemUsers))
	for name, users := range systemUsers {
		out[name] = append([]string(nil), users...)
	}
	return out
}
