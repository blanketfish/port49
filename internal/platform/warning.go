package platform

import "slices"

// ceilingWarningOn names the platforms sent the session ceiling warning in
// a permit's server_msg (spec §5.6; decision 33): those spec §15 L34 found
// show it and still treat the reply as a permit, each entry citing its
// note. EOS, NX-OS and Junos showed nothing and stay off
// (tests/lab/results/L34-arista_eos.md, L34-cisco_nxos.md,
// L34-juniper_vsrx.md, L34-juniper_vjunos-router.md); their operators are
// warned by port49 token. An operator adds an unmeasured platform with
// session.ceiling_warning_platforms. A table in code, not in a platform
// set: a released set is never edited.
var ceilingWarningOn = map[string]bool{
	// Shown before the prompt at login and after a permitted command's
	// output, which still ran (tests/lab/results/L34-cisco_iosxe.md).
	"cisco_iosxe": true,
}

// CeilingWarning reports whether name's permits carry the warning, given
// the platforms the operator added.
func CeilingWarning(name string, added []string) bool {
	return ceilingWarningOn[name] || slices.Contains(added, name)
}
