package platform

import "slices"

// ceilingWarningOn names the platforms sent the session ceiling warning in
// a permit's server_msg (spec §5.6; decision 33): those spec §15 L34 found
// show it and still treat the reply as a permit, each entry citing its
// note. It is empty until L34 is measured (plan 7b, Task 13); an operator
// adds an unmeasured platform with session.ceiling_warning_platforms. A table
// in code, not in a platform set: a released set is never edited.
var ceilingWarningOn = map[string]bool{}

// CeilingWarning reports whether name's permits carry the warning, given
// the platforms the operator added.
func CeilingWarning(name string, added []string) bool {
	return ceilingWarningOn[name] || slices.Contains(added, name)
}
