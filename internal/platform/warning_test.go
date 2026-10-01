package platform

import "testing"

// No platform carries the warning until L34 names it; an operator's list
// adds one (spec §5.6; pre-flight M10).
func TestCeilingWarningIsAnAllowList(t *testing.T) {
	if CeilingWarning("arista_eos", nil) {
		t.Fatal("arista_eos warned with nothing measured and nothing added")
	}
	if !CeilingWarning("arista_eos", []string{"cisco_nxos", "arista_eos"}) {
		t.Fatal("an operator-added platform was not warned")
	}
	if CeilingWarning("cisco_nxos", []string{"arista_eos"}) {
		t.Fatal("a platform the operator did not add was warned")
	}
}
