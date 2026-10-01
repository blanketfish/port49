package platform

import "testing"

// A platform carries the warning when L34 found it shows it and still
// permits, or when an operator's list adds it (spec §5.6; pre-flight M10).
func TestCeilingWarningIsAnAllowList(t *testing.T) {
	if !CeilingWarning("cisco_iosxe", nil) {
		t.Fatal("cisco_iosxe, which L34 found shows it, was not warned")
	}
	for _, name := range []string{"arista_eos", "cisco_nxos", "juniper_junos"} {
		if CeilingWarning(name, nil) {
			t.Fatalf("%s, which L34 found does not show it, was warned with nothing added", name)
		}
	}
	if !CeilingWarning("arista_eos", []string{"cisco_nxos", "arista_eos"}) {
		t.Fatal("an operator-added platform was not warned")
	}
	if CeilingWarning("cisco_nxos", []string{"arista_eos"}) {
		t.Fatal("a platform the operator did not add was warned")
	}
}
