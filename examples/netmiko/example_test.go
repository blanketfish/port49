// Package netmiko holds the Netmiko example's test: its own Python test, run
// when python3 is installed (plan 9a, Task 7).
package netmiko

import (
	"os"
	"os/exec"
	"testing"
)

func TestTheNetmikoExample(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed: the example's own test needs it")
	}
	cmd := exec.Command(py, "test_port49_netmiko.py", "-v")
	// Never write bytecode into the tree.
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
}
