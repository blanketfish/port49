package port49d

import (
	"io"
	"os"
	"strings"
	"testing"
)

// captureStd runs f with os.Stdout and os.Stderr pointed at one pipe and returns what f wrote and
// returned. The subcommands write to os.Stdout and os.Stderr themselves, so this is the only seat.
func captureStd(t *testing.T, f func() int) (string, int) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = w, w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	code := f()
	os.Stdout, os.Stderr = oldOut, oldErr
	w.Close()
	return <-done, code
}

// The tables DaemonSubcommands and BrokerSubcommands list are the ones Main and BrokerMain dispatch
// from, so each name must reach its own command: with --help it prints that command's usage and
// never the top-level line an unknown first word prints.
func TestEachSubcommandDispatches(t *testing.T) {
	for _, tc := range []struct {
		binary string
		top    string
		names  []string
		run    func([]string) int
	}{
		{"port49d", "usage: port49d [--config FILE],", DaemonSubcommands(), Main},
		{"port49-broker", "usage: port49-broker [--config FILE],", BrokerSubcommands(), BrokerMain},
	} {
		// The control: an unknown word prints the top-level line and exits 2.
		out, code := captureStd(t, func() int { return tc.run([]string{"no-such-subcommand"}) })
		if code != 2 || !strings.Contains(out, tc.top) {
			t.Fatalf("%s: control: an unknown word gave exit %d and %q, want exit 2 and %q", tc.binary, code, out, tc.top)
		}
		if len(tc.names) == 0 {
			t.Fatalf("%s: no subcommands listed", tc.binary)
		}
		for _, name := range tc.names {
			out, _ := captureStd(t, func() int { return tc.run([]string{name, "--help"}) })
			if strings.Contains(out, tc.top) {
				t.Errorf("%s %s --help printed the top-level usage line, so the name does not dispatch", tc.binary, name)
			}
		}
	}
}
