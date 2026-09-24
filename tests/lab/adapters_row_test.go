//go:build lab

package lab

import (
	"errors"
	"strings"
	"testing"
)

// These run without a device (`go test -tags lab -run TestAdapterRow
// ./tests/lab`): no platform is brought up for a test that never calls
// eachPlatform.

var rowCommands = []string{"show privilege", "clear counters", "configure terminal", "show version"}

func commandRecord(verdict string, vector ...string) map[string]any {
	v := make([]any, len(vector))
	for i, w := range vector {
		v[i] = w
	}
	return map[string]any{"event": "authorize_command", "verdict": verdict, "request": map[string]any{"vector": v}}
}

// A command whose deadline expired is not observed: its cell never reads
// "refused by the device", the row says which command and why, and the
// level check has something to fail on (task 17 review I1). A command a
// record shows reaching port49 still reads sent.
func TestAdapterRowADeadlineIsNotObserved(t *testing.T) {
	var missed notObserved
	missed.add("clear counters", "deadline")
	outs := []string{"Current privilege level is 1\n", "", "", "Arista vEOS\n"}
	row := adapterRowFrom("arista_eos", rowCommands, outs, &missed,
		[]map[string]any{commandRecord("permit", "show", "version")})
	if row.err != nil || row.session != "not observed (clear counters: deadline)" {
		t.Fatalf("session %q, err %v", row.session, row.err)
	}
	if got := row.reach("clear counters", row.clear); got != "not observed" {
		t.Errorf("clear counters: %q", got)
	}
	if got := row.reach("configure terminal", row.cfg); got != "refused by the device" {
		t.Errorf("configure terminal, which finished with no record: %q", got)
	}
	if got := row.permit(row.showVersion); got != "permitted by port49" {
		t.Errorf("show version: %q", got)
	}
	if row.identity != "Current privilege level is 1" || len(row.unobserved) != 1 {
		t.Errorf("identity %q, unobserved %v", row.identity, row.unobserved)
	}

	// The prompt never came back after the identity command: it is not
	// observed, and neither is anything after it.
	missed = notObserved{}
	missed.add("show privilege", "deadline")
	for _, c := range rowCommands[1:] {
		missed.add(c, "not run")
	}
	row = adapterRowFrom("cisco_iosxe", rowCommands, []string{""}, &missed, nil)
	if row.identity != "" || len(row.unobserved) != 4 || !strings.HasPrefix(row.session, "not observed (show privilege: deadline; ") {
		t.Fatalf("%+v", row)
	}
	for _, c := range rowCommands[1:3] {
		if got := row.reach(c, false); got != "not observed" {
			t.Errorf("%s: %q", c, got)
		}
	}
}

// A session that never opened observed nothing: every command reads "not
// observed", and the row carries the error.
func TestAdapterRowASessionThatNeverOpened(t *testing.T) {
	err := errors.New("none of [\"xe1#\" \"xe1>\"] appeared on the SSH CLI as alice05 within 1m0s; what it said was:\n" +
		"% Authorization failed.\n")
	row := adapterRowFrom("cisco_iosxe", rowCommands, nil, err, nil)
	if row.err == nil || !strings.HasPrefix(row.session, "refused: ") || strings.Contains(row.session, "\n") {
		t.Fatalf("session %q, err %v", row.session, row.err)
	}
	for _, c := range rowCommands[1:3] {
		if got := row.reach(c, false); got != "not observed" {
			t.Errorf("%s: %q", c, got)
		}
	}
	if got := row.permit(false); got != "not observed" {
		t.Errorf("show version: %q", got)
	}
}
