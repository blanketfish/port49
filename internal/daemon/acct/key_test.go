package acct

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/tacacs/wire"
)

// Accounting resolves its context by (nas, username) like every other
// exchange (spec §5.8), so a record whose port is a value the authentication
// never carried still attributes. On Junos the accounting port is `0`, `1` or
// `non-tty` while the authentication port was the empty string; on vEOS the
// stop carries `vty<n>` where the start carried `ssh`.
func TestAttributionIgnoresThePort(t *testing.T) {
	for _, port := range []string{"vty0", "non-tty", "", "0", "vty4"} {
		t.Run("port="+port, func(t *testing.T) {
			h, out, stop := setup(t)
			h.Handle(context.Background(), peer, acct(wire.AcctFlagStop, "alice", port,
				"task_id=43", "service=shell", "cmd="))
			stop()
			var m map[string]any
			if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &m); err != nil {
				t.Fatal(err)
			}
			s := m["session"].(map[string]any)
			if m["attribution"] != "resolved" || s["ctx_id"] != "ctx1" {
				t.Fatalf("%v", m)
			}
			// Requirement (e): the port as seen on this exchange is recorded.
			if s["port"] != port {
				t.Fatalf("port on the record: %v, want %q", s["port"], port)
			}
		})
	}
}
