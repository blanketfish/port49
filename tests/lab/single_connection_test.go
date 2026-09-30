//go:build lab

package lab

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/tests/lab/labcreds"
)

// singleConnectionAsks are the positions TestSingleConnectionSyntax asks the
// N9Kv's `?` at, to find where `single-connection` goes on its
// `tacacs-server host` line relative to `key 0 <key>`. <key> stands for the
// lab key, which is typed and never printed.
var singleConnectionAsks = []string{
	"tacacs-server host 172.100.100.1 ?",
	"tacacs-server host 172.100.100.1 single-connection ?",
	"tacacs-server host 172.100.100.1 key 0 <key> ?",
	"tacacs-server host 172.100.100.1 key 0 <key> single-connection ?",
}

// TestSingleConnectionSyntax reads, on NX-OS, the `?` help at each of
// singleConnectionAsks, with port49d stopped (offered), and writes what the
// device said, the key redacted, to
// tests/lab/results/single-connection-syntax-cisco_nxos.md: the measurement
// singleConnection's NX-OS line is written from (plan 6b Task 19).
func TestSingleConnectionSyntax(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if l.p.name != "cisco_nxos" {
			t.Skipf("the single-connection line's shape is measured on NX-OS only; %s's is set as the `?` offers it", l.p.name)
		}
		var b strings.Builder
		fmt.Fprintf(&b, "# single-connection-syntax — %s\n\n- **Date measured:** %s\n- **Platform:** %s (containerlab "+
			"node `%s`, %s)\n- **Image version:** %s (`%s`)\n- **Capture:** none: the break-glass CLI with port49d "+
			"stopped, no TACACS+ traffic\n\n## Claim\n\nWhere `single-connection` goes on the N9Kv's `tacacs-server host` "+
			"line relative to `key 0 <key>` (plan 6b Task 19; the line singleConnection types).\n\n## Observation\n\n"+
			"Each position was typed in configuration mode followed by `?`, then cleared (Ctrl-U) and left without "+
			"committing. `<key>` stands for the lab key, typed and redacted here.\n\n",
			l.p.name, time.Now().UTC().Format("2006-01-02"), l.p.name, l.p.node, l.p.addr, l.p.version, l.p.image)
		for _, ask := range singleConnectionAsks {
			typed := strings.ReplaceAll(ask, "<key>", labKeyDefault)
			_, help := l.offered(t, []string{"configure terminal"}, []string{typed}, "single-connection")
			help = strings.TrimSpace(strings.ReplaceAll(help, "\r", "")) // offered has replaced the key with <key>
			ok := helpOffers(help, "single-connection")
			fmt.Fprintf(&b, "### `%s`\n\nOffers `single-connection`: %v. The device said:\n\n```\n%s\n```\n\n", ask, ok, help)
			t.Logf("single-connection: `%s`: offers single-connection %v", ask, ok)
		}
		path := filepath.Join(root, "tests", "lab", "results", "single-connection-syntax-"+l.p.name+".md")
		if err := os.WriteFile(path, []byte(labcreds.RedactNote(b.String())), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", path)
	})
}

// helpOffers reports whether help, a `?` answer, lists keyword among its
// choices: a line of the list, not the echo of the half line typed, which may
// hold the keyword itself.
func helpOffers(help, keyword string) bool {
	lines := strings.Split(help, "\n")
	for _, ln := range lines[min(1, len(lines)):] {
		if f := strings.Fields(ln); len(f) > 0 && f[0] == keyword {
			return true
		}
	}
	return false
}
