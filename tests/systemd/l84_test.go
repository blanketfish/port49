//go:build systemd

package systemd

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/tacacs/wire"
	"github.com/blanketfish/port49/internal/testpki"
	"github.com/blanketfish/port49/tests/shapes/l84"
	"github.com/blanketfish/port49/tests/shapes/shapetest"
	"github.com/blanketfish/port49/tests/systemd/sdtest"
)

// TestL84Credentials is spec §15 L84 cell (a) and its (c): systemd LoadCredential= against
// fence.ReadSecret, in Task 9's container (bringUp). UNVERIFIED until it runs: it has not met Docker
// or the package. It needs `make packages` and the debian image (the pull waits on Ryan's rules).
// It writes its cells to the JSON file named by PORT49_L84_CELLS_OUT, which the lab test
// (tests/lab/l84_test.go, PORT49_L84_A_CELLS) merges into the note; `make lab-l84-systemd` runs it.
//
// (a) A drop-in gives port49d LoadCredential=tacacs_v1:/etc/port49/keys/tacacs_v1, port49d.yaml's key_secret_refs.file_dir is
// /run/credentials/port49d.service (the shipped line, its directory replaced) and the policy names the file there. It
// records stat of the directory and the file, the start's result and a second start's; PASS iff both
// starts are ready and a login keyed with the credential passes.
// (c) tacacs_v2 as a second LoadCredential= line, a policy naming it, systemctl daemon-reload and no
// restart; PASS iff a login keyed with version 2 passes within 120 s and ExecMainStartTimestamp is
// unchanged. The expectation is FAIL (credentials are made at start); the cell tests it.
func TestL84Credentials(t *testing.T) {
	out := os.Getenv("PORT49_L84_CELLS_OUT")
	if out == "" {
		t.Fatal("INVALID: PORT49_L84_CELLS_OUT names the JSON file the cells are written to")
	}
	u := bringUp(t)
	b := u.b
	const credDir = "/run/credentials/port49d.service"
	const dropIn = "/etc/systemd/system/port49d.service.d"

	yes := func(ok bool) string {
		if ok {
			return "yes"
		}
		return "no"
	}
	stat := func() string {
		return strings.TrimSpace(b.sh("stat -c '%U:%G %a %F' " + credDir + " " + credDir + "/tacacs_v1 2>&1 || true"))
	}
	loggedIn := func(d shapetest.Device) bool {
		st, err := d.TryLogin("alice", u.mint())
		return err == nil && st == wire.AuthenStatusPass
	}
	a := l84.Cell{ID: "a", Verdict: l84.Fail}
	a.Rows = append(a.Rows, l84.Row{Case: "systemd", Observation: strings.SplitN(b.sh("systemctl --version"), "\n", 2)[0]})

	// The config and the policy name the credentials directory, once, before the first start. The
	// shipped config already names key_secret_refs (file_dir /etc/port49/keys): that one line's
	// directory is replaced, and a drift in the shipped line is INVALID.
	daemon, err := sdtest.KeyDir(b.sh("cat /etc/port49/port49d.yaml"), credDir)
	if err != nil {
		t.Fatalf("INVALID: %v", err)
	}
	b.put("/etc/port49/port49d.yaml", "root:root", "0644", daemon)
	const oldRef = "file:/etc/port49/keys/tacacs_v1"
	if !strings.Contains(u.policy, oldRef) {
		t.Fatalf("INVALID: the policy no longer names %s", oldRef)
	}
	policy := strings.Replace(u.policy, oldRef, "file:"+credDir+"/tacacs_v1", 1)
	b.put("/etc/port49/policy.yaml", "root:root", "0644", policy)
	b.put(dropIn+"/l84.conf", "root:root", "0644", "[Service]\nLoadCredential=tacacs_v1:/etc/port49/keys/tacacs_v1\n")
	b.sh("systemctl daemon-reload && systemctl restart port49d")
	// What systemd renders for User=port49d, measured apart from port49d by two one-shot units that
	// print the credentials directory they are given: l84-bare (User= and LoadCredential= only) and
	// l84-hard (the shipped port49d.service, its ExecStart replaced, with the same LoadCredential=).
	// If bare shows the directory and hard does not, the shipped hardening hides it; if neither does,
	// this systemd cannot render credentials here. The output holds paths, owners and modes only.
	b.put("/usr/local/bin/l84-probe.sh", "root:root", "0755", `#!/bin/sh
echo "CREDENTIALS_DIRECTORY=[$CREDENTIALS_DIRECTORY]"
ls -ldn /run/credentials /run/credentials/* 2>&1
ls -ln "$CREDENTIALS_DIRECTORY" 2>&1
id
`)
	b.put("/etc/systemd/system/l84-bare.service", "root:root", "0644", "[Service]\nType=oneshot\nUser=port49d\nGroup=port49d\n"+
		"LoadCredential=tacacs_v1:/etc/port49/keys/tacacs_v1\nExecStart=/bin/sh /usr/local/bin/l84-probe.sh\n")
	b.sh(`frag=$(systemctl show port49d -p FragmentPath --value) && sed -e 's|^ExecStart=.*|ExecStart=/bin/sh /usr/local/bin/l84-probe.sh|' ` +
		`-e 's|^Type=simple|Type=oneshot|' -e '/^ExecReload=/d;/^Restart=/d;/^RestartSec=/d;/^\[Install\]/,$d' "$frag" ` +
		`> /etc/systemd/system/l84-hard.service && echo 'LoadCredential=tacacs_v1:/etc/port49/keys/tacacs_v1' >> /etc/systemd/system/l84-hard.service`)
	probe := func(name string) string {
		out := b.sh("systemctl daemon-reload; systemctl start " + name + ".service 2>&1; " +
			"echo \"start result: $(systemctl show " + name + " -p Result --value) status $(systemctl show " + name + " -p ExecMainStatus --value)\"; " +
			"journalctl -u " + name + ".service --no-pager -o cat 2>&1 || true")
		return strings.Join(strings.Fields(strings.ReplaceAll(strings.TrimSpace(out), "\n", " ; ")), " ")
	}
	a.Rows = append(a.Rows,
		l84.Row{Case: "what systemd renders: User=port49d with LoadCredential= only (l84-bare)", Observation: probe("l84-bare")},
		l84.Row{Case: "what systemd renders: the shipped port49d.service's hardening, same LoadCredential= (l84-hard)", Observation: probe("l84-hard")})
	a.Rows = append(a.Rows, l84.Row{Case: "stat of the credentials directory and file (owner:group mode type), when port49d was restarted", Observation: stat()})
	// A bounded wait: a start that never becomes ready is the measurement, not an invalid run.
	ready := func() bool {
		deadline := time.Now().Add(90 * time.Second)
		for ; time.Now().Before(deadline); time.Sleep(2 * time.Second) {
			if resp, err := http.Get("http://127.0.0.1:9049/readyz"); err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					return true
				}
			}
		}
		return false
	}
	// refusal is a category from port49d's own error words, never the journal line.
	refusal := func() string {
		for _, r := range sdtest.Refusals {
			n := strings.TrimSpace(b.sh("journalctl -u port49d --no-pager -o cat | grep -i -F -- '" + r.Phrase + "' | grep -c -F -- '" + r.Also + "' || true"))
			if n != "" && n != "0" {
				return r.Category
			}
		}
		return "no refusal of a secret file or directory in port49d's words"
	}
	unit := func() string {
		m := b.show("port49d", "ExecMainStatus", "Result", "NRestarts", "ActiveState")
		return fmt.Sprintf("ActiveState=%s Result=%s ExecMainStatus=%s NRestarts=%s",
			m["ActiveState"], m["Result"], m["ExecMainStatus"], m["NRestarts"])
	}
	first, second := false, false
	if ready() {
		first = loggedIn(u.dev)
		a.Rows = append(a.Rows, l84.Row{Case: "first start", Observation: "ready; a login keyed with the credential: " + yes(first)})
		b.sh("systemctl restart port49d")
		if ready() {
			second = loggedIn(u.dev)
			a.Rows = append(a.Rows, l84.Row{Case: "second start", Observation: "ready; a login keyed with the credential: " + yes(second)},
				l84.Row{Case: "stat after the second start", Observation: stat()})
		} else {
			a.Rows = append(a.Rows, l84.Row{Case: "second start", Observation: "not ready in 90 s: " + unit() + "; " + refusal()})
		}
	} else {
		a.Rows = append(a.Rows, l84.Row{Case: "first start", Observation: "not ready in 90 s: " + unit() + "; " + refusal()})
	}
	if first && second {
		a.Verdict = l84.Pass
	}
	cells := []l84.Cell{a}

	c := l84.Cell{ID: "c-systemd", Verdict: l84.NotRun, Rows: []l84.Row{{Case: "state", Observation: "not run: cell (a) did not pass"}}}
	if a.Verdict == l84.Pass {
		started := b.show("port49d", "ExecMainStartTimestamp")["ExecMainStartTimestamp"]
		v2, err := testpki.RandomSecret(32)
		if err != nil {
			t.Fatal(err)
		}
		b.put("/etc/port49/keys/tacacs_v2", "root:port49d", "0440", string(v2))
		next, err := shapetest.WithAcceptV2([]byte(policy), credDir)
		if err != nil {
			t.Fatal(err)
		}
		b.put("/etc/port49/policy.yaml", "root:root", "0644", string(next))
		b.put(dropIn+"/l84.conf", "root:root", "0644",
			"[Service]\nLoadCredential=tacacs_v1:/etc/port49/keys/tacacs_v1\nLoadCredential=tacacs_v2:/etc/port49/keys/tacacs_v2\n")
		b.sh("systemctl daemon-reload")
		_, errV2 := b.exec("", "test", "-e", credDir+"/tacacs_v2")
		dev2 := shapetest.Device{T: t, Addr: "127.0.0.1:49", Key: []byte(v2)}
		begin := time.Now()
		inForce := false
		for time.Since(begin) < 120*time.Second && !inForce {
			inForce = loggedIn(dev2)
			if !inForce {
				time.Sleep(2 * time.Second)
			}
		}
		after := b.show("port49d", "ExecMainStartTimestamp")["ExecMainStartTimestamp"]
		c.Rows = []l84.Row{
			{Case: "the second credential's file in the running unit's directory after daemon-reload", Observation: yes(errV2 == nil)},
			{Case: "a login keyed with version 2 (policy names it)", Observation: fmt.Sprintf("in force within 120 s: %s", yes(inForce))},
			{Case: "ExecMainStartTimestamp", Observation: "before " + started + ", after " + after + "; unchanged: " + yes(started == after)},
		}
		c.Verdict = l84.Fail
		if inForce && started == after {
			c.Verdict = l84.Pass
		}
	}
	cells = append(cells, c)
	if err := l84.Save(out, cells); err != nil {
		t.Fatal(err)
	}
}
