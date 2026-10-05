//go:build lab

package lab

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const l39Claim = "On the compose deployment (plan 7f; deploy/compose), with port49d's TACACS+ port published on " +
	"the clab bridge's address (172.100.100.1:49), port49d sees the device's own address as the TCP source, so " +
	"the device-binding check passes for the known device: the redeem record's device.nas is the device's " +
	"management address, not the compose network's gateway (" + composeGateway + ", listed as l39_gateway so a " +
	"rewritten source is recorded rather than refused). Measured with Docker's userland proxy as the run found it " +
	"(policy engine spec §15 L39 (a); design §13)."

// TestL39DockerSourceAddress measures L39 (a) in the mode Docker runs in
// now: run it once with the userland proxy on (Docker's default) and once
// with "userland-proxy": false in /etc/docker/daemon.json (Task 2 Step 7).
// One platform is enough (the observation is the server's): run it with
// PORT49_LAB_PLATFORMS=eos.
func TestL39DockerSourceAddress(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		c := l.startCompose(t)
		mode, err := c.ProxyMode()
		if err != nil {
			t.Fatal(err)
		}
		entry := "L39-docker-proxy-" + mode
		stop := l.capture(t, entry)
		defer stop()
		off := l.mark()
		sock, _, stopAgent := revokeAgent(t)
		defer stopAgent()
		said, tok := l29Mint(sock, l.p.node)
		if tok == "" {
			t.Fatalf("the agent minted no token through the compose broker: %s", said)
		}
		_, lerr := l.loginWithin(sliceUser, tok, 90*time.Second, "show version")
		recs := l.waitForRecords(off, 30*time.Second, func(rs []map[string]any) bool { return redeemReason(rs, sha(tok)) != "" })
		nas, name := "", ""
		for _, r := range sliceRecords(recs, "redeem", "") {
			if str(sub(r, "auth"), "credential_sha256") == sha(tok) {
				nas, name = str(sub(r, "device"), "nas"), str(sub(r, "device"), "name")
			}
		}
		var obs strings.Builder
		obs.WriteString("| cell | observed |\n|---|---|\n")
		fmt.Fprintf(&obs, "| Docker's userland proxy | %s (a docker-proxy process %s 172.100.100.1:49) |\n", mode,
			map[string]string{"on": "serves", "off": "does not serve"}[mode])
		dv, _ := exec.Command("docker", "version", "--format", "{{.Server.Version}}").Output()
		fmt.Fprintf(&obs, "| Docker engine | %s |\n", strings.TrimSpace(string(dv)))
		fmt.Fprintf(&obs, "| the redeem record's device | nas %q, name %q (the device's address: %s) |\n", nas, name, l.p.addr)
		fmt.Fprintf(&obs, "| the login | err %v; redeem %q |\n", lerr, redeemReason(recs, sha(tok)))
		note := obs.String()
		failed := nas != l.p.addr || lerr != nil
		if failed && nas == "" && len(recs) == 0 {
			// No record at all is "the connection never reached port49d", not a
			// rewritten source: Docker's bridge isolation can drop traffic
			// DNAT'd from the clab network to the compose network (Step 5a).
			note += "\n**No connection reached port49d:** no record of any kind, so this says nothing about the " +
				"source address. Step 5a's reachability check decides which it is.\n"
		} else if failed {
			note += fmt.Sprintf("\n**Not as the claim says:** port49d saw %q, not the device's %s.\n", nas, l.p.addr)
		}
		l.result(t, entry, l39Claim, note)
		if failed {
			t.Fatalf("L39 (a), proxy %s: port49d saw %q, want %s; login err %v", mode, nas, l.p.addr, lerr)
		}
	})
}
