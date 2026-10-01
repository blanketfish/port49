//go:build lab

package lab

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const sotE2EClaim = "A change in a source of truth reaches a device's admission through the webhook, the " +
	"inventory service and port49d (spec §15 L33, the device run): the device in NetBox or Nautobot, synced by the " +
	"connector, admits a token login; an attribute change, a status change that the default filter removes, and " +
	"the status restored each publish through the webhook and reload in port49d, and break-glass logs in while " +
	"the device is removed."

// TestSoTDeviceEndToEnd runs one stack (run.sh <netbox-4|nautobot-3> e2e,
// with PORT49_LAB_PLATFORMS=arista_eos) to vEOS.
func TestSoTDeviceEndToEnd(t *testing.T) {
	stack := os.Getenv("L32_STACK")
	if stack == "" || os.Getenv("L33_HOOK_BIND") == "" {
		t.Skip("run by tests/lab/sot/run.sh <stack> e2e")
	}
	eachPlatform(t, func(t *testing.T, l *lab) {
		if l.p.name != "arista_eos" {
			t.Skip("the end-to-end run is vEOS's")
		}
		pr := l29Heartbeat(t)
		defer pr.end()
		var failed []string
		fail := func(format string, args ...any) {
			msg := fmt.Sprintf(format, args...)
			failed = append(failed, msg)
			t.Error(msg)
		}
		a := newSoTAdmin(t)
		node := l.p.node
		var obs strings.Builder
		fmt.Fprintf(&obs, "%s\n\nSource of truth: %s (`run.sh %s e2e`), beside the 120 devices the run seeded.\n\n",
			l29Built(), stack, stack)

		// 1. The device in the source of truth: leaf-01's facts, its own
		// name, and the address it sources TACACS+ from as its primary.
		pr.at(t, "the device in %s", stack)
		id, err := a.createDevice(node)
		if err == nil {
			err = a.addPrimary(id, l.p.addr+"/32")
		}
		if err != nil {
			t.Fatalf("seeding %s: %v", node, err)
		}

		// 2. The service with the stack as its one source and its webhook;
		// port49d pulling it, on the lab policy with an attribute group for
		// site dc1 beside its CIDR group, so the 120 seeded devices are
		// admitted and removing this one is under every bound.
		raw, err := os.ReadFile(filepath.Join(root, "tests", "lab", "l29", "policy.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		withSite := strings.Replace(string(raw), "key_groups:\n",
			"key_groups:\n  - {match: {attributes: {site: dc1}}, key_ref: lab_key}\n", 1)
		if withSite == string(raw) {
			t.Fatal("tests/lab/l29/policy.yaml has no key_groups: block to add to")
		}
		policy := filepath.Join(privateDir(t, "sot-e2e-"+l.p.name), "policy.yaml")
		writeAtomic(t, policy, []byte(withSite), 0o600)
		secret := l33Secret(t)
		li := newLabInventory(t, l.p.name)
		startInventoryWith(t, li, policy, l33SyncYAML(stack, a.product), []string{"L33_WEBHOOK_SECRET=" + secret})
		l29RestoreStanding(t, l)
		if err := a.removeWebhooks("l27"); err != nil {
			t.Fatal(err)
		}
		_, port, _ := net.SplitHostPort(os.Getenv("L33_HOOK_BIND"))
		if _, err := a.webhook("port49-e2e", "https://port49-inventory.lab:"+port+"/v1/webhook/l33", secret,
			"/etc/port49-lab/ca.pem"); err != nil {
			t.Fatal(err)
		}
		stop := l.capture(t, "L33-e2e")
		defer stop()
		l.l28Restart(t, l.serviceConfig(t, li, policy))
		agent, stopAgent := l29Agent(t)
		defer stopAgent()
		login := func() string {
			said, tok := l29Mint(agent, node)
			if tok == "" {
				return "no token: " + oneLine(said)
			}
			t0 := time.Now()
			c, err := l.dial(sliceUser, tok, 120*time.Second)
			if err != nil {
				return fmt.Sprintf("refused in %s: %s", time.Since(t0).Round(10*time.Millisecond), oneLine(err.Error()))
			}
			c.Close()
			return fmt.Sprintf("logged in in %s", time.Since(t0).Round(10*time.Millisecond))
		}
		pr.at(t, "a token login with the device synced from %s", stack)
		first := login()
		fmt.Fprintf(&obs, "Token login, the device synced at start: %s.\n\n", first)
		if !strings.HasPrefix(first, "logged in") {
			fail("the token login after the first sync did not log in: %s", first)
		}

		// 3. Each change through the webhook: its time to the service's
		// publication and to port49d's reload, and what a login then does.
		obs.WriteString("| change | to the service's publication | to port49d's reload | token login after | break-glass after |\n|---|---|---|---|---|\n")
		for _, ch := range []struct {
			name     string
			body     map[string]any
			admitted bool
		}{
			{"os_version 4.99.0F", map[string]any{"custom_fields": map[string]any{"os_version": "4.99.0F"}}, true},
			{"status offline (the default filter removes it)", map[string]any{"status": a.statusWord("offline")}, false},
			{"status active again", map[string]any{"status": a.statusWord("active")}, true},
		} {
			pr.at(t, "%s", ch.name)
			time.Sleep(35 * time.Second) // past the debouncer's gap
			mark, errOff := li.mark(), l.errMark()
			t0 := time.Now()
			if err := a.patchDevice(id, ch.body); err != nil {
				t.Fatalf("%s: %v", ch.name, err)
			}
			pub, okPub := li.waitLine(t, mark, "sync (webhook): published bundle", 2*time.Minute)
			rel, okRel := l.waitForLine(t, errOff, "port49d: inventory reloaded (inventory service, bundle", 2*time.Minute)
			cell := func(ok bool, at time.Time) string {
				if !ok {
					return "not observed"
				}
				return fmt.Sprintf("%.2f s", at.Sub(t0).Seconds())
			}
			if !okPub || !okRel {
				fail("%s: published %v, reloaded %v", ch.name, okPub, okRel)
			}
			after, glass := login(), "not tried"
			if !ch.admitted {
				out := l.timedLogins(t)
				glass = "logged in"
				if !strings.Contains(out, "| break-glass login plus three `show version` | logged in") {
					glass = "did not log in"
					fail("%s: break-glass did not log in while the device is removed", ch.name)
				}
			}
			if ch.admitted != strings.HasPrefix(after, "logged in") {
				fail("%s: the token login after it: %s", ch.name, after)
			}
			fmt.Fprintf(&obs, "| %s | %s | %s | %s | %s |\n", ch.name, cell(okPub, pub), cell(okRel, rel), after, glass)
		}
		if raw, _ := os.ReadFile(li.errPath); strings.Contains(string(raw), secret) {
			fail("the service's log holds the webhook secret")
		}
		pr.end()
		l.l29Note(t, "L33-e2e-"+a.product, sotE2EClaim, obs.String(), failed)
	})
}
