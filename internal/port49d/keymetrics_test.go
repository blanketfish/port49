package port49d

import (
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/admission"
	"github.com/blanketfish/port49/internal/config"
	"github.com/blanketfish/port49/internal/policy"
	"github.com/blanketfish/port49/internal/secretref"
)

func TestSingleDeviceKeyRefsAreTheOnesHeldOnce(t *testing.T) {
	got := singleDeviceKeyRefs([]string{"core", "r1_pin", "core", ""})
	if len(got) != 1 || !got["r1_pin"] {
		t.Fatalf("got %v, want only r1_pin", got)
	}
}

// A policy pinning one device to its own key and two to core reports the pin
// as single-device and core as itself.
func TestPolicyAndIndexSingleDeviceKeyRefs(t *testing.T) {
	dev := func(name, addr, pin string) admission.Device {
		return admission.Device{Name: name, Platform: "arista_eos", KeyRef: pin, Transport: admission.TransportTCP,
			Addresses: []netip.Addr{netip.MustParseAddr(addr)}}
	}
	keys := "keys:\n"
	for _, r := range []string{"core", "r1_pin"} {
		keys += "  " + r + ":\n    current: {version: 1, secret_ref: env:PORT49_KEY_RUN}\n"
	}
	body := strings.Replace(minimalPolicy, runKeys, "", 1) +
		"key_groups:\n  - {match: {cidr: 0.0.0.0/0}, key_ref: core}\n" + keys
	pol, err := policy.Parse([]byte(body), policy.Env{Devices: []admission.Device{
		dev("r1", "192.0.2.1", "r1_pin"), dev("a", "192.0.2.2", ""), dev("b", "192.0.2.3", "")}})
	if err != nil {
		t.Fatal(err)
	}
	got := policySingleDeviceKeyRefs(pol)
	if len(got) != 1 || !got["r1_pin"] {
		t.Fatalf("policy: got %v, want only r1_pin", got)
	}
	// With no policy: the admission index config.Load built.
	inv := admission.Inventory{Devices: []admission.Device{dev("r1", "192.0.2.1", "r1_pin"),
		dev("a", "192.0.2.2", "core"), dev("b", "192.0.2.3", "core")}}
	trie, err := admission.Build(inv)
	if err != nil {
		t.Fatal(err)
	}
	got = indexSingleDeviceKeyRefs(config.Config{Inventory: inv, Admission: trie})
	if len(got) != 1 || !got["r1_pin"] {
		t.Fatalf("index: got %v, want only r1_pin", got)
	}
}

// keyRunConfig is a no-broker run of the policy file policy, over an
// inventory of leaf1 (127.0.0.1), leaf2 (127.0.0.2) and leaf3 (127.0.0.3)
// with the key_groups the inventory says; and the policy file's path.
func keyRunConfig(t *testing.T, policy, inventory string) (cfgPath, policyPath string) {
	t.Helper()
	b := brokerConfig(t, policy).Broker
	cfgPath = writeRunConfigWith(t, b, inventory, "")
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	body = body[:strings.Index(body, "broker:\n")] + "policy: {file: " + b.PolicyFile + ", watch_interval: 1s}\n" +
		"inventory: {max_removed_percent: 100}\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, b.PolicyFile
}

// keyScrape is the /metrics of the run whose stderr is out, filtered to the
// key_validations lines.
func keyScrape(t *testing.T, out *syncBuffer) string {
	t.Helper()
	ms := regexp.MustCompile(`port49d: metrics on (127\.0\.0\.1:\d+)`).FindAllStringSubmatch(out.String(), -1)
	if len(ms) == 0 {
		t.Fatal("no metrics address said")
	}
	resp, err := http.Get("http://" + ms[len(ms)-1][1] + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, l := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(l, "port49_key_validations_total{") {
			lines = append(lines, l)
		}
	}
	return strings.Join(lines, "\n")
}

const threeLeaves = `
devices:
  - {name: leaf1, platform: arista_eos, addresses: [127.0.0.1]%s}
  - {name: leaf2, platform: arista_eos, addresses: [127.0.0.2]}
  - {name: leaf3, platform: arista_eos, addresses: [127.0.0.3]}
key_groups:
  - {match: {cidr: 127.0.0.0/8}, key_ref: k}
`

// One device pinned to its own key and two on k: a login from the pinned one
// is counted under single_device/any, and no line carries the pin's name.
func TestAPinnedDeviceIsReportedAsSingleDevice(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	cfgPath, _ := keyRunConfig(t, minimalPolicy, fmt.Sprintf(threeLeaves, ", key_ref: lab_key"))
	tacacs := startSplitDaemon(t, cfgPath, &out, 1)
	if !answeredFrom(t, tacacs, "127.0.0.1") || !answeredFrom(t, tacacs, "127.0.0.2") {
		t.Fatal("a login was not answered")
	}
	got := keyScrape(t, &out)
	if strings.Contains(got, "lab_key") {
		t.Fatalf("a key_validations line names the pin:\n%s", got)
	}
	if !strings.Contains(got, `key_ref="single_device",outcome="validated",version="any"} 1`) ||
		!strings.Contains(got, `key_ref="k",outcome="validated",version="1"} 1`) {
		t.Fatalf("key_validations:\n%s", got)
	}
}

// A reload that leaves k with one device takes its series, which named a
// key two devices held, out of the exposition, and counts under single_device.
func TestAReloadThatMakesAKeySingleDeviceDropsItsNamedSeries(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	cfgPath, policyPath := keyRunConfig(t, minimalPolicy, fmt.Sprintf(threeLeaves, ""))
	tacacs := startSplitDaemon(t, cfgPath, &out, 1)
	if !answeredFrom(t, tacacs, "127.0.0.1") {
		t.Fatal("a login was not answered")
	}
	if got := keyScrape(t, &out); !strings.Contains(got, `key_ref="k",outcome="validated",version="1"`) {
		t.Fatalf("control: k is not a label while three devices hold it:\n%s", got)
	}
	// leaf2 and leaf3 move to lab_key, leaving leaf1 alone on k.
	writePolicyFile(t, policyPath, minimalPolicy+"key_groups:\n  - {match: {name: leaf2}, key_ref: lab_key}\n"+
		"  - {match: {name: leaf3}, key_ref: lab_key}\n  - {match: {cidr: 127.0.0.0/8}, key_ref: k}\n")
	deadline := time.Now().Add(15 * time.Second)
	for !strings.Contains(keyScrape(t, &out), `key_ref="single_device"`) {
		if time.Now().After(deadline) {
			t.Fatalf("the reload never made k single-device:\n%s", out.String())
		}
		answeredFrom(t, tacacs, "127.0.0.1")
		time.Sleep(200 * time.Millisecond)
	}
	if got := keyScrape(t, &out); strings.Contains(got, `key_ref="k"`) {
		t.Fatalf("k, now held by one device, is still a label:\n%s", got)
	}
}

// The single-device set is in force before the policy is, so a login the new
// policy admits under a newly single-device key is never counted under its name.
func TestASwapSetsTheSingleDeviceKeyRefsBeforeThePolicyIsInForce(t *testing.T) {
	t.Setenv("PORT49_KEY_RUN", "run-test-secret")
	rig := newReloadRig(t, minimalPolicy)
	rig.r.keys = newLiveKeys(secretref.New(), secretref.Allowance{}.WithDefaults())
	kb, err := rig.r.keys.build(rig.b.Policy.Load())
	if err != nil {
		t.Fatal(err)
	}
	rig.r.keys.put(kb)
	rig.writeInventory(t, withoutGroups) // leaf1 and leaf2: no key_group admits them yet
	rig.pollTwice()
	inForce := rig.b.Policy.Load()
	var label string
	var old bool
	rig.r.keysPut = func() {
		label, _ = rig.r.metrics.KeyLabels("lab_key", 1)
		old = rig.b.Policy.Load() == inForce
	}
	swapTo(t, rig, minimalPolicy+"key_groups:\n  - {match: {name: leaf1}, key_ref: lab_key}\n"+
		"  - {match: {name: leaf2}, key_ref: k}\n")
	if !old || label != "single_device" {
		t.Fatalf("before the policy is in force: old policy in force %v, lab_key labelled %q", old, label)
	}
}
