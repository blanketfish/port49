package port49d

import (
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/decision"
)

// genericRunInventory is writeRunConfig's inventory with srl1 on a platform
// that has no adapter.
const genericRunInventory = `
devices:
  - {name: leaf1, platform: arista_eos, addresses: [127.0.0.1]}
  - {name: srl1, platform: nokia_srlinux, addresses: [127.0.0.2]}
key_groups:
  - {match: {cidr: 127.0.0.0/8}, key_ref: k}
`

// captureStdout points the decision log at a buffer for the test.
func captureStdout(t *testing.T) *syncBuffer {
	t.Helper()
	out := &syncBuffer{}
	o := stdout
	t.Cleanup(func() { stdout = o })
	stdout = out
	return out
}

// waitForGeneric waits until log holds a generic_platform record.
func waitForGeneric(t *testing.T, log *syncBuffer) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(log.String(), `"event":"`+decision.EventGenericPlatform+`"`) {
		if time.Now().After(deadline) {
			t.Fatalf("no generic_platform record: %q", log.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A start writes the generic_platform record, and says the platform's line,
// for a device with no adapter: without a swap to carry it (spec §5.7, §8).
func TestStartWritesTheGenericPlatformRecord(t *testing.T) {
	out := captureStderr(t)
	log := captureStdout(t)
	cfg := writeRunConfigWith(t, brokerConfig(t, minimalPolicy).Broker, genericRunInventory, "")
	_, stop := startDaemon(t, cfg, out)
	defer stop()
	waitForGeneric(t, log)
	recs := genericRecords(t, log.String())
	if len(recs) != 1 {
		t.Fatalf("%d records: %s", len(recs), log.String())
	}
	dev, _ := recs[0]["device"].(map[string]any)
	if recs[0]["reason"] != string(decision.PlatformUnknown) || dev["name"] != "srl1" || dev["platform"] != "nokia_srlinux" {
		t.Fatalf("record: %v", recs[0])
	}
	if !strings.Contains(out.String(), "port49d: policy: platform nokia_srlinux has no adapter: 1 device(s) served by the generic adapter") {
		t.Fatalf("stderr: %s", out.String())
	}
}

// port49-broker writes none, at start or at a swap: a split deployment gets
// one record per port49d, not one per process.
func TestPort49BrokerWritesNoGenericPlatformRecord(t *testing.T) {
	var out syncBuffer
	e, o := stderr, stdout
	log := &syncBuffer{}
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, log
	f := splitFleet(t)
	writePolicyFile(t, f.inventory, genericRunInventory)
	startBroker(t, f.broker, &out, 1)
	// A swap after the start: another device joins the generic platform.
	writePolicyFile(t, f.inventory, strings.Replace(genericRunInventory, "\nkey_groups:",
		"\n  - {name: srl2, platform: nokia_srlinux, addresses: [127.0.0.3]}\nkey_groups:", 1))
	waitFor(t, &out, "inventory reloaded (inventory file changed)")
	if strings.Contains(log.String(), decision.EventGenericPlatform) || strings.Contains(out.String(), "platform_unknown") {
		t.Fatalf("port49-broker recorded: %s / %s", log.String(), out.String())
	}
}
