//go:build lab

package lab

import (
	"fmt"
	"regexp"
	"strings"
)

// labLine is one device line of the lab inventory. The file pads names to
// line up the columns ({name: srx1,  platform: ...}), so the separators take
// any run of spaces (pre-flight M9).
var labLine = regexp.MustCompile(`(?m)^  - \{name: ([^,]+),\s+platform:\s+([a-z_]+),.*\n`)

// labSource is the lab inventory's devices, key groups dropped — the service
// assigns no key (spec §13, decision 30), and the lab's group is in the run's
// policy — padded with ten dummy devices, so taking one lab device out of
// service is 1 of 15, under the default 10% bound on both sides.
func labSource(inventoryLab string) string {
	body, _, _ := strings.Cut(inventoryLab, "key_groups:")
	for i := 1; i <= 10; i++ {
		body += fmt.Sprintf("  - {name: dummy-%02d, platform: arista_eos, addresses: [10.99.0.%d]}\n", i, 100+i)
	}
	return body
}

// labLineOf is node's line in the lab inventory, and labPlatformOf its
// platform: the inventory's (juniper_junos), not the results note's name for
// the image (conflict scan F6). Both are "" for a node the inventory lacks.
func labLineOf(src, node string) string {
	for _, m := range labLine.FindAllStringSubmatch(src, -1) {
		if m[1] == node {
			return m[0]
		}
	}
	return ""
}

func labPlatformOf(src, node string) string {
	if m := labLine.FindStringSubmatch(labLineOf(src, node)); m != nil {
		return m[2]
	}
	return ""
}

// l29Edit is one reload phase's change to src for node.
func l29Edit(src, node, phase string) (string, error) {
	line, platform := labLineOf(src, node), labPlatformOf(src, node)
	if line == "" {
		return "", fmt.Errorf("the lab inventory has no device %s", node)
	}
	var edited string
	switch phase {
	case "removed":
		edited = ""
	case "renamed":
		edited = strings.Replace(line, "{name: "+node+",", "{name: "+node+"-b,", 1)
	case "replatformed":
		other := "arista_eos"
		if platform == "arista_eos" {
			other = "cisco_nxos"
		}
		edited = regexp.MustCompile(`platform:\s+`+platform+`,`).ReplaceAllString(line, "platform: "+other+",")
	case "refused":
		edited = strings.Replace(line, "]}", "], transport: tls}", 1)
	default:
		return "", fmt.Errorf("no source edit for phase %s", phase)
	}
	if edited == line {
		return "", fmt.Errorf("phase %s changed nothing on %s's line", phase, node)
	}
	return strings.Replace(src, line, edited, 1), nil
}

// l29Pin is the rekeyed phase's edit to the policy: a reviewed pin (Task 3a)
// of node onto lab_key2, the rotation key, which the device does not hold.
// key_groups: is the policy's last block, so the item is appended.
func l29Pin(policy, node string) string {
	return policy + "  - {match: {name: " + node + "}, key_ref: lab_key2}\n"
}

// quarantineDummies is the quarantine-through-a-sync source before the sync
// under test: two dummy devices, one of which that sync changes beside the
// device it introduces, so "the rest of the sync applies" is observable.
const quarantineDummies = "devices:\n" +
	"  - {name: dummy-eos, platform: arista_eos, addresses: [10.99.0.11]}\n" +
	"  - {name: dummy-xe, platform: cisco_iosxe, addresses: [10.99.0.41], attributes: {site: dc1}}\n"

// quarantineSource is the source of the sync that introduces node: the
// dummies, dummy-xe's site changed, and node's line from the lab inventory.
func quarantineSource(inventoryLab, node string) (string, error) {
	line := labLineOf(inventoryLab, node)
	if line == "" {
		return "", fmt.Errorf("the lab inventory has no device %s", node)
	}
	return strings.Replace(quarantineDummies, "site: dc1", "site: dc2", 1) + line, nil
}
