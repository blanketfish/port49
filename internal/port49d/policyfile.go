package port49d

import "github.com/rhwendt/port49/internal/fence"

// maxPolicySize bounds the policy file's read: a policy file is kilobytes,
// and a link aimed at a multi-gigabyte file must not be read at every poll.
const maxPolicySize = 1 << 20

// maxInventorySize bounds the inventory file's read: a 10,000-device
// inventory is a few megabytes.
const maxInventorySize = 64 << 20

// readPolicyFile reads broker.policy_file behind the write fence (spec
// §5.1.3; fence.Read).
func readPolicyFile(path string) ([]byte, error) {
	return fence.Read(path, maxPolicySize, "policy file")
}

// readInventoryFile reads inventory_file behind the same fence: with a broker
// it is reloaded live and decides scope membership, the addresses a mint
// hands out and key pins (spec §10; plan 6a C2).
func readInventoryFile(path string) ([]byte, error) {
	return fence.Read(path, maxInventorySize, "inventory file")
}
