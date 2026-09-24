//go:build !linux

package main

import "errors"

// readPolicyFile refuses on every system but Linux: the check that nobody
// else could have written the policy is made on descriptors (openat, O_PATH)
// that port49d uses on Linux alone, and a policy file that cannot be checked
// is not loaded. port49d builds here so the rest of it can be worked on.
func readPolicyFile(string) ([]byte, error) {
	return nil, errors.New("port49d reads broker.policy_file on Linux only: the check of who could have written " +
		"it is Linux's")
}
