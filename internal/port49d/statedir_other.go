//go:build !linux

package port49d

import "errors"

// The files port49-broker keeps in broker.state_dir (statedir_linux.go).
const (
	stateMarksFile   = "marks.json"
	stateWitnessFile = "witness.json"
)

// ownStateDir refuses off Linux: who owns broker.state_dir is asked of
// the file's owner uid, which port49 reads on Linux only, as the policy
// file's fence does.
func ownStateDir(string) error {
	return errors.New("port49-broker keeps broker.state_dir on Linux only: the check of who owns it is Linux's")
}

// writeOwnerOnly refuses off Linux, as ownStateDir does.
func writeOwnerOnly(string, []byte) error { return ownStateDir("") }

// createOwnerOnly refuses off Linux, as ownStateDir does.
func createOwnerOnly(string, []byte) error { return ownStateDir("") }

// readOwnerOnly refuses off Linux, as ownStateDir does.
func readOwnerOnly(string) ([]byte, error) { return nil, ownStateDir("") }
