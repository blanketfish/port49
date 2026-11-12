//go:build port49_lab_acct_hold

package acct

import (
	"os"
	"time"
)

// labAcctHold is L94 cell C4's hold on an accounting reply (hold.go). This
// file is built only with the tag port49_lab_acct_hold, which only the lab
// harness passes (tests/lab, TestL94).
const labAcctHold = 1500 * time.Millisecond

// labAcctHoldFileEnv names the control file the hold build checks on every
// accounting request. The harness sets it on c4's port49d alone, and creates
// the file only from the cell's clean point: the device's own accounting
// before it (a backlog drained at login) is answered unheld.
const labAcctHoldFileEnv = "PORT49_LAB_ACCT_HOLD_FILE"

// labHoldFile is the control file's path, read once at start.
var labHoldFile = os.Getenv(labAcctHoldFileEnv)

// labHoldOn reports whether this request's reply is held.
func labHoldOn() bool { return labHoldOnAt(labHoldFile) }

// labHoldOnAt holds a reply only while path exists, and appends a line to it
// for each reply it holds, so the harness can tell a record answered without
// the hold. It never creates the file: opened without O_CREATE, an absent
// file is no hold.
func labHoldOnAt(path string) bool {
	if path == "" {
		return false
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	_, err = f.WriteString("held\n")
	return err == nil
}
