//go:build !port49_lab_acct_hold

package acct

import "testing"

// Every build but L94 cell C4's holds no accounting reply (hold.go).
func TestTheDefaultBuildHoldsNoAccountingReply(t *testing.T) {
	if labAcctHold != 0 {
		t.Fatalf("the default build holds every accounting reply %s: only the lab's C4 build may", labAcctHold)
	}
	if labHoldOn() {
		t.Fatal("the default build's hold is on: only the lab's C4 build checks a control file")
	}
}
