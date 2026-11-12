//go:build port49_lab_acct_hold

package acct

import "time"

// labAcctHold is L94 cell C4's hold on every accounting reply (hold.go). This
// file is built only with the tag port49_lab_acct_hold, which only the lab
// harness passes (tests/lab, TestL94).
const labAcctHold = 1500 * time.Millisecond
