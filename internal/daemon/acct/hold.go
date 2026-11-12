//go:build !port49_lab_acct_hold

package acct

import "time"

// labAcctHold is how long Handle holds every accounting reply. It is zero in
// every build but the lab's L94 cell C4 (hold_lab.go, build tag
// port49_lab_acct_hold), which holds it so the reply to a request NX-OS
// pipelines behind an accounting record leaves first (spec §15 L94).
// TestNoReleaseBuildNamesTheAccountingHoldTag keeps the tag out of every
// release build.
const labAcctHold time.Duration = 0
