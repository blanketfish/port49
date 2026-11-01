package authen

import "github.com/blanketfish/port49/internal/username"

// Canonical is username.Canonical. The name stays exported here because plan 1's
// handler, its tests and package author all call it by this name; the body moved
// so internal/token can enforce the same rule at mint without importing this
// package, which from Task 7 on imports internal/token itself.
func Canonical(u string) string { return username.Canonical(u) }
