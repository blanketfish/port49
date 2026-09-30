//go:build race

package policy

// raceBuild is whether the race detector is on, which slows the load too much
// for a test that times it.
const raceBuild = true
