//go:build race

package engine

// raceBuild is whether the race detector is on, which slows the engine too
// much for a test that times it.
const raceBuild = true
