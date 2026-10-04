//go:build !linux

package port49d

// initOwner has nothing to ask off Linux: fence.CheckDir refuses there
// first, since port49 keeps the revocations file on Linux only.
func initOwner(string, string) error { return nil }
