//go:build !linux

package l60

import "os"

// flushTTYInput discards nothing off Linux: the harness runs on the SER8.
func flushTTYInput(*os.File) {}
