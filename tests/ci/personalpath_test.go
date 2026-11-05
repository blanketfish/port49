package ci

import (
	"bytes"
	"testing"
)

// No tracked file names the author's home directory: the repository is going public, and a path
// like that is the author's machine in every reader's tree.
func TestNoPersonalPathInTheTree(t *testing.T) {
	// Assembled here, so that this file does not hold it.
	needle := []byte("/home/" + "rwendt")
	for name, b := range trackedText(t) {
		if i := bytes.Index(b, needle); i >= 0 {
			t.Errorf("%s:%d names the author's home directory", name, bytes.Count(b[:i], []byte("\n"))+1)
		}
	}
}
