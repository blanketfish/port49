// Command oldroot is helm's --post-renderer for the fsGroup cell's RED run (plan 12b, Task 11):
// it reads the rendered manifests on stdin and writes them with the first design's volume root.
// Test-only; the chart ships no post-renderer.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/rhwendt/port49/tests/kind/kindtest"
)

func main() {
	in, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "oldroot:", err)
		os.Exit(1)
	}
	out, err := kindtest.OldRoot(in)
	if err != nil {
		fmt.Fprintln(os.Stderr, "oldroot:", err)
		os.Exit(1)
	}
	os.Stdout.Write(out)
}
