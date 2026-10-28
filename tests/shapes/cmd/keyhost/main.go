// Command keyhost is the Makefile's pre-check for the container and cluster smokes: it exits 1 with
// one line on a host that has a TPM or a Yubico key (shapetest.KeyHostRefusal).
package main

import (
	"fmt"
	"os"

	"github.com/rhwendt/port49/tests/shapes/shapetest"
)

func main() {
	if r := shapetest.KeyHostRefusal("/"); r != "" {
		fmt.Fprintln(os.Stderr, r)
		os.Exit(1)
	}
}
