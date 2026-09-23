// Command slice-pki writes the vertical slice's lab certificates (plan 3): a
// CA, the broker's server certificate for 127.0.0.1, and one client
// certificate. They protect nothing — the lab broker listens on the loopback —
// and the default directory is git-ignored. TestSliceEndToEnd writes the same
// set for itself; this is for the by-hand runs in tests/lab/README.md.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
)

func main() {
	out := flag.String("out", "tests/lab/logs/slice-pki", "directory to write into")
	email := flag.String("email", "alice@slice.port49.test", "the client certificate's email SAN")
	flag.Parse()
	if err := testpki.WriteLab(*out, *email, time.Now()); err != nil {
		fmt.Fprintln(os.Stderr, "slice-pki:", err)
		os.Exit(1)
	}
	fmt.Printf("slice-pki: wrote %s (valid 24h)\n", *out)
}
