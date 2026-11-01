// Command compose-pki writes deploy/compose/local/ for a trial of the
// compose stack (plan 7f, Task 1): etcd's CA, members and users, the
// broker's PKI with client certificates, the device key and the two sealing key
// files (no env file). It protects nothing real, is valid 24h, and the directory is
// git-ignored. A deployment brings its own PKI (deploy/compose/README.md).
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/blanketfish/port49/internal/testpki"
)

func main() {
	out := flag.String("out", "deploy/compose/local", "directory to write into")
	email := flag.String("email", "alice@example.com", "the client certificate's email SAN")
	flag.Parse()
	if err := testpki.WriteCompose(*out, *email, time.Now()); err != nil {
		fmt.Fprintln(os.Stderr, "compose-pki:", err)
		os.Exit(1)
	}
	fmt.Printf("compose-pki: wrote %s (valid 24h)\n", *out)
}
