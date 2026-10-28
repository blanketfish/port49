// Command versioncheck exits 1 when the published artifacts' versions disagree,
// or with -tag vX.Y.Z when any of them is not that tag. Run from the repository
// root.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/rhwendt/port49/tests/ci/versions"
)

func main() {
	fs := flag.NewFlagSet("versioncheck", flag.ContinueOnError)
	tag := fs.String("tag", "", "a release tag, as v0.1.0")
	root := fs.String("root", ".", "the repository root")
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	v, err := versions.Read(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "versioncheck:", err)
		os.Exit(1)
	}
	if found := versions.Check(v, *tag); len(found) > 0 {
		fmt.Fprintln(os.Stderr, "versioncheck: "+strings.Join(found, "\nversioncheck: "))
		os.Exit(1)
	}
	fmt.Printf("versioncheck: pypi %s, galaxy %s, chart %q appVersion %q\n", v.PyPI, v.Galaxy, v.Chart, v.ChartApp)
}
