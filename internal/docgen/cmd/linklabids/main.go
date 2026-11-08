// Command linklabids links every bare lab ID on the hand-written pages of the documentation site, and in the
// regions of the READMEs those pages include, to its section of the lab register page.
//
//	go run ./internal/docgen/cmd/linklabids
//
// It is deterministic and idempotent: a second run changes nothing. Generated pages are not its business;
// their generators link their own IDs (make docs). An ID the spec's section 15 does not hold is an error
// and nothing is written. tests/ci fails a bare ID that gets past it.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/blanketfish/port49/internal/docgen"
)

func main() {
	root := flag.String("root", ".", "the repository root")
	flag.Parse()
	if err := run(*root); err != nil {
		fmt.Fprintln(os.Stderr, "linklabids:", err)
		os.Exit(1)
	}
}

func run(root string) error {
	spec, err := os.ReadFile(filepath.Join(root, "docs", "design", "2026-08-23-policy-engine-spec.md"))
	if err != nil {
		return err
	}
	reg, err := docgen.LabRegister(spec)
	if err != nil {
		return err
	}
	changed, err := docgen.LinkLabIDsInTree(root, reg)
	if err != nil {
		return err
	}
	for _, f := range changed {
		fmt.Println("linked", f)
	}
	return nil
}
