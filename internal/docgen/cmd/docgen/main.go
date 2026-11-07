// Command docgen writes the generated pages of the documentation site (make docs).
//
// With -seed it appends a DRAFT entry to a descriptions file for every key that has none, and writes
// no page.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/blanketfish/port49/internal/docgen"
)

func main() {
	root := flag.String("root", ".", "the repository root")
	seed := flag.Bool("seed", false, "append a DRAFT entry for every key without a description, and write no page")
	flag.Parse()
	if err := run(*root, *seed); err != nil {
		fmt.Fprintln(os.Stderr, "docgen:", err)
		os.Exit(1)
	}
}

func run(root string, seed bool) error {
	if seed {
		return docgen.Seed(root)
	}
	pages, err := docgen.Pages(root)
	if err != nil {
		return err
	}
	paths := make([]string, 0, len(pages))
	for p := range pages {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		dst := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(dst, []byte(pages[p]), 0o644); err != nil {
			return err
		}
		fmt.Println("wrote", p)
	}
	return nil
}
