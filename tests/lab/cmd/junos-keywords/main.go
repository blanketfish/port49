// Command junos-keywords merges the lab's per-image Junos keyword captures,
// tests/lab/results/L26-keywords-<image>.yaml, into the tree a platform set
// ships (spec §13 decision 27; §15 L26): what every image proves, a keyword
// on one image only left out, an argument on any image kept. Each -overlay,
// tests/lab/results/L26b-keywords-<image>.yaml, is first laid over the one
// capture whose sha256 its first line names (platform.OverlayKeywords); an
// overlay that names none of them, or a capture two overlays name, is
// refused. It writes the tree to stdout, in the form platform.ParseKeywords
// reads.
//
//	go run ./tests/lab/cmd/junos-keywords \
//	  -overlay tests/lab/results/L26b-keywords-juniper_vjunos-router.yaml \
//	  -overlay tests/lab/results/L26b-keywords-juniper_vsrx.yaml \
//	  tests/lab/results/L26-keywords-juniper_vjunos-router.yaml \
//	  tests/lab/results/L26-keywords-juniper_vsrx.yaml \
//	  > platforms/keywords/1.1.0/juniper_junos.yaml
package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/rhwendt/port49/internal/platform"
)

type files []string

func (f *files) String() string     { return strings.Join(*f, ",") }
func (f *files) Set(v string) error { *f = append(*f, v); return nil }

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "junos-keywords:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fl := flag.NewFlagSet("junos-keywords", flag.ContinueOnError)
	var overlays files
	fl.Var(&overlays, "overlay", "an L26b overlay, laid over the capture its sha256 names (repeatable)")
	if err := fl.Parse(args); err != nil {
		return err
	}
	captures := fl.Args()
	if len(captures) < 2 {
		return fmt.Errorf("give every image's capture, at least two: a keyword one image lacks is not proven")
	}
	raws := make([][]byte, len(captures))
	byHash := map[string]int{}
	for i, f := range captures {
		raw, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		raws[i] = raw
		byHash[fmt.Sprintf("%x", sha256.Sum256(raw))] = i
	}
	laid := make([][]byte, len(captures))
	for _, f := range overlays {
		raw, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		i, ok := -1, false
		for h, j := range byHash {
			if first, _, _ := strings.Cut(string(raw), "\n"); strings.HasSuffix(first, " sha256 "+h) {
				i, ok = j, true
			}
		}
		if !ok {
			return fmt.Errorf("%s: computed against none of the captures given: recompute it", f)
		}
		if laid[i] != nil {
			return fmt.Errorf("%s: a second overlay for %s", f, captures[i])
		}
		laid[i] = raw
	}
	var trees []*platform.Keywords
	name := ""
	for i, f := range captures {
		n, k, err := platform.ParseKeywords(raws[i])
		if err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		if laid[i] != nil {
			if k, err = platform.OverlayKeywords(raws[i], laid[i]); err != nil {
				return fmt.Errorf("%s: %w", f, err)
			}
		}
		if name != "" && n != name {
			return fmt.Errorf("%s names platform %q, and %s %q", f, n, captures[0], name)
		}
		name = n
		trees = append(trees, k)
	}
	out := platform.MarshalKeywords(name, platform.MergeKeywords(trees...))
	if _, k, err := platform.ParseKeywords(out); err != nil || k.Len() == 0 {
		return fmt.Errorf("the merged tree does not load (%v), or is empty", err)
	}
	_, err := os.Stdout.Write(out)
	return err
}
