// Command junos-keywords merges the lab's Junos keyword captures,
// tests/lab/results/L26-keywords-<image>.yaml, into the tree a platform set
// ships (spec §13 decision 27; §15 L26): what every run on every image
// proves, a keyword one run lacks left out, an argument any run takes kept.
// An image measured more than once keeps each earlier run beside the latest,
// as L26-keywords-<image>.<run>.yaml, and every run is one more capture to
// intersect: a word is a keyword only where each run proves it, and unproven
// fails closed.
//
// Each -overlay, tests/lab/results/L26b-keywords-<image>.yaml, pins the
// latest run of its image, L26-keywords-<image>.yaml, by the sha256 its first
// line names, and is laid over every run of that image
// (platform.OverlayRuns): at the nodes it lists its words join each run's
// and its argument replaces each run's, where each run offers the words the
// pinned one does. An overlay that names none of the captures, names an
// earlier run, or a second overlay for one image, is refused. It writes the
// tree to stdout, in the form platform.ParseKeywords reads.
//
//	go run ./tests/lab/cmd/junos-keywords \
//	  -overlay tests/lab/results/L26b-keywords-juniper_vjunos-router.yaml \
//	  -overlay tests/lab/results/L26b-keywords-juniper_vsrx.yaml \
//	  tests/lab/results/L26-keywords-juniper_vjunos-router.yaml \
//	  tests/lab/results/L26-keywords-juniper_vsrx.yaml \
//	  tests/lab/results/L26-keywords-juniper_vsrx.run1.yaml \
//	  > platforms/keywords/1.1.0/juniper_junos.yaml
package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
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

// imageOf is the image a capture file measures, and whether it is the
// image's latest run: L26-keywords-<image>.yaml is, and
// L26-keywords-<image>.<run>.yaml is an earlier one.
func imageOf(file string) (string, bool, error) {
	base := filepath.Base(file)
	rest, ok := strings.CutPrefix(base, "L26-keywords-")
	if !ok || !strings.HasSuffix(rest, ".yaml") {
		return "", false, fmt.Errorf("%s: not an L26-keywords-<image>[.<run>].yaml capture", file)
	}
	image, run, earlier := strings.Cut(strings.TrimSuffix(rest, ".yaml"), ".")
	if image == "" || (earlier && run == "") {
		return "", false, fmt.Errorf("%s: not an L26-keywords-<image>[.<run>].yaml capture", file)
	}
	return image, !earlier, nil
}

func run(args []string) error {
	fl := flag.NewFlagSet("junos-keywords", flag.ContinueOnError)
	var overlays files
	fl.Var(&overlays, "overlay", "an L26b overlay, laid over every run of the image whose latest capture its sha256 names (repeatable)")
	if err := fl.Parse(args); err != nil {
		return err
	}
	captures := fl.Args()
	var images []string        // in the order given
	runs := map[string][]int{} // image → its captures, the latest first
	hasLatest := map[string]bool{}
	raws := make([][]byte, len(captures))
	byHash := map[string]int{}
	for i, f := range captures {
		image, latest, err := imageOf(f)
		if err != nil {
			return err
		}
		if !slices.Contains(images, image) {
			images = append(images, image)
		}
		if latest {
			if hasLatest[image] {
				return fmt.Errorf("%s: a second latest run of %s", f, image)
			}
			hasLatest[image] = true
			runs[image] = slices.Insert(runs[image], 0, i)
		} else {
			runs[image] = append(runs[image], i)
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		raws[i] = raw
		byHash[fmt.Sprintf("%x", sha256.Sum256(raw))] = i
	}
	if len(images) < 2 {
		return fmt.Errorf("give every image's captures, at least two images: a keyword one image lacks is not proven")
	}
	laid := map[string][]byte{}
	for _, f := range overlays {
		raw, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		i := -1
		for h, j := range byHash {
			if first, _, _ := strings.Cut(string(raw), "\n"); strings.HasSuffix(first, " sha256 "+h) {
				i = j
			}
		}
		if i < 0 {
			return fmt.Errorf("%s: computed against none of the captures given: recompute it", f)
		}
		image, latest, _ := imageOf(captures[i])
		if !latest {
			return fmt.Errorf("%s: computed against %s, an earlier run of %s: an overlay pins the latest", f,
				captures[i], image)
		}
		if laid[image] != nil {
			return fmt.Errorf("%s: a second overlay for %s", f, image)
		}
		laid[image] = raw
	}
	var trees []*platform.Keywords
	name := ""
	for _, image := range images {
		var ks []*platform.Keywords
		if overlay := laid[image]; overlay != nil {
			rs := make([][]byte, len(runs[image]))
			for j, i := range runs[image] {
				rs[j] = raws[i]
			}
			var err error
			if ks, err = platform.OverlayRuns(overlay, rs...); err != nil {
				return fmt.Errorf("%s: %w", image, err)
			}
		} else {
			for _, i := range runs[image] {
				_, k, err := platform.ParseKeywords(raws[i])
				if err != nil {
					return fmt.Errorf("%s: %w", captures[i], err)
				}
				ks = append(ks, k)
			}
		}
		for _, i := range runs[image] {
			n, _, err := platform.ParseKeywords(raws[i])
			if err != nil {
				return fmt.Errorf("%s: %w", captures[i], err)
			}
			if name != "" && n != name {
				return fmt.Errorf("%s names platform %q, and %s %q", captures[i], n, captures[0], name)
			}
			name = n
		}
		trees = append(trees, ks...)
	}
	out := platform.MarshalKeywords(name, platform.MergeKeywords(trees...))
	if _, k, err := platform.ParseKeywords(out); err != nil || k.Len() == 0 {
		return fmt.Errorf("the merged tree does not load (%v), or is empty", err)
	}
	_, err := os.Stdout.Write(out)
	return err
}
