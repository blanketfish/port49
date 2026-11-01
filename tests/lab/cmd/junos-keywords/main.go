// Command junos-keywords merges the lab's Junos keyword captures,
// tests/lab/results/L26-keywords-<image>.yaml, into the tree a platform set
// ships (spec §13 decision 27; §15 L26): what every run on every image
// proves, a keyword one run lacks left out, an argument any run takes kept.
// An image measured more than once keeps each earlier run beside the latest,
// as L26-keywords-<image>.run<N>.yaml, and every run is one more capture to
// intersect: a word is a keyword only where each run proves it, and unproven
// fails closed. So every run of an image must be given: the tool refuses an
// image whose latest run is not given, or with a run file beside a given
// capture that is not, an image committed beside a given capture and not
// given at all, and two captures with the same content.
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
	"regexp"
	"slices"
	"strings"

	"github.com/blanketfish/port49/internal/platform"
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

var earlierRun = regexp.MustCompile(`^(.+)\.run[0-9]+$`)

// imageOf is the image a capture file measures, and whether it is the
// image's latest run: L26-keywords-<image>.yaml is, and
// L26-keywords-<image>.run<N>.yaml is an earlier one. An image name holds no
// dot, so a file is never read as an earlier run of a shorter image.
func imageOf(file string) (string, bool, error) {
	base := filepath.Base(file)
	rest, ok := strings.CutPrefix(base, "L26-keywords-")
	if !ok || !strings.HasSuffix(rest, ".yaml") {
		return "", false, fmt.Errorf("%s: not an L26-keywords-<image>[.run<N>].yaml capture", file)
	}
	image, earlier := strings.TrimSuffix(rest, ".yaml"), false
	if m := earlierRun.FindStringSubmatch(image); m != nil {
		image, earlier = m[1], true
	}
	if image == "" || strings.Contains(image, ".") {
		return "", false, fmt.Errorf("%s: not an L26-keywords-<image>[.run<N>].yaml capture", file)
	}
	return image, !earlier, nil
}

// runsBeside is every capture of image in dir: its latest run and each
// earlier one, and any other file named as one of its runs, which imageOf
// then refuses.
func runsBeside(dir, image string) ([]string, error) {
	return filepath.Glob(filepath.Join(dir, "L26-keywords-"+image+".*yaml"))
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
		h := fmt.Sprintf("%x", sha256.Sum256(raw))
		if j, dup := byHash[h]; dup {
			return fmt.Errorf("%s: the same capture as %s", f, captures[j])
		}
		byHash[h] = i
	}
	if len(images) < 2 {
		return fmt.Errorf("give every image's captures, at least two images: a keyword one image lacks is not proven")
	}
	// A run left off would prove what it does not: every run of an image
	// beside a capture given must be given too, and the latest among them.
	given := map[string]bool{}
	for _, f := range captures {
		abs, err := filepath.Abs(f)
		if err != nil {
			return err
		}
		given[abs] = true
	}
	// So would an image left off: every image committed beside a capture
	// given is one more tree to intersect (kw-merge review M4).
	dirs := map[string]bool{}
	for _, f := range captures {
		dirs[filepath.Dir(f)] = true
	}
	for dir := range dirs {
		committed, err := filepath.Glob(filepath.Join(dir, "L26-keywords-*.yaml"))
		if err != nil {
			return err
		}
		for _, f := range committed {
			image, _, err := imageOf(f)
			if err != nil {
				return err
			}
			if !slices.Contains(images, image) {
				return fmt.Errorf("%s: image %s is committed beside the captures and not given: give every "+
					"image, or the merge proves what it lacks", f, image)
			}
		}
	}
	for _, image := range images {
		if !hasLatest[image] {
			return fmt.Errorf("%s: no latest run, L26-keywords-%s.yaml, given", image, image)
		}
		for _, i := range runs[image] {
			beside, err := runsBeside(filepath.Dir(captures[i]), image)
			if err != nil {
				return err
			}
			for _, f := range beside {
				if _, _, err := imageOf(f); err != nil {
					return err
				}
				abs, err := filepath.Abs(f)
				if err != nil {
					return err
				}
				if !given[abs] {
					return fmt.Errorf("%s: a run of %s not given: give every run, or the merge proves what it lacks", f, image)
				}
			}
		}
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
