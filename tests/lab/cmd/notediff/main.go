// Command notediff compares a results note a lab rerun rewrote with the copy at
// HEAD. It masks only what every rerun changes, and compares the numbers on
// the remaining lines with a tolerance, so the lines it prints are changed
// observations (plan 11b). It reports; the lab is the truth.
package main

import (
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var (
	volatileHeader = regexp.MustCompile(`^- \*\*(Date measured|Run|Capture):\*\*`)
	volatile       = []struct {
		re  *regexp.Regexp
		rep string
	}{
		{regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z`), "<ts>"},
		{regexp.MustCompile(`\balice\d{2}\b|\bl73u\d{2}\b|\bqual\d{2}\b`), "<user>"},
		{regexp.MustCompile(`\b(device_)?port \d{4,5}\b`), "port <n>"},
		{regexp.MustCompile(`\b\d+ packets\b`), "<n> packets"},
	}
	// Masked by kind, never by length alone: a long snake_case reason, a cipher
	// suite or an image tag is an observation. Pure hex (a digest, a key id) of
	// 16 or more characters is volatile. A base64/base64url run of 24 or more
	// characters is volatile only when isToken says it is random (RE2 has no lookahead,
	// so the kind is checked in maskLong). A tag such as
	// "vjunos-router:23.4R2-S2.1" stays whole: ':' and '.' split it into
	// pieces too short to qualify.
	hexRun    = regexp.MustCompile(`\b[0-9a-fA-F]{16,}\b`)
	base64Run = regexp.MustCompile(`[A-Za-z0-9_+/=-]{24,}`)
	// group 1 the value, group 2 a decimal part, group 3 a unit (kept in the skeleton).
	number = regexp.MustCompile(`(\d+(\.\d+)?)( ?(?:ms|min|s)\b)?`)
	// A range whose unit follows its second number ("81–85ms", "100-200 ms"):
	// the unit is copied onto the first, so both compare as durations.
	unitRange = regexp.MustCompile(`(\d+(?:\.\d+)?)(\s?[–-]\s?)(\d+(?:\.\d+)?)( ?(?:ms|min|s)\b)`)
)

// isToken reports whether a base64-class run looks like random data: it holds
// a digit, a lowercase and an uppercase letter. Random base64 of 24 or more
// characters lacks one of the three with probability about 1e-6, while an
// upper-case constant such as TLS_CHACHA20_POLY1305_SHA256 or a lower-case
// tag piece does not qualify.
func isToken(m string) bool {
	return strings.ContainsAny(m, "0123456789") && strings.ContainsAny(m, "abcdefghijklmnopqrstuvwxyz") && strings.ContainsAny(m, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
}

func maskLong(l string) string {
	l = hexRun.ReplaceAllString(l, "<LONG>")
	return base64Run.ReplaceAllStringFunc(l, func(m string) string {
		if isToken(m) {
			return "<LONG>"
		}
		return m
	})
}

func normalize(note string) []string {
	var out []string
	for _, l := range strings.Split(note, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if m := volatileHeader.FindString(l); m != "" {
			out = append(out, m+" <volatile>")
			continue
		}
		for _, v := range volatile {
			l = v.re.ReplaceAllString(l, v.rep)
		}
		out = append(out, maskLong(l))
	}
	return out
}

// num is one number on a line. A duration (a number followed by ms, s or min)
// is compared with the tolerance; every other number (a count, an id, a byte
// length, a version part) is compared exactly (re-review I-A).
type num struct {
	v        float64
	duration bool
}

// skeleton is a line with its numbers replaced, so two lines that differ only
// in their numbers pair up, and their numbers are then compared.
func skeleton(l string) (string, []num) {
	var nums []num
	l = unitRange.ReplaceAllString(l, "$1$4$2$3$4")
	s := number.ReplaceAllStringFunc(l, func(m string) string {
		sub := number.FindStringSubmatch(m)
		f, _ := strconv.ParseFloat(sub[1], 64)
		// A duration only when a unit follows: a bare decimal is a version or
		// an address part (26.7 vs 26.8), and compares exactly.
		nums = append(nums, num{v: f, duration: sub[3] != ""})
		return "#" + strings.TrimSpace(sub[3])
	})
	return s, nums
}

func within(a, b []num, tol float64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].v == b[i].v {
			continue
		}
		if !a[i].duration || !b[i].duration {
			return false
		}
		if m := math.Max(math.Abs(a[i].v), math.Abs(b[i].v)); m == 0 || math.Abs(a[i].v-b[i].v)/m > tol {
			return false
		}
	}
	return true
}

func changed(old, new []string, tol float64) (removed, added []string) {
	type entry struct {
		line string
		nums []num
		used bool
	}
	pool := map[string][]*entry{}
	var all []*entry
	for _, l := range old {
		s, n := skeleton(l)
		e := &entry{line: l, nums: n}
		pool[s] = append(pool[s], e)
		all = append(all, e)
	}
	for _, l := range new {
		s, n := skeleton(l)
		matched := false
		for _, o := range pool[s] {
			if !o.used && within(o.nums, n, tol) {
				o.used = true
				matched = true
				break
			}
		}
		if !matched {
			added = append(added, l)
		}
	}
	for _, e := range all { // file order
		if !e.used {
			removed = append(removed, e.line)
		}
	}
	return removed, added
}

// compare reports on one note and returns the exit code. dir is where git
// runs ("" for the current directory); a relative note path is relative to the
// repository root, which is how the runner names notes.
func compare(dir, note string, tol float64, fail bool, out, errw io.Writer) int {
	rootOut, err := gitIn(dir, "rev-parse", "--show-toplevel")
	if err != nil {
		fmt.Fprintf(errw, "notediff: %v\n", err)
		return 2
	}
	root := strings.TrimSpace(string(rootOut))
	path := note
	if !filepath.IsAbs(path) {
		path = filepath.Join(root, note)
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		fmt.Fprintf(errw, "notediff: %v\n", err)
		return 2
	}
	rel = filepath.ToSlash(rel)
	listed, err := gitIn(root, "ls-tree", "--name-only", "HEAD", "--", rel)
	if err != nil {
		fmt.Fprintf(errw, "notediff: %v\n", err)
		return 2
	}
	if len(strings.TrimSpace(string(listed))) == 0 {
		fmt.Fprintf(out, "notediff: %s: new (not at HEAD)\n", note)
		return 0
	}
	head, err := gitIn(root, "show", "HEAD:"+rel)
	if err != nil {
		fmt.Fprintf(errw, "notediff: %v\n", err)
		return 2
	}
	now, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(errw, err)
		return 2
	}
	r, a := changed(normalize(string(head)), normalize(string(now)), tol)
	if len(r) == 0 && len(a) == 0 {
		fmt.Fprintf(out, "notediff: %s: unchanged\n", note)
		return 0
	}
	fmt.Fprintf(out, "notediff: %s: %d observation line(s) changed\n", note, len(r)+len(a))
	for _, l := range r {
		fmt.Fprintln(out, "  - "+l)
	}
	for _, l := range a {
		fmt.Fprintln(out, "  + "+l)
	}
	if fail {
		return 1
	}
	return 0
}

func gitIn(dir string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w", args[0], err)
	}
	return out, nil
}

func main() {
	note := flag.String("note", "", "a results note path (relative to the repository root)")
	tol := flag.Float64("tolerance", 0.2, "the relative change in a number that counts as an observation")
	fail := flag.Bool("fail-on-change", false, "exit 1 when an observation changed (CI)")
	flag.Parse()
	os.Exit(compare("", *note, *tol, *fail, os.Stdout, os.Stderr))
}
