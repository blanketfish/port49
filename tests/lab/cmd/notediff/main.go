// Command notediff compares a results note a lab rerun rewrote with the copy at
// HEAD. It masks only what every rerun changes, and compares the numbers on
// the remaining lines with a tolerance, so the lines it prints are changed
// observations (plan 11b). It reports; the lab is the truth.
package main

import (
	"flag"
	"fmt"
	"math"
	"os"
	"os/exec"
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
		{regexp.MustCompile(`[A-Za-z0-9_+/=.-]{24,}`), "<LONG>"},
	}
	// group 1 the value, group 2 a decimal part, group 3 a unit (kept in the skeleton).
	number = regexp.MustCompile(`(\d+(\.\d+)?)( ?(?:ms|min|s)\b)?`)
	// A range whose unit follows its second number ("81–85ms", "100-200 ms"):
	// the unit is copied onto the first, so both compare as durations.
	unitRange = regexp.MustCompile(`(\d+(?:\.\d+)?)(\s?[–-]\s?)(\d+(?:\.\d+)?)( ?(?:ms|min|s)\b)`)
)

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
		out = append(out, l)
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
		return "#" + sub[3]
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
	pool := map[string][][]num{}
	lines := map[string][]string{}
	for _, l := range old {
		s, n := skeleton(l)
		pool[s] = append(pool[s], n)
		lines[s] = append(lines[s], l)
	}
	for _, l := range new {
		s, n := skeleton(l)
		hit := -1
		for i, o := range pool[s] {
			if within(o, n, tol) {
				hit = i
				break
			}
		}
		if hit < 0 {
			added = append(added, l)
			continue
		}
		pool[s] = append(pool[s][:hit], pool[s][hit+1:]...)
		lines[s] = append(lines[s][:hit], lines[s][hit+1:]...)
	}
	for _, ls := range lines {
		removed = append(removed, ls...)
	}
	return removed, added
}

func main() {
	note := flag.String("note", "", "a results note path")
	tol := flag.Float64("tolerance", 0.2, "the relative change in a number that counts as an observation")
	fail := flag.Bool("fail-on-change", false, "exit 1 when an observation changed (CI)")
	flag.Parse()
	head, err := exec.Command("git", "show", "HEAD:"+*note).Output()
	if err != nil {
		fmt.Printf("notediff: %s: new (not at HEAD)\n", *note)
		return
	}
	now, err := os.ReadFile(*note)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	r, a := changed(normalize(string(head)), normalize(string(now)), *tol)
	if len(r) == 0 && len(a) == 0 {
		fmt.Printf("notediff: %s: unchanged\n", *note)
		return
	}
	fmt.Printf("notediff: %s: %d observation line(s) changed\n", *note, len(r)+len(a))
	for _, l := range r {
		fmt.Println("  - " + l)
	}
	for _, l := range a {
		fmt.Println("  + " + l)
	}
	if *fail {
		os.Exit(1)
	}
}
