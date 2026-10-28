// Command mustpass reads `go test -json` on standard input and exits 1 unless
// every named test passed. A test that skipped, failed or never ran is named:
// a skip is how a test that needs root or an ACL goes quiet on a runner that has
// neither, and CI must see it.
//
//	go test -json ./pkg -run '^TestA$' | mustpass -tests TestA
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

func main() {
	fs := flag.NewFlagSet("mustpass", flag.ContinueOnError)
	tests := fs.String("tests", "", "comma-separated test names that must pass")
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	var names []string
	for _, n := range strings.Split(*tests, ",") {
		if n = strings.TrimSpace(n); n != "" {
			names = append(names, n)
		}
	}
	os.Exit(mustPass(os.Stdin, names, os.Stderr))
}

// mustPass is 0 when every name has a pass event and no skip or fail, 1 with
// each offender named, and 2 for no names.
func mustPass(in io.Reader, names []string, stderr io.Writer) int {
	if len(names) == 0 {
		fmt.Fprintln(stderr, "usage: mustpass -tests A,B < go-test-json")
		return 2
	}
	state := map[string]string{}
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var ev struct{ Action, Test string }
		if json.Unmarshal(sc.Bytes(), &ev) != nil || ev.Test == "" {
			continue // the build's own lines, not events
		}
		switch ev.Action {
		case "pass", "skip", "fail":
			state[ev.Test] = ev.Action
		}
	}
	sort.Strings(names)
	bad := false
	for _, name := range names {
		switch state[name] {
		case "pass":
		case "skip":
			fmt.Fprintf(stderr, "mustpass: %s skipped; it must run here\n", name)
			bad = true
		case "fail":
			fmt.Fprintf(stderr, "mustpass: %s failed\n", name)
			bad = true
		default:
			fmt.Fprintf(stderr, "mustpass: %s never ran\n", name)
			bad = true
		}
	}
	if bad {
		return 1
	}
	return 0
}
