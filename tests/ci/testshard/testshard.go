// Package testshard splits one package's tests across CI jobs and proves the
// split loses none. A shard is a regex for go test -run; a test that lands in no
// shard would never run, so every way this can come out empty or short is an
// error, never a regex that matches nothing and passes.
package testshard

import (
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Partition is the names, sorted, that fall to shard i of n: those at index k
// with k % n == i-1.
func Partition(names []string, i, n int) ([]string, error) {
	if n < 1 {
		return nil, fmt.Errorf("a shard count of %d: it must be at least 1", n)
	}
	if i < 1 || i > n {
		return nil, fmt.Errorf("shard %d of %d: the shard must be from 1 to %d", i, n, n)
	}
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	var out []string
	for k, name := range sorted {
		if k%n == i-1 {
			out = append(out, name)
		}
	}
	return out, nil
}

// Regex is the anchored alternation of names, ^(A|B)$. An empty list is an
// error: ^$ would match no test, and a job running it would pass having run
// nothing.
func Regex(names []string) (string, error) {
	if len(names) == 0 {
		return "", fmt.Errorf("no tests to run: the regex would match nothing and the job would pass empty")
	}
	quoted := make([]string, len(names))
	for k, name := range names {
		quoted[k] = regexp.QuoteMeta(name)
	}
	return "^(" + strings.Join(quoted, "|") + ")$", nil
}

// ParseShard reads "i/n".
func ParseShard(s string) (i, n int, err error) {
	a, b, ok := strings.Cut(s, "/")
	if !ok {
		return 0, 0, fmt.Errorf("shard %q: want i/n, as 1/3", s)
	}
	if i, err = strconv.Atoi(a); err != nil {
		return 0, 0, fmt.Errorf("shard %q: %q is not a number", s, a)
	}
	if n, err = strconv.Atoi(b); err != nil {
		return 0, 0, fmt.Errorf("shard %q: %q is not a number", s, b)
	}
	if n < 1 || i < 1 || i > n {
		return 0, 0, fmt.Errorf("shard %q: want 1 <= i <= n", s)
	}
	return i, n, nil
}

// ShardRegex is the regex for shard i of n over names, or the reason the shard
// is empty.
func ShardRegex(names []string, i, n int) (string, error) {
	part, err := Partition(names, i, n)
	if err != nil {
		return "", err
	}
	if len(part) == 0 {
		return "", fmt.Errorf("shard %d/%d is empty: %d tests cannot fill %d shards; use fewer shards", i, n, len(names), n)
	}
	return Regex(part)
}

// Check is nil when the shards 1..n together hold exactly names, each once.
func Check(names []string, n int) error {
	if len(names) == 0 {
		return fmt.Errorf("no tests listed")
	}
	shards := make([][]string, 0, n)
	for i := 1; i <= n; i++ {
		part, err := Partition(names, i, n)
		if err != nil {
			return err
		}
		shards = append(shards, part)
	}
	return covers(names, shards)
}

// covers is nil when shards hold every name once and nothing else.
func covers(names []string, shards [][]string) error {
	count := map[string]int{}
	for _, shard := range shards {
		for _, name := range shard {
			count[name]++
		}
	}
	var problems []string
	for _, name := range names {
		switch c := count[name]; {
		case c == 0:
			problems = append(problems, name+" is in no shard")
		case c > 1:
			problems = append(problems, fmt.Sprintf("%s is in %d shards", name, c))
		}
		delete(count, name)
	}
	var extra []string
	for name := range count {
		extra = append(extra, name)
	}
	sort.Strings(extra)
	for _, name := range extra {
		problems = append(problems, name+" is in a shard but is not a listed test")
	}
	if len(problems) > 0 {
		return fmt.Errorf("the shards do not cover the tests: %s", strings.Join(problems, "; "))
	}
	return nil
}

// ParseList keeps the Test, Fuzz and Example names of `go test -list` output.
func ParseList(out string) []string {
	var names []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		for _, prefix := range []string{"Test", "Fuzz", "Example"} {
			if strings.HasPrefix(line, prefix) && !strings.ContainsAny(line, " \t") {
				names = append(names, line)
				break
			}
		}
	}
	return names
}

// List runs `go test -list . pkg` and returns its tests. It fails when go does,
// or when the package lists none.
func List(pkg string) ([]string, error) {
	cmd := exec.Command("go", "test", "-list", ".", pkg)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("go test -list . %s: %v: %s", pkg, err, strings.TrimSpace(errb.String()))
	}
	names := ParseList(out.String())
	if len(names) == 0 {
		return nil, fmt.Errorf("go test -list . %s listed no tests", pkg)
	}
	return names, nil
}
