// Command testshard prints the go test -run regex for one shard of a package's
// tests, or checks that the shards of a package cover every test.
//
//	testshard -pkg ./internal/port49d -shard 2/3     # prints ^(A|B|...)$
//	testshard -pkg ./internal/port49d -check -n 3    # exit 1 unless the union is the list
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/blanketfish/port49/tests/ci/testshard"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("testshard", flag.ContinueOnError)
	fs.SetOutput(stderr)
	pkg := fs.String("pkg", "", "the package, as ./internal/port49d")
	shard := fs.String("shard", "", "the shard to print, as i/n")
	check := fs.Bool("check", false, "check that shards 1..n cover every test")
	n := fs.Int("n", 0, "with -check, the shard count")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *pkg == "" || (*check) == (*shard != "") || (*check && *n < 1) {
		fmt.Fprintln(stderr, "usage: testshard -pkg PKG (-shard i/n | -check -n N)")
		return 2
	}
	names, err := testshard.List(*pkg)
	if err != nil {
		fmt.Fprintln(stderr, "testshard:", err)
		return 1
	}
	if *check {
		if err := testshard.CheckListed(names, *n, func(re string) ([]string, error) { return testshard.ListMatching(*pkg, re) }); err != nil {
			fmt.Fprintln(stderr, "testshard:", err)
			return 1
		}
		fmt.Fprintf(stdout, "testshard: %d tests in %d shards, each once\n", len(names), *n)
		return 0
	}
	i, count, err := testshard.ParseShard(*shard)
	if err != nil {
		fmt.Fprintln(stderr, "testshard:", err)
		return 2
	}
	re, err := testshard.ShardRegex(names, i, count)
	if err != nil {
		fmt.Fprintln(stderr, "testshard:", err)
		return 1
	}
	fmt.Fprintln(stdout, re)
	return 0
}
