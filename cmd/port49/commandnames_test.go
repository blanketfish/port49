package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/blanketfish/port49/internal/port49d"
)

// A refusal that names a command must name one that works. The broker told an operator at 3am to run
// `port49 directory init-enrollments`, which the CLI refuses (it runs on the broker host as
// `port49-broker init-enrollments`). Every `port49 directory <sub>` that server code or the spec
// names is one the CLI accepts.
func TestEveryDirectorySubcommandARefusalNamesIsOneTheCLIAccepts(t *testing.T) {
	real := map[string]bool{"forget": true, "unlock": true, "reset-second-factor": true, "import": true}
	var files []string
	for _, g := range []string{"../../internal/broker/*.go", "../../internal/port49d/*.go", "../../internal/directory/*.go"} {
		m, _ := filepath.Glob(g)
		files = append(files, m...)
	}
	design, _ := filepath.Glob("../../docs/design/*.md")
	files = append(files, design...)
	re := regexp.MustCompile("port49 directory ([a-z][a-z-]*)")
	seen := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllStringSubmatchIndex(string(b), -1) {
			seen++
			text := string(b)
			sub, name := text[m[2]:m[3]], text[m[0]:m[1]]
			// the spec's table of ruling 15 maps each old socket command to its new home: that row names the
			// old form to say it is gone
			lineStart := strings.LastIndex(text[:m[0]], "\n") + 1
			lineEnd := m[1] + strings.Index(text[m[1]:]+"\n", "\n")
			if !real[sub] && !strings.Contains(text[lineStart:lineEnd], "(socket)") {
				t.Errorf("%s names `%s`, which the CLI does not accept (init-enrollments and export run on the broker host as port49-broker or port49d)", f, name)
			}
		}
	}
	if seen < 5 {
		t.Errorf("found %d command names, want many more: the scan is broken", seen)
	}
}

// The same for the two servers: every `port49-broker <sub>` and `port49d <sub>` that a refusal, a README or
// the design names is a subcommand of that binary. The sets are the tables Main and BrokerMain dispatch from
// (port49d.DaemonSubcommands, port49d.BrokerSubcommands), so a command that is renamed or never added is found.
// A name counts when it sits in a code span or a string, or is followed by a flag, so prose such as
// "port49d reads" is not one.
func TestEveryServerSubcommandNamedIsOneTheBinaryHas(t *testing.T) {
	setOf := func(names []string) map[string]bool {
		if len(names) < 4 {
			t.Fatalf("found %d subcommands, want more: the table is broken", len(names))
		}
		set := map[string]bool{}
		for _, n := range names {
			set[n] = true
		}
		return set
	}
	sets := map[string]map[string]bool{
		"port49-broker": setOf(port49d.BrokerSubcommands()),
		"port49d":       setOf(port49d.DaemonSubcommands()),
	}
	ref := regexp.MustCompile("(`)?\\b(port49-broker|port49d) ([a-z][a-z-]+)")
	var files []string
	for _, g := range []string{"../../internal/*/*.go", "../../cmd/*/*.go", "../../docs/design/*.md", "../../deploy/*/README.md",
		"../../deploy/*/*/README.md", "../../deploy/systemd/*.service", "../../packaging/README.md"} {
		m, _ := filepath.Glob(g)
		files = append(files, m...)
	}
	seen := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for n, line := range strings.Split(string(b), "\n") {
			for _, m := range ref.FindAllStringSubmatchIndex(line, -1) {
				tick := m[2] >= 0
				bin, sub := line[m[4]:m[5]], line[m[6]:m[7]]
				rest := line[m[7]:]
				if !tick && !strings.HasPrefix(rest, " --") && !strings.HasPrefix(rest, "`") {
					continue
				}
				if strings.HasSuffix(f, ".md") && strings.Contains(line, "(socket)") {
					continue
				}
				seen++
				if !sets[bin][sub] {
					t.Errorf("%s:%d names `%s %s`, which %s does not have", f, n+1, bin, sub, bin)
				}
			}
		}
	}
	if seen < 20 {
		t.Errorf("found %d server command names, want many more: the scan is broken", seen)
	}
}
