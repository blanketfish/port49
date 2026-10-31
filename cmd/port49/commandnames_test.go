package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
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
	files = append(files, "../../docs/design/2026-08-23-policy-engine-spec.md")
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
