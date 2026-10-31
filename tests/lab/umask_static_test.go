package lab

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// umaskExempt are the packages under tests/ with a daemon-starting tag that need no pin, each with the
// reason. Everything else with such a tag must pin.
var umaskExempt = map[string]string{
	"../compose": "its daemons run in containers; the harness copies files into volumes with modes it sets, " +
		"and the host test reads no fenced file",
	"../systemd": "its daemons run in a container; b.put and b.putFile set owner and mode on every file, " +
		"and the host test reads no fenced file",
	"../image":    "inspects an image's tar and runs it in a container; no daemon reads a host file",
	"../packages": "inspects built packages and runs them in containers; no daemon reads a host file",
	"../helm":     "renders the chart and checks the manifests; it starts no daemon",
}

// The daemons the lab starts read their trust files through the fence (decision 54 ruling 16), which
// refuses a directory others can write; t.TempDir takes the process umask, so on a host at 002 every
// daemon input is group-writable and the start is refused. Every package under tests/ whose test files
// carry a tag that starts a daemon therefore pins umask 022 in an init of its own (not an assumption
// about the host), in a file that is built under each of the package's tags, or is exempt with a reason.
func TestEveryLabTaggedPackagePinsUmask022(t *testing.T) {
	const needle = "syscall.Umask(0o0" + "22)"
	constraint := regexp.MustCompile(`(?m)^//go:build (.*)$`)
	tag := regexp.MustCompile(`\b(lab|hwkey_dlopen|hwkey|l60probe|kind|systemd|compose|image|packages|helm)\b`)
	tagged := map[string]map[string]bool{} // dir -> daemon-starting tags its test files use
	pinned := map[string][]string{}        // dir -> the build constraint of each pinning file ("" for none)
	err := filepath.WalkDir("..", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == "logs" || n == "results" || n == "evidence" || n == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		dir := filepath.Dir(p)
		var line string
		if m := constraint.FindSubmatch(b); m != nil {
			line = strings.TrimSpace(string(m[1]))
			for _, tg := range tag.FindAllString(line, -1) {
				if tagged[dir] == nil {
					tagged[dir] = map[string]bool{}
				}
				tagged[dir][tg] = true
			}
		}
		if strings.Contains(string(b), needle) && !strings.HasSuffix(p, "umask_static_test.go") {
			pinned[dir] = append(pinned[dir], line)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(tagged) < 4 {
		t.Fatalf("found %d tagged packages, want at least 4: the scan is broken", len(tagged))
	}
	for dir, tags := range tagged {
		if _, ok := umaskExempt[dir]; ok {
			if len(pinned[dir]) > 0 {
				t.Errorf("%s pins the umask and is also exempt: drop the exemption", dir)
			}
			continue
		}
		covered := false
		for _, line := range pinned[dir] {
			if line == "" || line == "unix" {
				covered = true
				break
			}
			all := true
			for tg := range tags {
				all = all && regexp.MustCompile(`\b`+tg+`\b`).MatchString(line)
			}
			covered = covered || all
		}
		if !covered {
			t.Errorf("%s has tests under tags %v and no `syscall.Umask(0o022)` in an init built under all of them "+
				"(add one, or an entry in umaskExempt with the reason)", dir, tagKeys(tags))
		}
	}
	for dir := range umaskExempt {
		if tagged[dir] == nil {
			t.Errorf("umaskExempt names %s, which has no tagged test files: drop the entry", dir)
		}
	}
}

func tagKeys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
