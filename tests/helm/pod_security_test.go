package helm

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Kubernetes' Pod Security Standards, baseline level: the capabilities a container may add. Anything
// else, however small, is refused at pod creation with "violates PodSecurity", and the StatefulSet
// shows no pod at all.
var baselineCaps = map[string]bool{
	"AUDIT_WRITE": true, "CHOWN": true, "DAC_OVERRIDE": true, "FOWNER": true, "FSETID": true, "KILL": true,
	"MKNOD": true, "NET_BIND_SERVICE": true, "SETFCAP": true, "SETGID": true, "SETPCAP": true, "SETUID": true,
	"SYS_CHROOT": true,
}

// The chart's pods must be admitted by a namespace enforcing Pod Security baseline: no template adds a
// capability outside baseline's list (the root init holds CHOWN, FOWNER and FSETID; the descent into
// the data directory is a second init that runs as its owner with none). The README says so and names
// the three, and neither it nor values.yaml may tell an operator to loosen the namespace.
func TestTheChartsCapabilitiesFitPodSecurityBaseline(t *testing.T) {
	var outside []string
	files, _ := filepath.Glob(filepath.Join("..", "..", "deploy", "helm", "port49", "templates", "*"))
	add := regexp.MustCompile(`add: \[([^\]]*)\]`)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range add.FindAllStringSubmatch(string(b), -1) {
			for _, c := range strings.Split(m[1], ",") {
				if c = strings.TrimSpace(c); c != "" && !baselineCaps[c] {
					outside = append(outside, c)
				}
			}
		}
	}
	sort.Strings(outside)
	if len(outside) != 0 {
		t.Errorf("the chart adds %v, which Pod Security baseline refuses: no pod would be created", outside)
	}
	flat := func(name string) string {
		b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "helm", "port49", name))
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(strings.Fields(string(b)), " ")
	}
	readme := flat("README.md")
	for _, c := range []string{"`CHOWN`", "`FOWNER`", "`FSETID`", "`baseline`", "`restricted`"} {
		if !strings.Contains(readme, c) {
			t.Errorf("README.md does not name %s", c)
		}
	}
	// No doc in the repo may tell an operator to loosen the namespace: the kubectl form, YAML, prose, or
	// an exemption of the release's namespace.
	loosen := regexp.MustCompile(`(?i)enforce[=: "']*privileged|exempt[^.\n]{0,40}namespace|namespace[^.\n]{0,40}exempt|` + "`privileged`" + ` Pod Security`)
	for _, root := range []string{"deploy", "docs", "examples"} {
		filepath.Walk(filepath.Join("..", "..", root), func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			switch filepath.Ext(path) {
			case ".md", ".yaml", ".yml":
			default:
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if m := loosen.Find(b); m != nil {
				t.Errorf("%s tells the operator to loosen the namespace: %q", path, m)
			}
			return nil
		})
	}
}

// The init-script test runs a pulled image as root on whatever host runs make test, a key host
// included. It gets exactly the capabilities it names, an image pinned by digest, and no device.
func TestTheInitScriptTestGrantsNoMoreThanItNeeds(t *testing.T) {
	b, err := os.ReadFile("initscript_test.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	for _, bad := range []string{
		`[]string{"` + "ALL" + `"}`, `"--cap-add", "ALL"`, "--priv" + "ileged", "--dev" + "ice", "--pid", "--net", "--ipc", "--uts",
		`"alpine:`, `alpine:3`, "docker.sock", `"-v", "/`,
	} {
		if strings.Contains(src, bad) {
			t.Errorf("initscript_test.go contains %q", bad)
		}
	}
	if !strings.Contains(src, `"@sha256:"`) {
		t.Error("initscript_test.go does not require the chart's init image to be pinned by digest")
	}
}
