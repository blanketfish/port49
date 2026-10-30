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
	readme, values := flat("README.md"), flat("values.yaml")
	for _, c := range []string{"`CHOWN`", "`FOWNER`", "`FSETID`", "`baseline`", "`restricted`"} {
		if !strings.Contains(readme, c) {
			t.Errorf("README.md does not name %s", c)
		}
	}
	for name, text := range map[string]string{"README.md": readme, "values.yaml": values} {
		if strings.Contains(text, "enforce \"privileged\"") || strings.Contains(text, "`privileged` Pod Security level") {
			t.Errorf("%s tells the operator to loosen the namespace to privileged", name)
		}
	}
}
