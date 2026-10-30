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

// The root init containers add DAC_READ_SEARCH (it descends into the 0700 state directory it does not
// own; DAC_OVERRIDE, which baseline allows, would be the wider capability). It is not in baseline's
// list, so the chart's pods are not baseline-clean, and the README must say which level the namespace
// needs rather than claim one the pods fail.
func TestTheReadmeNamesThePodSecurityLevelTheCapabilitiesNeed(t *testing.T) {
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
	readme, err := os.ReadFile(filepath.Join("..", "..", "deploy", "helm", "port49", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	values, err := os.ReadFile(filepath.Join("..", "..", "deploy", "helm", "port49", "values.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(outside) == 0 {
		return // the pods meet baseline: the docs may say so
	}
	flat := func(b []byte) string { return strings.Join(strings.Fields(string(b)), " ") }
	for _, doc := range []struct{ name, text string }{{"README.md", flat(readme)}, {"values.yaml", flat(values)}} {
		if strings.Contains(doc.text, `Pod Security "baseline"`) || strings.Contains(doc.text, "# setup target). They run as root, so the namespace needs Pod Security \"baseline\"") || strings.Contains(doc.text, "meet the Pod Security `baseline` level") ||
			strings.Contains(doc.text, "must be `baseline`") {
			t.Errorf("%s claims the baseline level, but the chart adds %v, which baseline refuses", doc.name, outside)
		}
	}
	if !strings.Contains(flat(readme), "enforce the `privileged` Pod Security level") {
		t.Errorf("README.md does not say the namespace must enforce the `privileged` Pod Security level (the chart adds %v)", outside)
	}
	if !strings.Contains(string(readme), "DAC_READ_SEARCH") {
		t.Error("README.md does not name the capability that baseline refuses")
	}
}
