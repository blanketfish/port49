// The compose files' static checks: they run with `go test ./...`, no Docker.
// A secret is a file, never an environment variable (spec decision 54 ruling
// 2): so no secret reference in the shipped config names the environment, and
// no `environment:` entry in compose.yaml looks like a secret. A failure names
// the file and the variable, never a value.
package compose

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// secretName is an environment variable's name that says it holds a secret.
var secretName = regexp.MustCompile(`(?i)(SECRET|PASSWORD|PASSWD|PASSPHRASE|TOKEN|CREDENTIAL|PRIVATE|KEY)`)

// secretValue is a value that looks like key material: a long run of base64,
// base64url or hex characters (a path or a URL has a slash, a colon or a dot).
var secretValue = regexp.MustCompile(`^[A-Za-z0-9+_=-]{20,}$`)

// notSecret are names that match secretName and hold a public setting.
var notSecret = map[string]bool{"ETCD_INITIAL_CLUSTER_TOKEN": true}

// refsInEnv returns a complaint for each scalar in doc that is an env: secret
// reference, under any key.
func refsInEnv(file string, doc *yaml.Node) []string {
	var out []string
	var walk func(n *yaml.Node, path string)
	walk = func(n *yaml.Node, path string) {
		switch n.Kind {
		case yaml.DocumentNode, yaml.SequenceNode:
			for _, c := range n.Content {
				walk(c, path)
			}
		case yaml.MappingNode:
			for i := 0; i+1 < len(n.Content); i += 2 {
				k, v := n.Content[i], n.Content[i+1]
				walk(v, path+"."+k.Value)
			}
		case yaml.ScalarNode:
			if strings.HasPrefix(strings.TrimSpace(n.Value), "env:") {
				out = append(out, fmt.Sprintf("%s: %s names the environment (env:), and a secret is a file", file, strings.TrimPrefix(path, ".")))
			}
		}
	}
	walk(doc, "")
	return out
}

// envEntries returns a complaint for each environment entry of doc (a mapping or a list
// of NAME=value) whose name says secret or whose value looks like key material.
func envEntries(file string, doc *yaml.Node) []string {
	var out []string
	check := func(where, name, value string) {
		switch {
		case !notSecret[name] && secretName.MatchString(name):
			out = append(out, fmt.Sprintf("%s: %s sets %s, a name for a secret; a secret is a file", file, where, name))
		case secretValue.MatchString(value):
			out = append(out, fmt.Sprintf("%s: %s sets %s to a value that looks like key material; a secret is a file", file, where, name))
		}
	}
	var walk func(n *yaml.Node, path string)
	walk = func(n *yaml.Node, path string) {
		switch n.Kind {
		case yaml.DocumentNode:
			for _, c := range n.Content {
				walk(c, path)
			}
		case yaml.SequenceNode:
			for _, c := range n.Content {
				walk(c, path)
			}
		case yaml.MappingNode:
			for i := 0; i+1 < len(n.Content); i += 2 {
				k, v := n.Content[i], n.Content[i+1]
				if k.Value == "environment" {
					switch v.Kind {
					case yaml.MappingNode:
						for j := 0; j+1 < len(v.Content); j += 2 {
							check(path+".environment", v.Content[j].Value, v.Content[j+1].Value)
						}
					case yaml.SequenceNode:
						for _, e := range v.Content {
							name, value, _ := strings.Cut(e.Value, "=")
							check(path+".environment", name, value)
						}
					}
					continue
				}
				walk(v, path+"."+k.Value)
			}
		}
	}
	walk(doc, "")
	return out
}

func parse(t *testing.T, name string, body []byte) *yaml.Node {
	t.Helper()
	var doc yaml.Node
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return &doc
}

func TestNoSecretRefOrEnvironmentEntryIsAnEnvironmentSecret(t *testing.T) {
	dir := filepath.Join("..", "..", "deploy", "compose")
	cfgs, err := filepath.Glob(filepath.Join(dir, "config", "*.yaml"))
	if err != nil || len(cfgs) == 0 {
		t.Fatalf("no config files under %s: %v", dir, err)
	}
	for _, f := range cfgs {
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range refsInEnv(filepath.Base(f), parse(t, f, body)) {
			t.Error(c)
		}
	}
	body, err := os.ReadFile(filepath.Join(dir, "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range envEntries("compose.yaml", parse(t, "compose.yaml", body)) {
		t.Error(c)
	}
}

// The checks catch what they are for: fake values only.
func TestTheStaticChecksCatchAnEnvironmentSecret(t *testing.T) {
	cfg := `
encryption:
  current: {id: c1, secret_ref: "env:FAKE_SEALING"}
keys:
  k:
    current: {version: 1, secret_ref: "file:/run/port49/keys/tacacs_v1"}
stores:
  directory:
    etcd:
      password_secret_ref: "env:FAKE_ETCD"
`
	if got := refsInEnv("port49d.yaml", parse(t, "x", []byte(cfg))); len(got) != 2 {
		t.Fatalf("two env: refs expected, got %q", got)
	}
	clean := "encryption:\n  current: {id: c1, secret_ref: \"file:/etc/port49/secrets/encryption.key\"}\n"
	if got := refsInEnv("port49d.yaml", parse(t, "x", []byte(clean))); len(got) != 0 {
		t.Fatalf("a file ref was flagged: %q", got)
	}
	for name, doc := range map[string]string{
		"map name":   "services:\n  a:\n    environment:\n      PORT49_KEY_V1: x\n",
		"list name":  "services:\n  a:\n    environment:\n      - FAKE_PASSWORD=x\n",
		"map value":  "services:\n  a:\n    environment:\n      FAKE: ABCDEFGHIJKLMNOPQRSTUVWXYZ012345\n",
		"anchor use": "x-e: &e\n  environment:\n    SEALING_SECRET: x\nservices:\n  a: *e\n",
	} {
		if got := envEntries("compose.yaml", parse(t, name, []byte(doc))); len(got) == 0 {
			t.Errorf("%s: an environment secret was not caught", name)
		}
	}
	ok := "services:\n  a:\n    environment:\n      ETCD_INITIAL_CLUSTER_TOKEN: port49-compose\n      ETCD_DATA_DIR: /var/lib/etcd\n      U: https://etcd-1:2380\n"
	if got := envEntries("compose.yaml", parse(t, "ok", []byte(ok))); len(got) != 0 {
		t.Fatalf("ordinary settings were flagged: %q", got)
	}
}

// onceFunc is setup.sh's once(), extracted, so its cases run with no Docker.
func onceFunc(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../deploy/compose/setup.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i := strings.Index(s, "once() {")
	j := strings.Index(s[i:], "\n}\n")
	if i < 0 || j < 0 {
		t.Fatal("setup.sh has no once() function")
	}
	return s[i : i+j+3]
}

func runOnce(t *testing.T, src, dst string) (string, error) {
	t.Helper()
	script := "set -eu\nTMP=\n" + onceFunc(t) + `once "$1" "$2" "$(id -u)" "$(id -g)" 0400` + "\n"
	out, err := exec.Command("sh", "-c", script, "sh", src, dst).CombinedOutput()
	return string(out), err
}

// A sealing key that is in neither local/ nor the volume is skipped without a word: a rotation's
// last step leaves it so, and the daemon's own start check names a file the config still wants.
func TestOnceSkipsAKeyInNeitherPlace(t *testing.T) {
	d := t.TempDir()
	out, err := runOnce(t, filepath.Join(d, "gone"), filepath.Join(d, "installed"))
	if err != nil || out != "" {
		t.Fatalf("a key in neither place: err %v, output %q, want success and silence", err, out)
	}
	if _, err := os.Stat(filepath.Join(d, "installed")); err == nil {
		t.Fatal("once installed something from nothing")
	}
}

func TestOnceStillKeepsAnInstalledKeyWhoseSourceIsGone(t *testing.T) {
	d := t.TempDir()
	dst := filepath.Join(d, "installed")
	if err := os.WriteFile(dst, []byte("fake"), 0o400); err != nil {
		t.Fatal(err)
	}
	out, err := runOnce(t, filepath.Join(d, "gone"), dst)
	if err != nil || !strings.Contains(out, "is gone; keeping the installed") {
		t.Fatalf("err %v, output %q, want the keep line", err, out)
	}
}

// The rotation recipe refuses an empty key id before it touches anything.
func TestTheRotationRecipeRefusesAnEmptyKeyID(t *testing.T) {
	b, err := os.ReadFile("../../deploy/compose/README.md")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	k := strings.Index(s, "KEY_ID=$1")
	if k < 0 {
		t.Fatal("the README has no rotation recipe")
	}
	i := strings.LastIndex(s[:k], "-c '") + len("-c '")
	j := strings.Index(s[i:], "\n   ' sh e2")
	if j < 0 {
		t.Fatal("the rotation recipe's end is not where the test expects")
	}
	out, err := exec.Command("sh", "-c", s[i:i+j], "sh", "").CombinedOutput()
	if err == nil || !strings.Contains(string(out), "set KEY_ID to the new key id") {
		t.Fatalf("an empty key id: err %v, output %q, want a refusal naming KEY_ID", err, out)
	}
}
