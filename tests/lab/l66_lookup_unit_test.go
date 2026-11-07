//go:build lab

package lab

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// tokenLookupOptions are the options port49.client.token documents, read from
// the plugin in the tree: d97c52c6 removed `socket`, and L66 kept passing it,
// so every play died in the lookup.
func tokenLookupOptions(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "clients", "ansible", "ansible_collections", "port49", "client", "plugins", "lookup", "token.py"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i := strings.Index(s, `DOCUMENTATION = r"""`)
	if i < 0 {
		t.Fatal("no DOCUMENTATION in token.py")
	}
	doc := s[i+len(`DOCUMENTATION = r"""`):]
	doc = doc[:strings.Index(doc, `"""`)]
	var d struct {
		Options map[string]any `yaml:"options"`
	}
	if err := yaml.Unmarshal([]byte(doc), &d); err != nil {
		t.Fatal(err)
	}
	var out []string
	for k := range d.Options {
		out = append(out, k)
	}
	if len(out) < 5 || !slices.Contains(out, "port49") {
		t.Fatalf("read options %v from token.py", out)
	}
	return out
}

var lookupCall = regexp.MustCompile(`lookup\('port49\.client\.token'([^)]*)\)`)
var lookupKey = regexp.MustCompile(`,\s*([a-z_0-9]+)=`)

// lookupKeys are the key= options of every port49.client.token lookup in text.
func lookupKeys(text string) []string {
	var keys []string
	for _, m := range lookupCall.FindAllStringSubmatch(text, -1) {
		for _, k := range lookupKey.FindAllStringSubmatch(m[1], -1) {
			keys = append(keys, k[1])
		}
	}
	return keys
}

func TestL66LookupCallsUseOnlyDocumentedOptions(t *testing.T) {
	opts := tokenLookupOptions(t)
	src, err := os.ReadFile("l66_test.go")
	if err != nil {
		t.Fatal(err)
	}
	texts := map[string]string{"l66MintFact": l66MintFact, "l66_test.go": string(src)}
	for _, mode := range []string{"lookup", "fact"} {
		texts["inventory "+mode] = l66Inventory(l66InvSpec{Hosts: []l66Host{{"leaf1", "172.100.100.11"}},
			Platform: l66Platforms["arista_eos"], Conn: "network_cli", SSHType: "libssh", Mode: mode, Bin: "/r/bin/port49"})
	}
	for name, text := range texts {
		keys := lookupKeys(text)
		// Fact mode's inventory holds no lookup: it reads the fact the play minted.
		if len(keys) == 0 && name != "inventory fact" {
			t.Errorf("%s: no lookup option found; the check read too little", name)
		}
		for _, k := range keys {
			if !slices.Contains(opts, k) {
				t.Errorf("%s passes %s=, which the lookup does not document (options: %v)", name, k, opts)
			}
		}
	}
}

// The CLI finds a non-default agent through PORT49_TEST_AGENT_SOCKET alone
// (d97c52c6: agent.SocketPath reads it; no command takes a socket flag).
func TestL66AnsibleEnvPointsTheCLIAtTheRunsAgent(t *testing.T) {
	e := &l66Env{l64Env: &l64Env{home: "/w/home", sock: "/w/a/agent.sock"}, work: "/w", collDir: "/w/coll", nssLib: "/l/nss.so"}
	if env := e.ansibleEnv(l66Opts{}); !slices.Contains(env, "PORT49_TEST_AGENT_SOCKET=/w/a/agent.sock") {
		t.Error("the play's env does not name the run's agent socket, so the lookup's CLI looks at the per-user default")
	}
}
