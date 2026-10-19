package config

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The compose example's commented identity block, uncommented where it
// stands, is broker.identity: it sits under broker:, not under store:, and
// the real checks accept it (Task 14 review M2).
func TestTheComposeExampleIdentityBlockIsBrokerIdentity(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/compose/config/port49-broker.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	in := false
	for _, l := range strings.Split(string(raw), "\n") {
		switch {
		case strings.HasPrefix(l, "  client_ca_file:"):
			continue // the block replaces it, as its comment says
		case l == "  # identity:":
			in = true
		case strings.HasPrefix(l, "  # The provider posts"):
			in = false
		}
		if in {
			l = strings.Replace(l, "  # ", "  ", 1)
		}
		out = append(out, l)
	}
	var f struct {
		Broker BrokerConfig   `yaml:"broker"`
		Rest   map[string]any `yaml:",inline"`
	}
	dec := yaml.NewDecoder(bytes.NewReader([]byte(strings.Join(out, "\n"))))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		t.Fatalf("the example with its identity block uncommented: %v", err)
	}
	if f.Broker.IdentitySet == nil {
		t.Fatal("the uncommented identity block is not under broker:")
	}
	// The key must be there, or the check below would pass on a missing one.
	stores, ok := f.Rest["stores"].(map[string]any)
	if !ok {
		t.Fatal("the example has no stores: block")
	}
	dir, _ := stores["directory"].(map[string]any)
	if stores["identity"] != nil || dir == nil || dir["identity"] != nil {
		t.Fatal("the identity block sits under stores: or stores.directory:")
	}
	id, err := checkIdentity(f.Broker.IdentitySet, "")
	if err != nil {
		t.Fatal(err)
	}
	if id.X509AnchorFile == "" || len(id.OIDC) != 2 {
		t.Fatalf("the example's identity: anchor %q, %d oidc verifiers", id.X509AnchorFile, len(id.OIDC))
	}
}
