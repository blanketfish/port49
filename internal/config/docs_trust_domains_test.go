package config

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The trust-domains page shows a broker.identity block for operators to copy. The block is read out of
// the page, strict-decoded into the real schema and resolved by checkIdentity, so the page cannot drift
// from what the broker accepts.
const trustDomainsPage = "../../docs/site/concepts/trust-domains.md"

func TestTrustDomainsPageExampleLoads(t *testing.T) {
	page, err := os.ReadFile(trustDomainsPage)
	if err != nil {
		t.Fatal(err)
	}
	_, after, ok := strings.Cut(string(page), "```yaml\n")
	if !ok {
		t.Fatal("trust-domains.md has no yaml block")
	}
	block, _, ok := strings.Cut(after, "```")
	if !ok {
		t.Fatal("trust-domains.md: the yaml block is not closed")
	}

	var doc struct {
		Broker struct {
			Identity *identityYAML `yaml:"identity"`
		} `yaml:"broker"`
	}
	dec := yaml.NewDecoder(bytes.NewReader([]byte(block)))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("the page's example does not decode: %v", err)
	}
	if doc.Broker.Identity == nil {
		t.Fatal("the example has no broker.identity")
	}
	if _, err := checkIdentity(doc.Broker.Identity, ""); err != nil {
		t.Fatalf("the page's example is refused: %v", err)
	}
}
