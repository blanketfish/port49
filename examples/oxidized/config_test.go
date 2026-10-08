package oxidized

import (
	"os"
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestTheConfigOffersKeyboardInteractiveToEOSAlone pins two L49 findings.
// Arista EOS lists only publickey,keyboard-interactive, Oxidized's default
// auth_methods (none, publickey, password) names no method it lists, and
// net-ssh skips methods the server does not list, so the token is never sent
// without keyboard-interactive. But on NX-OS and IOS-XE, which also list
// password, a global keyboard-interactive made one stale token cost two
// authentications instead of one. So the setting is the eos model's alone
// (Oxidized resolves a model's vars before the global ones).
func TestTheConfigOffersKeyboardInteractiveToEOSAlone(t *testing.T) {
	raw, err := os.ReadFile("config")
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Vars   map[string]any `yaml:"vars"`
		Models map[string]struct {
			Vars map[string]any `yaml:"vars"`
		} `yaml:"models"`
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("config does not parse: %v", err)
	}
	if got, ok := cfg.Vars["auth_methods"]; ok {
		t.Errorf("global vars.auth_methods = %v; it belongs to models.eos.vars", got)
	}
	want := []any{"none", "publickey", "password", "keyboard-interactive"}
	if got := cfg.Models["eos"].Vars["auth_methods"]; !reflect.DeepEqual(got, want) {
		t.Fatalf("models.eos.vars.auth_methods = %v, want %v", got, want)
	}
	if len(cfg.Models) != 1 {
		t.Errorf("models = %v, want eos alone", cfg.Models)
	}
}
