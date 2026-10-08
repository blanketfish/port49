package oxidized

import (
	"os"
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestTheConfigOffersKeyboardInteractive pins the L49 finding on Arista EOS: vEOS
// lists only publickey,keyboard-interactive, Oxidized's default auth_methods
// (none, publickey, password) names no method the device lists, and net-ssh skips
// methods the server does not list, so the token is never sent.
func TestTheConfigOffersKeyboardInteractive(t *testing.T) {
	raw, err := os.ReadFile("config")
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Vars map[string]any `yaml:"vars"`
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("config does not parse: %v", err)
	}
	want := []any{"none", "publickey", "password", "keyboard-interactive"}
	if got := cfg.Vars["auth_methods"]; !reflect.DeepEqual(got, want) {
		t.Fatalf("vars.auth_methods = %v, want %v", got, want)
	}
}
