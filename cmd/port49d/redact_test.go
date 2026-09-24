package main

import (
	"reflect"
	"testing"

	"github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/internal/policy"
)

// port49d redacts with the built-in patterns and, where a policy is in force,
// the ones its `platforms:` blocks add, read at each record so a reload
// reaches them (spec §5.8).
func TestTheDaemonRedactsWithThePolicyInForce(t *testing.T) {
	if rules := redactorFor(nil)("arista_eos"); !reflect.DeepEqual(rules, platform.Redactions("arista_eos")) {
		t.Fatalf("no policy: %+v", rules)
	}
	parse := func(body string) *policy.Policy {
		p, err := policy.Parse([]byte(body+minimalPolicy), policy.Env{})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	live := policy.NewLive(parse(""))
	redact := redactorFor(live)
	if rules := redact("arista_eos"); len(rules) != len(platform.Redactions("arista_eos")) {
		t.Fatalf("%+v", rules)
	}
	live.Swap(parse("platforms: {arista_eos: {redact: [{match: ['**'], after: psk}]}}\n"))
	if rules := redact("arista_eos"); len(rules) != len(platform.Redactions("arista_eos"))+1 ||
		rules[len(rules)-1].After != "psk" {
		t.Fatalf("after the reload: %+v", rules)
	}
	if rules := redact("cisco_nxos"); len(rules) != len(platform.Redactions("cisco_nxos")) {
		t.Fatalf("a block reaches only its own platform: %+v", rules)
	}
}
