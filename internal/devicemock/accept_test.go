package devicemock

import (
	"slices"
	"strings"
	"testing"
)

func longArgs() [][]byte {
	return [][]byte{[]byte("local-user-name=p49-ro"), []byte("allow-commands=" + strings.Repeat("a", 140)),
		[]byte("deny-commands=" + strings.Repeat("d", 140))}
}

func TestAMeasuredRuleGatesAReplyOverItsLimit(t *testing.T) {
	p, _ := Load("testdata/profiles/fixture_junos.yaml", root)
	gate, warn := Check(p.Acceptance, "authorize_session", longArgs())
	if len(gate) != 1 || gate[0].Rule != "junos_reply_total" || gate[0].Effect != "lockout" || len(warn) != 0 {
		t.Fatalf("gate %+v warn %+v", gate, warn)
	}
	if strings.Contains(gate[0].Detail, "aaaa") {
		t.Fatal("a violation names lengths, never an attribute's value")
	}
}

func TestTheSameReplyPassesAProfileWithoutTheRule(t *testing.T) {
	p, _ := Load("testdata/profiles/fixture_plain.yaml", root)
	if gate, warn := Check(p.Acceptance, "authorize_session", longArgs()); len(gate)+len(warn) != 0 {
		t.Fatalf("no rule, no violation: %+v %+v", gate, warn)
	}
}

func TestAnUnmeasuredRuleWarnsAndNeverGates(t *testing.T) {
	r := AcceptanceRule{ID: "junos_reply_total", Kind: "max_reply_bytes", Applies: "authorize_session", Max: 255,
		Effect: "lockout", Status: "unmeasured"}
	gate, warn := Check([]AcceptanceRule{r}, "authorize_session", longArgs())
	if len(gate) != 0 || len(warn) != 1 || warn[0].Measured {
		t.Fatalf("gate %+v warn %+v", gate, warn)
	}
}

func TestTheSameViolationGatesWhenMeasuredAndWarnsWhenNot(t *testing.T) {
	r := AcceptanceRule{ID: "r", Kind: "max_reply_bytes", Applies: "any", Max: 255, Effect: "lockout", Status: "measured"}
	gate, warn := Check([]AcceptanceRule{r}, "authorize_session", longArgs())
	if len(gate) != 1 || len(warn) != 0 || !gate[0].Measured {
		t.Fatalf("measured: gate %+v warn %+v", gate, warn)
	}
	r.Status = "unmeasured"
	gate, warn = Check([]AcceptanceRule{r}, "authorize_session", longArgs())
	if len(gate) != 0 || len(warn) != 1 || warn[0].Measured {
		t.Fatalf("unmeasured: gate %+v warn %+v", gate, warn)
	}
}

func TestARuleOnlyAppliesToItsStep(t *testing.T) {
	r := AcceptanceRule{ID: "r", Kind: "max_reply_bytes", Applies: "authorize_session", Max: 255, Status: "measured"}
	if gate, warn := Check([]AcceptanceRule{r}, "command_permitted", longArgs()); len(gate)+len(warn) != 0 {
		t.Fatalf("%+v %+v", gate, warn)
	}
}

func TestEachRuleKind(t *testing.T) {
	for _, c := range []struct {
		r    AcceptanceRule
		args []string
		hit  bool
	}{
		{AcceptanceRule{Kind: "max_attribute_bytes", Max: 10}, []string{"priv-lvl=15"}, true},
		{AcceptanceRule{Kind: "max_attribute_bytes", Max: 11}, []string{"priv-lvl=15"}, false},
		{AcceptanceRule{Kind: "priv_lvl_range", Min: 0, Max: 15}, []string{"priv-lvl=16"}, true},
		{AcceptanceRule{Kind: "priv_lvl_range", Min: 0, Max: 15}, []string{"priv-lvl=15"}, false},
		{AcceptanceRule{Kind: "attribute_refused", Names: []string{"shell:roles"}}, []string{"shell:roles*x"}, true},
		{AcceptanceRule{Kind: "role_names", Names: []string{"network-admin"}}, []string{"shell:roles*network-operator"}, true},
		{AcceptanceRule{Kind: "role_names", Names: []string{"network-admin"}}, []string{"shell:roles*network-admin"}, false},
		{AcceptanceRule{Kind: "role_names", Names: []string{"network-admin", "p49-ro"}}, []string{`shell:roles*"network-admin p49-ro"`}, false},
	} {
		c.r.ID, c.r.Applies, c.r.Status = "r", "any", "measured"
		var args [][]byte
		for _, a := range c.args {
			args = append(args, []byte(a))
		}
		gate, _ := Check([]AcceptanceRule{c.r}, "authorize_session", args)
		if (len(gate) == 1) != c.hit {
			t.Errorf("%s %v: hit %v, want %v", c.r.Kind, c.args, len(gate) == 1, c.hit)
		}
	}
}

// A violation names lengths and attribute names. Reply attributes can hold
// role names and other policy output, so no kind may echo a value.
func TestNoViolationEchoesAnAttributeValue(t *testing.T) {
	const secret = "zq7-distinctive-value"
	for _, c := range []struct {
		r    AcceptanceRule
		args string
	}{
		{AcceptanceRule{Kind: "max_attribute_bytes", Max: 5}, "allow-commands=" + secret},
		{AcceptanceRule{Kind: "max_reply_bytes", Max: 5}, "allow-commands=" + secret},
		{AcceptanceRule{Kind: "priv_lvl_range", Min: 0, Max: 15}, "priv-lvl=" + secret},
		{AcceptanceRule{Kind: "attribute_refused", Names: []string{"shell:roles"}}, "shell:roles*" + secret},
		{AcceptanceRule{Kind: "role_names", Names: []string{"network-admin"}}, "shell:roles*" + secret},
	} {
		c.r.ID, c.r.Applies, c.r.Status, c.r.Effect = "r", "any", "measured", "lockout"
		gate, _ := Check([]AcceptanceRule{c.r}, "authorize_session", [][]byte{[]byte(c.args)})
		if len(gate) != 1 {
			t.Fatalf("%s: no violation", c.r.Kind)
		}
		if strings.Contains(gate[0].Detail, secret) || strings.Contains(gate[0].Detail, "distinctive") {
			t.Errorf("%s: Detail echoes a value: %q", c.r.Kind, gate[0].Detail)
		}
	}
}

func TestRoleNamesReadsQuotedAndBareValues(t *testing.T) {
	for in, want := range map[string][]string{
		`network-admin`:          {"network-admin"},
		`"network-admin p49-ro"`: {"network-admin", "p49-ro"},
		`network-admin  p49-ro`:  {"network-admin", "p49-ro"},
	} {
		if got := roleNames(in); !slices.Equal(got, want) {
			t.Errorf("roleNames(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAMalformedAttributeIsNamedUnnamedNeverEchoed(t *testing.T) {
	r := AcceptanceRule{ID: "r", Kind: "max_attribute_bytes", Applies: "any", Max: 5, Status: "measured"}
	gate, _ := Check([]AcceptanceRule{r}, "authorize_session", [][]byte{[]byte("zq7-no-separator-distinctive")})
	if len(gate) != 1 || strings.Contains(gate[0].Detail, "zq7") || !strings.Contains(gate[0].Detail, "<unnamed>") {
		t.Fatalf("%+v", gate)
	}
}

// The total counts whole name=value bytes, without the 1-byte length prefix.
func TestReplyTotalPassesAt255AndGatesAt256(t *testing.T) {
	r := AcceptanceRule{ID: "r", Kind: "max_reply_bytes", Applies: "any", Max: 255, Status: "measured"}
	at := func(n int) [][]byte {
		return [][]byte{[]byte("a=" + strings.Repeat("x", 100)), []byte("b=" + strings.Repeat("x", n-102-2))}
	}
	if gate, _ := Check([]AcceptanceRule{r}, "authorize_session", at(255)); len(gate) != 0 {
		t.Fatalf("255 bytes gated: %+v", gate)
	}
	if gate, _ := Check([]AcceptanceRule{r}, "authorize_session", at(256)); len(gate) != 1 {
		t.Fatal("256 bytes passed")
	}
}

func TestRoleNamesCurrentBehaviourOnOddInput(t *testing.T) {
	for in, want := range map[string][]string{
		`"network-admin`:        {"network-admin"},
		`network-admin"`:        {"network-admin"},
		``:                      {},
		`   `:                   {},
		"network-admin\tp49-ro": {"network-admin", "p49-ro"},
	} {
		if got := roleNames(in); !slices.Equal(got, want) && !(len(got) == 0 && len(want) == 0) {
			t.Errorf("roleNames(%q) = %q, want %q", in, got, want)
		}
	}
}
