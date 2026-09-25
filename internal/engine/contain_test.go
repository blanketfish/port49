package engine

import "testing"

func TestContains(t *testing.T) {
	classes := map[string][]string{"management": {"^(fxp0|em0)$"}}
	for _, c := range []struct {
		outer, inner string
		want         bool
	}{
		{"show **", "show configuration **", true},
		{"show **", "show", true},
		{"show configuration **", "show **", false},
		{"show *", "show version", true},
		{"show *", "show version detail", false},
		{"show version", "SHOW VERSION", true},
		{"**", "request system reboot", true},
		{"show interfaces @management", "show interfaces fxp0", true},
		{"show interfaces @management", "show interfaces ge-0/0/0", false},
		{"show interfaces @management", "show interfaces *", false},
		{"show interfaces @management", "show interfaces @management", true},
		{"show interfaces /^fxp/", "show interfaces /^fxp0$/", false},
		{"show interfaces *", "show interfaces @management", true},
		{"show version", "show version **", false},
		{"show version **", "show version", true},
	} {
		got, err := Contains(c.outer, c.inner, classes)
		if err != nil || got != c.want {
			t.Errorf("Contains(%q, %q) = %v, %v; want %v", c.outer, c.inner, got, err, c.want)
		}
	}
}

func TestMayMeetAndAlwaysDominates(t *testing.T) {
	junos := Normalize{PipeToken: "|", StripCR: true, SessionOnly: true}
	for _, c := range []struct {
		permit, deny string
		meet, dom    bool
	}{
		// The spec's capability shape: a permit beneath a deny wins there.
		{"show configuration interfaces **", "show configuration **", true, true},
		// The refused shape: a deny beneath the permit.
		{"show interfaces **", "show interfaces terse", true, false},
		{"show version", "request system reboot", false, true},
		// Incomparable: neither is more specific at every position.
		{"show * detail", "show interfaces *", true, false},
		// Two patterns meeting at one position: possible, never definite.
		{"show interfaces /^ge-/", "show interfaces /-0$/", true, false},
	} {
		meet, err := MayMeet(c.permit, c.deny, nil, junos)
		if err != nil || meet != c.meet {
			t.Errorf("MayMeet(%q, %q) = %v, %v; want %v", c.permit, c.deny, meet, err, c.meet)
		}
		dom, err := AlwaysDominates(c.permit, c.deny, nil, junos)
		if err != nil || dom != c.dom {
			t.Errorf("AlwaysDominates(%q, %q) = %v, %v; want %v", c.permit, c.deny, dom, err, c.dom)
		}
	}
}
