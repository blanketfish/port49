package devicemock

import (
	"strings"
	"testing"
)

func TestReactFindsTheStepThenTheWildcardAndRefusesTheUnknown(t *testing.T) {
	p, _ := Load("testdata/profiles/fixture_plain.yaml", root)
	if r, err := p.React("login", "authen_error"); err != nil || r.Outcome != "falls_to_local" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := p.React("authorize_session", "author_pass_add"); err != nil || r.Then != "next_step" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := p.React("login", "authen_getpass"); err == nil || !strings.Contains(err.Error(), "no reaction") {
		t.Fatal("an event the profile does not cover is an error the vetter fixes, never a default")
	}
}

func TestReactRefusesAnUnknownStepOrEvent(t *testing.T) {
	p, _ := Load("testdata/profiles/fixture_plain.yaml", root)
	for _, c := range [][2]string{{"no_such_step", "author_pass_add"}, {"login", "no_such_event"}} {
		if r, err := p.React(c[0], c[1]); err == nil {
			t.Errorf("%v: %+v %v", c, r, err)
		}
	}
}

func TestAStepsOwnEntryBeatsTheWildcard(t *testing.T) {
	p := &Profile{Stimulus: Stimulus{Steps: []Step{{Name: "login"}}}, Reactions: []Reaction{
		{Step: "*", On: "authen_fail", Then: "stop"},
		{Step: "login", On: "authen_fail", Then: "retry"},
	}}
	if r, err := p.React("login", "authen_fail"); err != nil || r.Then != "retry" {
		t.Fatalf("%+v %v", r, err)
	}
}
