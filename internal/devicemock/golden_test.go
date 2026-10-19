package devicemock

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestGoldenRoundTrips(t *testing.T) {
	g := Golden{PendingLab: true, Scenarios: map[string]GoldenScenario{"token_login": {Outcome: "login_ok",
		Steps: []GoldenStep{{Step: "login", Event: "authen_pass"}, {Step: "authorize_session", Event: "author_pass_add", Args: []string{"priv-lvl=15"}}}}}}
	path := filepath.Join(t.TempDir(), "g.json")
	if err := WriteGolden(path, g); err != nil {
		t.Fatal(err)
	}
	back, err := LoadGolden(path)
	if err != nil || !reflect.DeepEqual(back, g) {
		t.Fatalf("%+v %v", back, err)
	}
}

func TestJudgeTurnsAMeasuredGateIntoAFailureAndAnUnmeasuredOneIntoAWarning(t *testing.T) {
	want := GoldenScenario{Outcome: "login_ok"}
	tr := Transcript{Scenario: "token_login", Outcome: "rejected_by_device",
		Gate: []Violation{{Rule: "junos_reply_total", Effect: "lockout", Detail: "300 bytes", Measured: true}}}
	fails, _ := Judge(tr, want)
	if len(fails) == 0 || !strings.Contains(strings.Join(fails, "\n"), "junos_reply_total") {
		t.Fatalf("a measured gate fails, naming its rule: %q", fails)
	}
	tr = Transcript{Scenario: "token_login", Outcome: "login_ok",
		Warn: []Violation{{Rule: "junos_reply_total", Detail: "300 bytes"}}}
	fails, warns := Judge(tr, want)
	if len(fails) != 0 || len(warns) != 1 {
		t.Fatalf("an unmeasured rule warns and never fails: %q %q", fails, warns)
	}
}

func TestJudgeNamesAGoldenDifference(t *testing.T) {
	want := GoldenScenario{Outcome: "login_ok", Steps: []GoldenStep{{Step: "login", Event: "authen_pass"}}}
	tr := Transcript{Scenario: "token_login", Outcome: "login_refused", Steps: []StepResult{{Step: "login", Event: "authen_fail"}}}
	if fails, _ := Judge(tr, want); len(fails) == 0 {
		t.Fatal("a reply that moved from the golden fails")
	}
	same := Transcript{Scenario: "token_login", Outcome: "login_ok", Steps: []StepResult{{Step: "login", Event: "authen_pass"}}}
	if fails, _ := Judge(same, want); len(fails) != 0 {
		t.Fatalf("a matching play passes: %q", fails)
	}
}
