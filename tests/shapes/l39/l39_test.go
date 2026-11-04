package l39

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/blanketfish/port49/tests/shapes/l82"
)

func TestResultsNeedEveryCell(t *testing.T) {
	out, err := Results(Env{Date: "2026-11-04"}, []l82.Cell{{ID: "b1", Verdict: l82.Pass}, {ID: "c", Verdict: l82.Fail}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(out, "NOT RUN") < 3*2 {
		t.Errorf("the three cells never run are not NOT RUN:\n%s", out)
	}
	if !strings.Contains(out, "2026-11-04") || !strings.Contains(out, "not recorded") {
		t.Errorf("the environment is not rendered:\n%s", out)
	}
	if _, err := Results(Env{}, []l82.Cell{{ID: "z"}}); err == nil {
		t.Error("a cell the entry does not have is accepted")
	}
}

func TestResultsHoldNoToken(t *testing.T) {
	leak := l82.Cell{ID: "b1", Verdict: l82.Pass, Rows: []l82.Row{{Case: "x", Observation: "the password is hunter2"}}}
	if _, err := Results(Env{}, []l82.Cell{leak}); err == nil {
		t.Error("a password in a row is written")
	}
	long := l82.Cell{ID: "b1", Rows: []l82.Row{{Case: "x", Observation: strings.Repeat("a", 30)}}}
	if _, err := Results(Env{}, []l82.Cell{long}); err == nil {
		t.Error("a long key-like run is written")
	}
	// the reason code that names the credential is written without the word
	ok := l82.Cell{ID: "b1", Verdict: l82.Pass, Rows: []l82.Row{{Case: "reasons", Observation: Words([]string{"token_redeemed"})}}}
	if _, err := Results(Env{}, []l82.Cell{ok}); err != nil {
		t.Errorf("token_redeemed as written: %v", err)
	}
}

const log = `{"ts":"2026-11-04T10:00:00Z","event":"authen","verdict":"permit","reason":"token_redeemed","device":{"nas":"172.18.0.9:41234","name":"smoke1","platform":"arista_eos"}}
{"ts":"2026-11-04T10:00:01Z","event":"unvalidated","reason":"device_unknown","unvalidated":{"source":"10.244.1.1:5555"}}
port49d: some plain line
{"event":"x","reason":"Not A Code"}
`

func TestParseLogReadsReasonsAndSourcesOnly(t *testing.T) {
	r, s := ParseLog(log)
	if strings.Join(r, ",") != "device_unknown,token_redeemed" {
		t.Errorf("reasons %v", r)
	}
	if strings.Join(s, ",") != "10.244.1.1,172.18.0.9" {
		t.Errorf("sources %v", s)
	}
	if !Redeemed(r) || Redeemed([]string{"device_unknown"}) {
		t.Error("Redeemed")
	}
}

func TestVerdicts(t *testing.T) {
	pass := Outcome{Client: "pass", Redeemed: true, Device: "172.18.0.5", Sources: []string{"172.18.0.5"}}
	for _, id := range []string{"b1", "b2", "b3", "c"} {
		if Judge(id, pass) != l82.Pass {
			t.Errorf("%s: a redeem is not PASS", id)
		}
		if Judge(id, Outcome{Client: "fail:status_2", Reasons: []string{"device_unknown"}}) != l82.Fail {
			t.Errorf("%s: a refusal is not FAIL", id)
		}
		if Judge(id, Outcome{Client: "pass", Device: "172.18.0.5"}) != l82.Fail {
			t.Errorf("%s: a pass the log does not show is not FAIL", id)
		}
		for _, srcs := range [][]string{{"10.244.2.1"}, {"172.18.0.5", "10.244.2.1"}, nil} {
			o := pass
			o.Sources = srcs
			if Judge(id, o) != l82.Fail {
				t.Errorf("%s: a redeem with sources %v is not FAIL", id, srcs)
			}
		}
	}
	if Judge("b4", Outcome{Client: "fail:timeout"}) != Observed {
		t.Error("b4 is an observation: a timeout observed is recorded")
	}
	if Judge("b4", Outcome{}) != l82.Fail {
		t.Error("b4 with nothing read is FAIL")
	}
}

func TestPatchesAndValues(t *testing.T) {
	if _, err := PinToNode("x; rm"); err == nil {
		t.Error("a bad node name is accepted")
	}
	if p, err := PinToNode("port49l39-worker"); err != nil || !strings.Contains(p, `"kubernetes.io/hostname":"port49l39-worker"`) {
		t.Errorf("%q %v", p, err)
	}
	var ops []struct {
		Op, Path string
		Value    any
	}
	if err := json.Unmarshal([]byte(HostNetwork()), &ops); err != nil {
		t.Fatalf("the host network patch is not a JSON patch: %v", err)
	}
	want := map[string]string{"/spec/template/spec/hostNetwork": "add", "/spec/template/spec/dnsPolicy": "add",
		"/spec/template/spec/securityContext/sysctls": "remove"}
	for _, o := range ops {
		if want[o.Path] != o.Op {
			t.Errorf("unexpected op %s %s", o.Op, o.Path)
		}
		delete(want, o.Path)
	}
	if len(want) != 0 {
		t.Errorf("the host network patch lacks %v: Kubernetes refuses sysctls on the host network", want)
	}
	if v, err := ServiceValues("Local"); err != nil || !strings.Contains(v, "type: NodePort") || !strings.Contains(v, "externalTrafficPolicy: Local") {
		t.Errorf("%q %v", v, err)
	}
	if _, err := ServiceValues("Both"); err == nil {
		t.Error("an unknown policy")
	}
}

func TestB4RendersObservedWithTheSource(t *testing.T) {
	c := l82.Cell{ID: "b4", Verdict: Observed, Rows: []l82.Row{{Case: SourceCase, Observation: "10.244.1.1"}}}
	out, err := Results(Env{}, []l82.Cell{c})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "OBSERVED, source 10.244.1.1") || strings.Contains(out, "(an observation) | PASS") {
		t.Errorf("b4 is not rendered as observed with its source:\n%s", out)
	}
	none := l82.Cell{ID: "b4", Verdict: Observed, Rows: []l82.Row{{Case: SourceCase, Observation: "none recorded"}}}
	if out, _ := Results(Env{}, []l82.Cell{none}); !strings.Contains(out, "OBSERVED, source none recorded") {
		t.Errorf("no source recorded:\n%s", out)
	}
}

func TestOtherWorkerIsNeverThePodsNode(t *testing.T) {
	ws := []string{"w1", "w2"}
	for pod, want := range map[string]string{"w1": "w2", "w2": "w1"} {
		if got, err := OtherWorker(ws, pod); err != nil || got != want {
			t.Errorf("pod on %s: other is %q, %v; want %q", pod, got, err, want)
		}
	}
	for _, c := range []struct {
		ws  []string
		pod string
	}{{ws, "cp"}, {[]string{"w1"}, "w1"}, {[]string{"w1", "w2", "w3"}, "w1"}} {
		if got, err := OtherWorker(c.ws, c.pod); err == nil {
			t.Errorf("%v with the pod on %s gave %q", c.ws, c.pod, got)
		}
	}
}

func TestCheckTargetCatchesASelectionBug(t *testing.T) {
	const pod, other = "172.18.0.4", "172.18.0.2"
	for id, c := range map[string]struct {
		dialled string
		ok      bool
	}{
		"b1": {pod, true}, "b1x": {other, false},
		"b2": {other, true}, "b2x": {pod, false},
		"b3": {pod, true}, "b3x": {other, false},
		"b4": {other, true}, "b4x": {pod, false},
		"c": {pod, true}, "cx": {other, false},
	} {
		cell := strings.TrimSuffix(id, "x")
		err := CheckTarget(cell, c.dialled, pod)
		if (err == nil) != c.ok {
			t.Errorf("%s dialled %s: err %v, want ok=%v", id, c.dialled, err, c.ok)
		}
		if err != nil && !strings.Contains(err.Error(), Invalid) {
			t.Errorf("%s: the error does not say %s: %v", id, Invalid, err)
		}
	}
	if err := CheckTarget("b2", other, ""); err == nil {
		t.Error("an unknown pod node is accepted")
	}
}

func TestInvalidIsRenderedAndNeverAVerdict(t *testing.T) {
	out, err := Results(Env{}, []l82.Cell{{ID: "b2", Verdict: Invalid}})
	if err != nil || !strings.Contains(out, "| INVALID |") {
		t.Errorf("%v\n%s", err, out)
	}
}
