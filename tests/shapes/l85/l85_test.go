package l85

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/tests/shapes/l82"
)

const bgp = `{"prefix":"10.85.85.1/32","paths":[
{"valid":true,"multipath":true,"nexthops":[{"ip":"172.18.0.3","afi":"ipv4","used":true}]},
{"valid":true,"nexthops":[{"ip":"172.18.0.4","afi":"ipv4","used":true}]},
{"valid":false,"nexthops":[{"ip":"172.18.0.9","afi":"ipv4"}]},
{"valid":true,"nexthops":[{"ip":"172.18.0.3","afi":"ipv4"}]}]}`

const route = `{"10.85.85.1/32":[{"prefix":"10.85.85.1/32","protocol":"bgp","selected":true,
"nexthops":[{"ip":"172.18.0.3","active":true},{"ip":"172.18.0.4","active":true},{"ip":"172.18.0.9","active":false}]}]}`

func TestNextHopsOfValidPathsOnly(t *testing.T) {
	got, err := ParseBGPNextHops(bgp)
	if err != nil || strings.Join(got, ",") != "172.18.0.3,172.18.0.4" {
		t.Errorf("bgp %v %v", got, err)
	}
	got, err = ParseRouteNextHops(route)
	if err != nil || strings.Join(got, ",") != "172.18.0.3,172.18.0.4" {
		t.Errorf("route %v %v", got, err)
	}
	for _, f := range []func(string) ([]string, error){ParseBGPNextHops, ParseRouteNextHops} {
		if got, err := f(`{}`); err != nil || len(got) != 0 {
			t.Errorf("an empty answer is %v %v", got, err)
		}
		if _, err := f(`not json`); err == nil {
			t.Error("not JSON is accepted")
		}
	}
}

func TestTheVerdicts(t *testing.T) {
	P, F := l82.Pass, l82.Fail
	check := func(name, got, want string) {
		t.Helper()
		if got != want {
			t.Errorf("%s = %s, want %s", name, got, want)
		}
	}
	check("source, own address and a stranger refused", JudgeSource(true, true), P)
	check("source, login fails", JudgeSource(false, true), F)
	check("source, a stranger admitted", JudgeSource(true, false), F)
	check("nodes equal", JudgeNodes([]string{"b", "a"}, []string{"a", "b"}), P)
	check("nodes, one missing", JudgeNodes([]string{"a"}, []string{"a", "b"}), F)
	check("nodes, one extra", JudgeNodes([]string{"a", "b", "c"}, []string{"a", "b"}), F)
	check("nodes, none advertise", JudgeNodes(nil, nil), F)
	check("withdrawn in 10 s", JudgeWithdrawal(Withdrawal{true, 10 * time.Second, true}), P)
	check("withdrawn in 11 s", JudgeWithdrawal(Withdrawal{true, 11 * time.Second, true}), F)
	check("never withdrawn", JudgeWithdrawal(Withdrawal{false, 0, true}), F)
	check("next login fails", JudgeWithdrawal(Withdrawal{true, time.Second, false}), F)
	check("rollout clean", JudgeRollout(LoopStats{Seconds: 100, PassFirst: 97, PassOnRetry: 3}), P)
	check("rollout with a failure past the retry", JudgeRollout(LoopStats{Seconds: 100, PassFirst: 96, PassOnRetry: 3, FailedPastRetry: 1}), F)
	check("no logins at all", JudgeRollout(LoopStats{}), F)
}

func TestParseLoop(t *testing.T) {
	s, err := ParseLoop("0 pass -\n1 fail:reset pass\n2 fail:timeout fail:refused\n3 pass -\n")
	if err != nil || s != (LoopStats{Seconds: 4, PassFirst: 2, PassOnRetry: 1, FailedPastRetry: 1}) {
		t.Errorf("%+v %v", s, err)
	}
	for _, bad := range []string{"0 pass\n", "0 pass x\n", "0 token -\n", "a pass -\n", "0 fail:a-password -\n", "0 pass - extra\n"} {
		if _, err := ParseLoop(bad); err == nil {
			t.Errorf("%q is accepted", bad)
		}
	}
}

func TestParseSession(t *testing.T) {
	s, err := ParseSession("ok 0\nok 1\nok 2\nend 3 closed\n")
	if err != nil || s != (SessionStats{Logins: 3, End: "closed", EndSecond: 3}) {
		t.Errorf("%+v %v", s, err)
	}
	if s, err := ParseSession("ok 0\nend 1 deadline\n"); err != nil || s.End != "deadline" {
		t.Errorf("%+v %v", s, err)
	}
	for _, bad := range []string{"ok 0\n", "end 1 weird\n", "ok x\nend 1 closed\n", "end 1 closed\nok 2\n", ""} {
		if _, err := ParseSession(bad); err == nil {
			t.Errorf("%q is accepted", bad)
		}
	}
}

func TestFRRConfigPeersEveryNodeAndRunsECMP(t *testing.T) {
	c := FRRConfig(64512, 64500, []string{"172.18.0.2", "172.18.0.3"})
	for _, want := range []string{"router bgp 64512", "no bgp ebgp-requires-policy", "bgp bestpath as-path multipath-relax",
		"neighbor 172.18.0.2 remote-as 64500", "neighbor 172.18.0.3 remote-as 64500", "maximum-paths 8"} {
		if !strings.Contains(c, want) {
			t.Errorf("the config lacks %q:\n%s", want, c)
		}
	}
	if strings.Contains(c, "172.18.0.4") || strings.Count(c, "remote-as") != 2 {
		t.Errorf("a neighbor too many:\n%s", c)
	}
}

func TestMetalLBManifests(t *testing.T) {
	docs, err := MetalLB("10.85.85.1", "172.18.0.9", 64500, 64512)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]map[string]any{}
	for _, d := range docs {
		var m map[string]any
		if err := json.Unmarshal(d, &m); err != nil {
			t.Fatal(err)
		}
		kinds[m["kind"].(string)] = m["spec"].(map[string]any)
	}
	if p := kinds["IPAddressPool"]; p["addresses"].([]any)[0] != "10.85.85.1/32" || p["autoAssign"] != false {
		t.Errorf("pool %v", p)
	}
	if p := kinds["BGPPeer"]; p["myASN"] != float64(64500) || p["peerASN"] != float64(64512) || p["peerAddress"] != "172.18.0.9" {
		t.Errorf("peer %v", p)
	}
	if a := kinds["BGPAdvertisement"]; a["ipAddressPools"].([]any)[0] != PoolName {
		t.Errorf("advertisement %v", a)
	}
	if _, err := MetalLB("not an address", "172.18.0.9", 1, 2); err == nil {
		t.Error("a bad VIP is accepted")
	}
}

func TestServiceValues(t *testing.T) {
	v := ServiceValues("10.85.85.1")
	for _, want := range []string{"type: LoadBalancer", "externalTrafficPolicy: Local", `metallb.universe.tf/loadBalancerIPs: "10.85.85.1"`} {
		if !strings.Contains(v, want) {
			t.Errorf("the values lack %q:\n%s", want, v)
		}
	}
	if strings.Contains(v, "loadBalancerIP:") {
		t.Error("the deprecated spec.loadBalancerIP is set")
	}
}

func env() Env {
	return Env{Date: "2026-10-30", Runner: "ubuntu24 1", Run: "run 1", Docker: "28", Kernel: "6.8", Kind: "kind v0.29.0",
		NodeImage: "kindest/node:v1.33.1", Kubectl: "v1.33.1", Helm: "v3.22.0", MetalLBChart: "0.16.1", MetalLB: "v0.16.1",
		FRR: "quay.io/frrouting/frr:10.5.3", VIP: "10.85.85.1"}
}

func TestResultsHoldVersionsAndEveryCell(t *testing.T) {
	cells := []l82.Cell{{ID: "b", Verdict: l82.Pass, Rows: []l82.Row{{Case: "next hops", Observation: "172.18.0.3, 172.18.0.4"}}}}
	out, err := Results(env(), cells)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"MetalLB: chart 0.16.1, app v0.16.1", "FRR: quay.io/frrouting/frr:10.5.3", "172.18.0.3, 172.18.0.4", "GitHub-hosted runner"} {
		if !strings.Contains(out, want) {
			t.Errorf("the results lack %q", want)
		}
	}
	if strings.Count(out, "NOT RUN") < 3 {
		t.Errorf("the three cells never run are not NOT RUN:\n%s", out)
	}
	for _, id := range Order {
		if !strings.Contains(out, title(id)) {
			t.Errorf("no section for %s", id)
		}
	}
	for _, obs := range []string{"token", strings.Repeat("a", 24)} {
		cells[0].Rows[0].Observation = obs
		if out, err := Results(env(), cells); err == nil || out != "" {
			t.Errorf("%q is written", obs)
		}
	}
}

// The FRR image ships bgpd=no, so a router started from it answers "bgpd is not running" to every BGP
// command for ever (lab-kind run 41121821392, measured with a plain docker run of the pinned image).
func TestTheRoutersDaemonsFileStartsBGP(t *testing.T) {
	got := FRRDaemons()
	on := map[string]bool{}
	for _, ln := range strings.Split(got, "\n") {
		if k, v, ok := strings.Cut(ln, "="); ok && !strings.HasSuffix(k, "_options") {
			on[k] = v == "yes"
		}
	}
	for _, d := range []string{"zebra", "bgpd", "staticd", "vtysh_enable"} {
		if !on[d] {
			t.Errorf("%s is not yes in:\n%s", d, got)
		}
	}
	for _, d := range []string{"ospfd", "ospf6d", "ripd", "ripngd", "isisd", "pimd", "ldpd", "nhrpd", "eigrpd", "babeld", "sharpd", "pbrd", "bfdd", "fabricd", "vrrpd", "pathd"} {
		if on[d] {
			t.Errorf("%s is on; only what the lab needs runs", d)
		}
	}
}

// A router that never answers prints what it logged and the daemons file it ran on, the last lines of
// the log only, so the failure says why and stays short.
func TestAStuckRouterReportsItsLogAndItsDaemonsFile(t *testing.T) {
	var log []string
	for i := 0; i < 100; i++ {
		log = append(log, fmt.Sprintf("watchfrr line %d", i))
	}
	got := FRRStuck(strings.Join(log, "\n"), "bgpd=no\nzebra=yes\n")
	for _, want := range []string{"container log", "watchfrr line 99", "daemons file", "bgpd=no"} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "watchfrr line 10\n") || strings.Contains(got, "watchfrr line 0\n") {
		t.Errorf("the whole log is printed, not its tail:\n%s", got)
	}
	if got := FRRStuck("", ""); !strings.Contains(got, "empty") {
		t.Errorf("an empty log and file are said to be empty: %q", got)
	}
}

func TestAStoppedSessionWithNoEndIsStillOpenNotUnreadable(t *testing.T) {
	s, err := ParseStoppedSession("ok 0\nok 1\nok 2\n", true)
	if err != nil || s != (SessionStats{Logins: 3, End: OpenEnd}) {
		t.Errorf("%+v %v", s, err)
	}
	if s, err := ParseStoppedSession("", true); err != nil || s.End != OpenEnd || s.Logins != 0 {
		t.Errorf("%+v %v", s, err)
	}
	if s, err := ParseStoppedSession("ok 0\nend 5 closed\n", true); err != nil || s.End != "closed" {
		t.Errorf("an ended session read as %+v %v", s, err)
	}
	if _, err := ParseStoppedSession("ok 0\n", false); err == nil {
		t.Error("no end line, no cancel, was accepted")
	}
	if _, err := ParseStoppedSession("ok 0\nweird\n", true); err == nil {
		t.Error("garbage was accepted")
	}
}
