// Package l85 holds the pure parts of lab entry L85 (spec §15): MetalLB in BGP mode as an anycast
// address for port49d on kind, with an FRR router and a device behind it. The parsers of what FRR and
// the device client print, the verdicts, the router's and MetalLB's configuration and the results.
// The harness (tests/lab/l85_test.go, tag lab) measures and records; this package decides and
// renders, so a results file is built from the cells and never typed by hand.
//
// The results file is an uploaded CI artifact and will be public: addresses of the lab's own private
// networks, delays, counts, PASS or FAIL and versions. Results refuses text that looks like a key, a
// token or a password.
package l85

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rhwendt/port49/tests/shapes/l82"
)

// WithdrawWithin is (c): the route is withdrawn within this long of the pod's deletion.
const WithdrawWithin = 10 * time.Second

// PoolName is MetalLB's address pool.
const PoolName = "port49-anycast"

// Order is the cells' order in the results.
var Order = []string{"a", "b", "c", "d"}

func title(id string) string {
	return map[string]string{
		"a": "(a) the source port49d sees under externalTrafficPolicy: Local is the device's own address",
		"b": "(b) exactly the nodes running a ready port49d pod advertise the address",
		"c": "(c) a deleted pod's route is withdrawn within 10 s, and a per-transaction client's next login passes",
		"d": "(d) a rolling restart with one login a second: no login fails past one retry",
	}[id]
}

// collect walks a decoded FRR answer and gathers the next-hop addresses under every "nexthops" list
// whose enclosing object passes keep.
func collect(v any, keep func(map[string]any) bool, into map[string]bool) {
	switch x := v.(type) {
	case map[string]any:
		if hops, ok := x["nexthops"].([]any); ok && keep(x) {
			for _, h := range hops {
				m, _ := h.(map[string]any)
				if ip, _ := m["ip"].(string); ip != "" && m["active"] != false {
					into[ip] = true
				}
			}
		}
		for _, c := range x {
			collect(c, keep, into)
		}
	case []any:
		for _, c := range x {
			collect(c, keep, into)
		}
	}
}

func hops(js string, keep func(map[string]any) bool) ([]string, error) {
	var v any
	if err := json.Unmarshal([]byte(js), &v); err != nil {
		return nil, fmt.Errorf("l85: FRR's answer is not JSON: %w", err)
	}
	set := map[string]bool{}
	collect(v, keep, set)
	out := make([]string, 0, len(set))
	for ip := range set {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out, nil
}

// ParseBGPNextHops is the next hops of the valid paths in `show ip bgp <vip>/32 json`.
func ParseBGPNextHops(js string) ([]string, error) {
	return hops(js, func(p map[string]any) bool { return p["valid"] == true })
}

// ParseRouteNextHops is the active next hops of `show ip route <vip>/32 json`: what FRR forwards to.
func ParseRouteNextHops(js string) ([]string, error) {
	return hops(js, func(map[string]any) bool { return true })
}

// JudgeSource is (a): the login from the device's own address passed, which port49d admits only by
// its source address, and a login from an address that is not the device's was refused.
func JudgeSource(loginPassed, strangerRefused bool) string {
	if loginPassed && strangerRefused {
		return l82.Pass
	}
	return l82.Fail
}

// JudgeNodes is (b): the advertising next hops are exactly the ready pods' nodes.
func JudgeNodes(advertising, ready []string) string {
	a, r := append([]string(nil), advertising...), append([]string(nil), ready...)
	sort.Strings(a)
	sort.Strings(r)
	if len(a) > 0 && strings.Join(a, ",") == strings.Join(r, ",") {
		return l82.Pass
	}
	return l82.Fail
}

// Withdrawal is what (c) saw.
type Withdrawal struct {
	Withdrawn       bool          // the deleted pod's node left FRR's next hops
	Delay           time.Duration // from the deletion to that
	NextLoginPassed bool          // the per-transaction client's next login passed
}

// JudgeWithdrawal is (c).
func JudgeWithdrawal(w Withdrawal) string {
	if w.Withdrawn && w.Delay <= WithdrawWithin && w.NextLoginPassed {
		return l82.Pass
	}
	return l82.Fail
}

// LoopStats counts the client's one-login-a-second lines.
type LoopStats struct{ Seconds, PassFirst, PassOnRetry, FailedPastRetry int }

var (
	result = `(?:pass|fail:(?:refused|reset|closed|timeout|error|status_[0-9]+))`
	loopRe = regexp.MustCompile(`^([0-9]+) (` + result + `) (-|` + result + `)$`)
	sessRe = regexp.MustCompile(`^(ok ([0-9]+)|end ([0-9]+) (closed|reset|timeout|error|deadline|refused))$`)
)

// ParseLoop reads `l85client loop`'s output. A line outside the closed vocabulary is an error, so
// nothing else can reach the results.
func ParseLoop(out string) (LoopStats, error) {
	var s LoopStats
	for _, ln := range strings.Split(strings.TrimSpace(out), "\n") {
		m := loopRe.FindStringSubmatch(ln)
		if m == nil {
			return s, fmt.Errorf("l85: a line of the client's loop output is outside its vocabulary")
		}
		s.Seconds++
		switch {
		case m[2] == "pass":
			s.PassFirst++
		case m[3] == "pass":
			s.PassOnRetry++
		default:
			s.FailedPastRetry++
		}
	}
	return s, nil
}

// JudgeRollout is (d): logins were made and none failed past one retry.
func JudgeRollout(s LoopStats) string {
	if s.Seconds > 0 && s.FailedPastRetry == 0 {
		return l82.Pass
	}
	return l82.Fail
}

// SessionStats is what a single-connection session saw.
type SessionStats struct {
	Logins    int
	End       string // closed, reset, timeout, error, refused or deadline
	EndSecond int
}

// ParseSession reads `l85client session`'s output: "ok" lines and one "end" line, last.
func ParseSession(out string) (SessionStats, error) {
	var s SessionStats
	ended := false
	for _, ln := range strings.Split(strings.TrimSpace(out), "\n") {
		m := sessRe.FindStringSubmatch(ln)
		switch {
		case m == nil || ended:
			return s, fmt.Errorf("l85: the session output is outside its vocabulary or continues after its end")
		case m[2] != "":
			s.Logins++
		default:
			ended, s.End = true, m[4]
			s.EndSecond, _ = strconv.Atoi(m[3])
		}
	}
	if !ended {
		return s, fmt.Errorf("l85: the session output has no end line")
	}
	return s, nil
}

// FRRConfig is the vtysh script for the router: eBGP to every node, ECMP over equal paths.
func FRRConfig(localAS, peerAS int, nodes []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "configure terminal\nrouter bgp %d\n no bgp ebgp-requires-policy\n no bgp network import-check\n bgp bestpath as-path multipath-relax\n", localAS)
	for _, n := range nodes {
		fmt.Fprintf(&b, " neighbor %s remote-as %d\n", n, peerAS)
	}
	b.WriteString(" address-family ipv4 unicast\n  maximum-paths 8\n exit-address-family\nexit\nend\n")
	return b.String()
}

// MetalLB is the three resources that make vip a BGP-advertised address peered with the router at
// frrIP: the pool, the peer and the advertisement.
func MetalLB(vip, frrIP string, myAS, peerAS int) ([][]byte, error) {
	if _, err := netip.ParseAddr(vip); err != nil {
		return nil, fmt.Errorf("l85: the address %q: %w", vip, err)
	}
	if _, err := netip.ParseAddr(frrIP); err != nil {
		return nil, fmt.Errorf("l85: the router's address %q: %w", frrIP, err)
	}
	meta := func(kind, version, name string) map[string]any {
		return map[string]any{"apiVersion": "metallb.io/" + version, "kind": kind, "metadata": map[string]any{"name": name, "namespace": "metallb-system"}}
	}
	pool := meta("IPAddressPool", "v1beta1", PoolName)
	pool["spec"] = map[string]any{"addresses": []string{vip + "/32"}, "autoAssign": false}
	peer := meta("BGPPeer", "v1beta2", "l85-frr")
	peer["spec"] = map[string]any{"myASN": myAS, "peerASN": peerAS, "peerAddress": frrIP}
	adv := meta("BGPAdvertisement", "v1beta1", "l85")
	adv["spec"] = map[string]any{"ipAddressPools": []string{PoolName}}
	var out [][]byte
	for _, d := range []map[string]any{pool, peer, adv} {
		b, err := json.Marshal(d)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

// ServiceValues replaces the stack's `service:` values: the TACACS+ Service as a LoadBalancer with
// the local traffic policy and MetalLB's annotation for vip. spec.loadBalancerIP is not set.
func ServiceValues(vip string) string {
	return "service:\n  type: LoadBalancer\n  externalTrafficPolicy: Local\n  annotations: {metallb.universe.tf/loadBalancerIPs: \"" + vip + "\"}\n"
}

// Env is what the results record about the run.
type Env struct {
	Date, Runner, Run, Docker, Kernel, Kind, NodeImage, Kubectl, Helm string
	MetalLBChart, MetalLB, FRR, VIP                                   string
}

func nz(s string) string {
	if strings.TrimSpace(s) == "" {
		return "not recorded"
	}
	return s
}

func cell(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "|", "\\|"), "\n", " ")
}

func verdict(cells []l82.Cell, id string) string {
	for _, c := range cells {
		if c.ID == id && c.Verdict != "" {
			return c.Verdict
		}
	}
	return l82.NotRun
}

// Results is the results file for the CI artifact, built from cells and nothing else. It fails,
// writing nothing, if any text in it looks like a key.
func Results(env Env, cells []l82.Cell) (string, error) {
	var b strings.Builder
	b.WriteString("# L85: MetalLB in BGP mode as an anycast address for port49d, on kind with an FRR peer\n\n")
	b.WriteString("Generated by `make lab-l85` (tests/lab/l85_test.go) from the cells below; edit the harness, not this file.\n\n")
	fmt.Fprintf(&b, "- Date: %s\n- Platform: GitHub-hosted runner, %s\n- Run: %s\n- Docker: %s\n- Kernel: %s\n- kind: %s\n- Node image: %s\n- kubectl: %s\n- helm: %s\n- MetalLB: chart %s, app %s\n- FRR: %s\n- Address: %s\n\n",
		nz(env.Date), nz(env.Runner), nz(env.Run), nz(env.Docker), nz(env.Kernel), nz(env.Kind), nz(env.NodeImage), nz(env.Kubectl), nz(env.Helm),
		nz(env.MetalLBChart), nz(env.MetalLB), nz(env.FRR), nz(env.VIP))
	b.WriteString("## Verdicts\n\n| Cell | Verdict |\n|---|---|\n")
	for _, id := range Order {
		fmt.Fprintf(&b, "| %s | %s |\n", title(id), verdict(cells, id))
	}
	b.WriteString("\n")
	for _, id := range Order {
		fmt.Fprintf(&b, "## %s: %s\n\n", title(id), verdict(cells, id))
		var rows []l82.Row
		for _, c := range cells {
			if c.ID == id {
				rows = c.Rows
			}
		}
		if len(rows) == 0 {
			b.WriteString("No observation.\n\n")
			continue
		}
		b.WriteString("| Case | Observation |\n|---|---|\n")
		for _, r := range rows {
			fmt.Fprintf(&b, "| %s | %s |\n", cell(r.Case), cell(r.Observation))
		}
		b.WriteString("\n")
	}
	b.WriteString("The register row closes only when every cell has a PASS or a FAIL; a FAIL is a measured answer.\n")
	out := b.String()
	if why := l82.Leak(out); why != "" {
		return "", fmt.Errorf("l85: the results hold %s: nothing is written", why)
	}
	return out, nil
}
