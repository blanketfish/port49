// Package l39 holds the pure parts of lab entry L39 (b) and (c) (spec §15): which source address
// port49d sees when a device dials it behind a Kubernetes NodePort Service, under each
// externalTrafficPolicy and at each worker, and on the host network. The reading of port49d's log,
// the verdicts and the results. The harness (tests/lab/l39_test.go, tag lab) measures and records;
// this package decides and renders, so a results file is built from the cells and never typed by hand.
//
// The results file is an uploaded CI artifact and will be public: addresses of the lab's own private
// networks, PASS or FAIL, reason codes and versions. Results refuses text that looks like a key, a
// credential or a password; a reason code containing the word is written without it.
package l39

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"github.com/blanketfish/port49/tests/shapes/l82"
)

// Order is the cells' order in the results.
var Order = []string{"b1", "b2", "b3", "b4", "c"}

func title(id string) string {
	return map[string]string{
		"b1": "(b1) NodePort, externalTrafficPolicy: Cluster, dialled at the node running the pod",
		"b2": "(b2) NodePort, externalTrafficPolicy: Cluster, dialled at a node not running the pod",
		"b3": "(b3) NodePort, externalTrafficPolicy: Local, dialled at the node running the pod",
		"b4": "(b4) NodePort, externalTrafficPolicy: Local, dialled at a node not running the pod (an observation)",
		"c":  "(c) hostNetwork: true on a lab-only privileged namespace, dialled at its node",
	}[id]
}

// Outcome is what one dial came to: what the device's client printed and what port49d's log said.
type Outcome struct {
	Client   string // the l85client probe's answer: pass or fail:<kind>
	Redeemed bool   // the decision log holds token_redeemed for the dial
	Reasons  []string
	Sources  []string // the addresses port49d recorded as the connection's source
	Device   string   // the device's own address
}

// Passed is the dial redeemed: the client got a PASS, the log says the credential was redeemed, and
// the one source address port49d recorded is the device's own.
func (o Outcome) Passed() bool {
	return o.Client == "pass" && o.Redeemed && o.Device != "" && len(o.Sources) == 1 && o.Sources[0] == o.Device
}

// Observed is b4's verdict: the outcome was read and is recorded, neither a pass nor a fail.
const Observed = "OBSERVED"

// SourceCase is the row that records the source addresses port49d logged.
const SourceCase = "port49d's decision log: source addresses recorded"

// Judge is a cell's verdict. For b1, b2, b3 and c it is PASS iff the device-binding check passed
// (the credential was redeemed and the source port49d recorded is the device's own address); a
// FAIL is the measured answer. b4 is an observation, recorded either way: it is OBSERVED when the dial's
// outcome was read (a redeem, a refusal or no answer at all) and FAIL only when nothing was read.
func Judge(id string, o Outcome) string {
	if id == "b4" {
		if o.Client != "" {
			return Observed
		}
		return l82.Fail
	}
	if o.Passed() {
		return l82.Pass
	}
	return l82.Fail
}

var reasonRe = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// ParseLog reads port49d's JSON log lines (kubectl logs) for the reasons and the source addresses of
// its decision records: `reason`, `device.nas` and `unvalidated.source`, each a closed shape. It
// reads no other field, so nothing else can reach the results. Lines that are not JSON are skipped.
func ParseLog(logs string) (reasons, sources []string) {
	rs, ss := map[string]bool{}, map[string]bool{}
	for _, ln := range strings.Split(logs, "\n") {
		ln = strings.TrimSpace(ln)
		if !strings.HasPrefix(ln, "{") {
			continue
		}
		var rec struct {
			Reason string `json:"reason"`
			Device *struct {
				NAS string `json:"nas"`
			} `json:"device"`
			Unvalidated *struct {
				Source string `json:"source"`
			} `json:"unvalidated"`
		}
		if json.Unmarshal([]byte(ln), &rec) != nil {
			continue
		}
		if reasonRe.MatchString(rec.Reason) && len(rec.Reason) <= 48 {
			rs[rec.Reason] = true
		}
		for _, s := range []string{deviceNAS(rec.Device), unvalidatedSource(rec.Unvalidated)} {
			if ap, err := netip.ParseAddrPort(s); err == nil {
				ss[ap.Addr().String()] = true
			} else if a, err := netip.ParseAddr(s); err == nil {
				ss[a.String()] = true
			}
		}
	}
	return keys(rs), keys(ss)
}

func deviceNAS(d *struct {
	NAS string `json:"nas"`
}) string {
	if d == nil {
		return ""
	}
	return d.NAS
}

func unvalidatedSource(u *struct {
	Source string `json:"source"`
}) string {
	if u == nil {
		return ""
	}
	return u.Source
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Redeemed is whether the reasons hold token_redeemed.
func Redeemed(reasons []string) bool {
	for _, r := range reasons {
		if r == "token_redeemed" {
			return true
		}
	}
	return false
}

// Words renders reason codes for the results. The leak filter refuses the word for a credential, which
// token_redeemed carries, so the code is written without its "token_" prefix: "redeemed".
func Words(reasons []string) string {
	if len(reasons) == 0 {
		return "none"
	}
	out := make([]string, len(reasons))
	for i, r := range reasons {
		out[i] = strings.TrimPrefix(r, "token_")
	}
	return strings.Join(out, ", ")
}

// Addrs renders addresses, or says none were recorded.
func Addrs(a []string) string {
	if len(a) == 0 {
		return "none recorded"
	}
	return strings.Join(a, ", ")
}

// HostNetwork is the lab-only change that puts port49d on its node's network, as a JSON patch of the
// StatefulSet's pod template (`kubectl patch --type=json`). It lives here and never in deploy/helm: the
// chart offers no host networking (spec §13 decision 54 ruling 5). ClusterFirstWithHostNet keeps the
// etcd Service names resolvable. The chart's pod-level sysctl (net.ipv4.ip_unprivileged_port_start) is
// removed: Kubernetes refuses a pod with sysctls on the host network (run 41844736221: "sysctls[0].name:
// may not be specified when 'hostNetwork' is true"). The node's own value then governs binding port 49
// as the non-root user; a kind node's is 0, and if it is not the pod fails to bind and the cell says so.
func HostNetwork() string {
	return `[{"op":"add","path":"/spec/template/spec/hostNetwork","value":true},` +
		`{"op":"add","path":"/spec/template/spec/dnsPolicy","value":"ClusterFirstWithHostNet"},` +
		`{"op":"remove","path":"/spec/template/spec/securityContext/sysctls"}]`
}

// PinToNode is the patch that pins the pod template to the node named host.
func PinToNode(host string) (string, error) {
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*$`).MatchString(host) {
		return "", fmt.Errorf("l39: the node name %q", host)
	}
	return `{"spec":{"template":{"spec":{"nodeSelector":{"kubernetes.io/hostname":"` + host + `"}}}}}`, nil
}

// ServiceValues is the stack's `service:` values: the TACACS+ Service as a NodePort under policy.
func ServiceValues(policy string) (string, error) {
	if policy != "Cluster" && policy != "Local" {
		return "", fmt.Errorf("l39: externalTrafficPolicy %q", policy)
	}
	return "service:\n  type: NodePort\n  externalTrafficPolicy: " + policy + "\n", nil
}

// Env is what the results record about the run.
type Env struct {
	Date, Runner, Run, Docker, Kernel, Kind, NodeImage, Kubectl, Helm string
	KubeProxy                                                         string
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
			if c.Verdict == Observed {
				for _, r := range c.Rows {
					if r.Case == SourceCase {
						return Observed + ", source " + r.Observation
					}
				}
			}
			return c.Verdict
		}
	}
	return l82.NotRun
}

// Results is the results file for the CI artifact, built from cells and nothing else. It fails,
// writing nothing, on a cell it does not know or if any text in it looks like a key. A cell never
// run is NOT RUN, which the harness fails on.
func Results(env Env, cells []l82.Cell) (string, error) {
	known := map[string]bool{}
	for _, id := range Order {
		known[id] = true
	}
	for _, c := range cells {
		if !known[c.ID] {
			return "", fmt.Errorf("l39: a cell %q that is not one of the entry's", c.ID)
		}
	}
	var b strings.Builder
	b.WriteString("# L39 (b) and (c): the source address port49d sees behind a Kubernetes Service and on the host network (kind)\n\n")
	b.WriteString("Generated by `make lab-l39` (tests/lab/l39_kind_test.go) from the cells below; edit the harness, not this file.\n\n")
	fmt.Fprintf(&b, "- Date: %s\n- Platform: %s\n- Run: %s\n- Capture pointer: this run's artifact `lab-l39` (l39-results.md, l39-cells.json), kept as L39-kind-cells.json under tests/lab/results\n- Docker: %s\n- Kernel: %s\n- kind: %s\n- Node image: %s\n- kubectl: %s\n- helm: %s\n- kube-proxy: %s\n\n",
		nz(env.Date), nz(env.Runner), nz(env.Run), nz(env.Docker), nz(env.Kernel), nz(env.Kind), nz(env.NodeImage), nz(env.Kubectl), nz(env.Helm), nz(env.KubeProxy))
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
		return "", fmt.Errorf("l39: the results hold %s: nothing is written", why)
	}
	return out, nil
}
