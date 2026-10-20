package lab

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/rhwendt/port49/internal/devicemock"
	"github.com/rhwendt/port49/tests/lab/labcreds"
)

type qualCell struct {
	Name string
	Rows []string
}

var qualCells = []qualCell{
	{"token_login", []string{"L1", "L15", "L19"}},
	{"command_permitted", []string{"L10", "L21"}},
	{"command_denied", []string{"L21"}},
	{"accounting", []string{"L6"}},
	{"wrong_credential", []string{"L13"}},
	{"store_unavailable", []string{"L4", "L28"}},
	{"single_connection", []string{"L15", "L73"}},
	{"tls_token_login", []string{"L73"}},
	{"tls_store_unavailable", []string{"L73"}},
	{"tls_unknown_ca", []string{"L73"}},
}

// qualRun is run.json. Cells holds the start time of every cell that ran;
// Results holds every cell's verdict (pass, fail, not_applicable, not_run).
type qualRun struct {
	Platform    string              `json:"platform"`
	LabPlatform string              `json:"lab_platform"`
	Firmware    string              `json:"firmware"`
	Image       string              `json:"image"`
	Commit      string              `json:"commit"`
	Date        string              `json:"date"`
	Transports  []string            `json:"transports"`
	Cells       map[string]string   `json:"cells"`     // cell -> start time, RFC 3339
	Registers   map[string][]string `json:"registers"` // cell -> rows
	BreakGlass  map[string]bool     `json:"break_glass"`
	Results     map[string]string   `json:"results"` // cell -> verdict
}

// qualJunosL18 is the note a Junos command cell carries: the device sends no
// per-command authorization, so there is nothing to measure.
const qualJunosL18 = "L18: Junos sends no per-command authorization; the deny is enforced by the session reply's deny-commands"

// qualDeniedCommand is the command tests/qual/qual-policy.yaml denies on
// platform (a port49 platform name): Junos matches keywords only and `users`
// is no keyword under `show` (decision 27), so it denies the keyword path
// `show system users`; every other platform denies `show users`.
// TestQualDeniedCommandMatchesThePolicy fails if the two drift.
func qualDeniedCommand(platform string) string {
	if platform == "juniper_junos" {
		return "show system users"
	}
	return "show users"
}

// qualProbeCommands are the commands a plain or TLS sequence types: on Junos
// the denied command is not sent, because no authorization of it happens (L18).
func qualProbeCommands(platform string) []string {
	if platform == "juniper_junos" {
		return []string{"show version"}
	}
	return []string{"show version", qualDeniedCommand(platform)}
}

// qualRecord keeps what a profile is generated from (spec §13 decision 52
// ruling 2): event, verdict, reason, packet_fields, the request's service and
// attribute list, the reply's attributes, the accounting record's flags and
// attribute list, and the session's port and privilege. The minted user
// becomes {user}; any other username (a device's own account, such as SR
// Linux's root) is kept, so genprofile can pick the login's own records. The
// address becomes {rem_addr}. port49's tls_refused record keeps its
// diagnosis, transport and tls_outcome alone. Every hash, id, message, other
// unvalidated record and record that is not a validated request is dropped:
// the generator cannot read what is not here.
func qualRecord(r map[string]any, user string) (map[string]any, bool) {
	ev, _ := r["event"].(string)
	switch ev {
	case "redeem", "escalate", "authorize_session", "authorize_command", "account":
	case "unvalidated":
		u, _ := r["unvalidated"].(map[string]any)
		if u == nil || u["diagnosis"] != "tls_refused" {
			return nil, false
		}
		return map[string]any{"event": ev, "diagnosis": u["diagnosis"], "transport": u["transport"], "tls_outcome": u["tls_outcome"]}, true
	default:
		return nil, false
	}
	out := map[string]any{"event": ev}
	for _, k := range []string{"verdict", "reason", "flags", "attribution"} {
		if v, ok := r[k]; ok {
			out[k] = v
		}
	}
	if p, ok := r["packet_fields"].(map[string]any); ok {
		kept := map[string]any{}
		for _, k := range []string{"action", "authen_type", "service", "authen_method", "priv_lvl"} {
			if v, ok := p[k]; ok {
				kept[k] = v
			}
		}
		out["packet_fields"] = kept
	}
	if d, ok := r["device"].(map[string]any); ok {
		out["device"] = map[string]any{"platform": d["platform"], "transport": d["transport"]}
	}
	if s, ok := r["session"].(map[string]any); ok {
		name := s["username"]
		if name == user {
			name = "{user}"
		}
		out["session"] = map[string]any{"port": s["port"], "privilege": s["privilege"], "username": name, "rem_addr": "{rem_addr}"}
	}
	if q, ok := r["request"].(map[string]any); ok {
		out["request"] = map[string]any{"service": q["service"], "raw": templated(q["raw"])}
	}
	if q, ok := r["reply"].(map[string]any); ok {
		out["reply"] = map[string]any{"attributes": q["attributes"]}
	}
	if q, ok := r["record"].(map[string]any); ok {
		out["record"] = map[string]any{"raw": templated(q["raw"]), "priv_lvl": q["priv_lvl"]}
	}
	return out, true
}

func templated(v any) any {
	xs, ok := v.([]any)
	if !ok {
		return v
	}
	out := make([]any, 0, len(xs))
	for _, x := range xs {
		s, _ := x.(string)
		for _, k := range []string{"task_id", "start_time", "stop_time"} {
			if strings.HasPrefix(s, k+"=") {
				s = k + "={" + k + "}"
			}
		}
		out = append(out, s)
	}
	return out
}

// qualRecords maps every record through qualRecord. A record that holds one of
// secrets is refused, naming the record's event and never the secret; so is a
// redeem a lab seed answered, because then the broker's token did not.
func qualRecords(recs []map[string]any, user string, secrets []string) ([]map[string]any, error) {
	var out []map[string]any
	for i, r := range recs {
		b, err := json.Marshal(r)
		if err != nil {
			return nil, err
		}
		if len(labcreds.Contains(b, secrets)) > 0 {
			ev, _ := r["event"].(string)
			return nil, fmt.Errorf("record %d (event %q) holds a credential this run used", i, ev)
		}
		if a, _ := r["auth"].(map[string]any); r["event"] == "redeem" && a != nil && a["method"] == "lab" {
			return nil, fmt.Errorf("record %d: a lab seed answered a redeem, so the broker's token did not", i)
		}
		if k, ok := qualRecord(r, user); ok {
			out = append(out, k)
		}
	}
	return out, nil
}

// qualForbidden are the substrings no committed evidence file may hold; the
// genprofile audit refuses the same list.
var qualForbidden = []string{"_sha256", "password", "secret", "BEGIN "}

// qualGate names, by file, what an evidence file holds that it must not: a
// secret this run used, a forbidden substring, or a long hex or base64 run.
// The messages name files and kinds, never the content.
func qualGate(files map[string][]byte, secrets []string) []string {
	var bad []string
	for name, b := range files {
		if len(labcreds.Contains(b, secrets)) > 0 {
			bad = append(bad, name+": holds a credential this run used")
		}
		for _, f := range qualForbidden {
			if strings.Contains(string(b), f) {
				bad = append(bad, fmt.Sprintf("%s: holds %q", name, f))
			}
		}
		for _, h := range l73SummaryLeaks(string(b)) {
			bad = append(bad, name+": holds "+h)
		}
	}
	return bad
}

// qualDenyProven checks the cell's denied command was refused by the policy's
// deny: a denied authorize_command whose request vector is the command, with
// reason no_permit_dominates_deny. A privilege_exceeded or no_rule_matched
// refusal of it fails.
func qualDenyProven(recs []map[string]any, denied string) error {
	var proven bool
	for _, r := range recs {
		if r["event"] != "authorize_command" {
			continue
		}
		q, _ := r["request"].(map[string]any)
		vec, _ := q["vector"].([]any)
		words := make([]string, 0, len(vec))
		for _, w := range vec {
			s, _ := w.(string)
			words = append(words, s)
		}
		if strings.Join(words, " ") != denied {
			continue
		}
		if r["verdict"] == "permit" {
			return fmt.Errorf("%q was permitted", denied)
		}
		if r["reason"] != "no_permit_dominates_deny" {
			return fmt.Errorf("%q was refused for reason %v, not no_permit_dominates_deny", denied, r["reason"])
		}
		proven = true
	}
	if !proven {
		return fmt.Errorf("no authorize_command record denies %q", denied)
	}
	return nil
}

// qualPermitProven checks command was permitted by an authorize_command record.
func qualPermitProven(recs []map[string]any, command string) error {
	for _, r := range recs {
		if r["event"] != "authorize_command" || r["verdict"] != "permit" {
			continue
		}
		q, _ := r["request"].(map[string]any)
		vec, _ := q["vector"].([]any)
		words := make([]string, 0, len(vec))
		for _, w := range vec {
			s, _ := w.(string)
			words = append(words, s)
		}
		if strings.Join(words, " ") == command {
			return nil
		}
	}
	return fmt.Errorf("no authorize_command record permits %q", command)
}

// qualConfigYAML is the conformance run's port49d.yaml (decision 52 ruling 5):
// the lab file with the slice's broker block reading policyPath, the shared
// fragment merged in, and a lab: block holding fault_file alone, so no seed
// and no lab instrument can answer a request.
func qualConfigYAML(lab, broker, fragment, policyPath string) (string, error) {
	const want = "  policy_file: tests/lab/slice/policy.yaml\n"
	if !strings.Contains(broker, want) {
		return "", errors.New("tests/lab/slice/broker.yaml no longer reads tests/lab/slice/policy.yaml")
	}
	broker = strings.Replace(broker, want, "  policy_file: "+policyPath+"\n", 1)
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(lab+"\n"+broker), &doc); err != nil {
		return "", err
	}
	if len(doc.Content) == 0 {
		return "", errors.New("the lab config is empty")
	}
	m := doc.Content[0]
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == "lab" {
			m.Content[i+1] = &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{
				{Kind: yaml.ScalarNode, Value: "fault_file"}, {Kind: yaml.ScalarNode, Value: qualFaultFile}}}
		}
	}
	out, err := yaml.Marshal(&doc)
	if err != nil {
		return "", err
	}
	merged, err := devicemock.MergeFragment(out, []byte(fragment))
	return string(merged), err
}

// qualFaultFile is the file whose content port49d reads as a fault to inject.
const qualFaultFile = "/tmp/port49-lab-qual-fault"

// qualNoteGate names what the results note holds that it must not: a secret
// this run used, or a hash value under a *_sha256 key. Kinds only, never values.
func qualNoteGate(note string, secrets []string) []string {
	var bad []string
	if len(labcreds.Contains([]byte(note), secrets)) > 0 {
		bad = append(bad, "the note holds a credential this run used")
	}
	for _, k := range l72HashValueLeaks(note) {
		bad = append(bad, "the note holds a hash value under "+k)
	}
	return bad
}

// qualCommandCells grades command_permitted and command_denied from one
// login's records. Junos sends no command authorization (L18), so both are
// not_applicable: its refusals print text too, so output proves nothing.
func qualCommandCells(platform string, recs []map[string]any) (permitted, denied, why string) {
	if platform == "juniper_junos" {
		return "not_applicable", "not_applicable", qualJunosL18
	}
	permitted, denied = "pass", "pass"
	if err := qualPermitProven(recs, "show version"); err != nil {
		permitted, why = "fail", err.Error()
	}
	if err := qualDenyProven(recs, qualDeniedCommand(platform)); err != nil {
		denied, why = "fail", strings.TrimSpace(why+" "+err.Error())
	}
	return permitted, denied, why
}

// qualWriteEvidence gates the files and the note together, and only then
// replaces dir with files. Any hit returns its kinds and touches nothing.
func qualWriteEvidence(dir string, files map[string][]byte, note string, secrets []string) []string {
	bad := qualGate(files, secrets)
	bad = append(bad, qualNoteGate(note, secrets)...)
	if len(bad) > 0 {
		sort.Strings(bad)
		return bad
	}
	if err := os.RemoveAll(dir); err != nil {
		return []string{err.Error()}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return []string{err.Error()}
	}
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			return []string{err.Error()}
		}
	}
	return nil
}
