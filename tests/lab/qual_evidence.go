package lab

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

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
	{"tls_single_connection", []string{"L15", "L73"}},
	{"tls_denied_command", []string{"L80"}},
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
	Results     map[string]string   `json:"results"` // cell -> verdict: pass, fail, not_applicable, not_run; observed for L80's measurement cell
	// CommandAuthorization is what a TLS login cell's commands did at port49
	// (qualTLSCommands): sent, not_sent or not_applicable. genprofile reads it.
	CommandAuthorization map[string]string `json:"command_authorization"`
	// DeniedCommandRan is L80's cell: whether the denied command ran.
	DeniedCommandRan map[string]bool `json:"denied_command_ran"`
	// DeniedCommandAsked is whether that command reached port49 as an
	// authorize_command, so the page says who refused it (review M2).
	DeniedCommandAsked map[string]bool `json:"denied_command_asked"`
	// TLSServerSingleConnectOffered is whether the build under test offers
	// this platform single-connect over per-request TLS
	// (platform.TLSServerSingleConnect; decision 50 ruling 20). The flag is
	// inside the ciphertext, so genprofile grades honored or ignored from it
	// and the header-only connections.
	TLSServerSingleConnectOffered bool `json:"tls_server_single_connect_offered"`
	// Port49d is what bin/port49d was built from (go version -m). The TLS
	// cells run only on a clean build of the harness tree's HEAD, so the
	// offer above is the binary's own (review I2).
	Port49d buildVCS `json:"port49d"`
	// TLSCaptureStartedClean is set once no connection was open before or at
	// tls_token_login's capture's start: the capture sees only connections
	// whose SYN it caught, so the gauge decides (port49_connections{open} 0
	// before, and again once the capture is live). genprofile grades honored
	// or ignored only when it is true (review O1, R3).
	TLSCaptureStartedClean bool `json:"tls_capture_started_clean"`
}

// qualJunosL18 is the note a Junos command cell carries: the device sends no
// per-command authorization, so there is nothing to measure.
const qualJunosL18 = "L18: Junos sends no per-command authorization; the deny is enforced by the session reply's deny-commands"

// qualSRLinuxL76 is the note an SR Linux command cell carries (L76 cell b: one
// authorize_session, no authorize_command; the schema has no TACACS+ authorization method).
const qualSRLinuxL76 = "L76: SR Linux sends no per-command authorization; the session reply's role bounds the session"

// qualNoCommandAuthWhy is the note for a platform qualNoCommandAuth names.
func qualNoCommandAuthWhy(platform string) string {
	if platform == "nokia_srlinux" {
		return qualSRLinuxL76
	}
	return qualJunosL18
}

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

// qualNoCommandAuth is the platforms whose devices send no per-command
// authorization: Junos (L18) and SR Linux (L76 cell b: no authorize_command).
func qualNoCommandAuth(platform string) bool {
	return platform == "juniper_junos" || platform == "nokia_srlinux"
}

// qualProbeCommands are the commands a plain or TLS sequence types: where the
// device sends no command authorization the denied command is not sent, because
// no authorization of it happens.
func qualProbeCommands(platform string) []string {
	if qualNoCommandAuth(platform) {
		return []string{"show version"}
	}
	return []string{"show version", qualDeniedCommand(platform)}
}

// qualRecord keeps what a profile is generated from (spec §13 decision 52
// ruling 2): ts (genprofile cuts the records into cells by it), event, verdict, reason, packet_fields, the request's service and
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
		out := map[string]any{"event": ev, "diagnosis": u["diagnosis"], "transport": u["transport"], "tls_outcome": u["tls_outcome"]}
		keepTS(out, r)
		return out, true
	default:
		return nil, false
	}
	out := map[string]any{"event": ev}
	keepTS(out, r)
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

// keepTS copies the record's time, the one thing that cuts records into cells.
func keepTS(out, r map[string]any) {
	if ts, ok := r["ts"]; ok {
		out["ts"] = ts
	}
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
		// A device's own account records carry paths and names longer than the
		// gate's run length (Junos 23.4's telemetry commit: a gNMI resource path).
		// Neither a secret nor of use to the generator; the gate stays strict.
		s = l73LongHex.ReplaceAllString(s, "{long_run}")
		s = l73LongB64.ReplaceAllString(s, "{long_run}")
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
		if strings.HasSuffix(name, "-debug.txt") {
			bad = append(bad, qualDebugGate(name, b)...)
			continue
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

// qualDebugGate is the gate for a device-debug evidence file (QUAL-DEBUG and
// L80 `-debug.txt`), which is deviceDebugFilter.Keep's output. That text may say
// "password" or "secret" (its values are redacted), so it is not refused for the
// words; it is refused for what Keep drops or masks and must therefore not hold:
// a payload word, a hex layout or a long run, a key, password or secret
// followed by anything but <redacted>, a $9$ or crypt hash, a `_sha256` key and
// a PEM block. The messages name the file and the kind, never the content.
func qualDebugGate(name string, b []byte) []string {
	var bad []string
	for _, f := range []string{"_sha256", "BEGIN "} {
		if strings.Contains(string(b), f) {
			bad = append(bad, fmt.Sprintf("%s: holds %q", name, f))
		}
	}
	for _, ln := range strings.Split(string(b), "\n") {
		if !ddNoteKeptSafe(ln) {
			bad = append(bad, name+": holds a payload word, a hex layout or a long run")
			break
		}
	}
	for _, ln := range strings.Split(string(b), "\n") {
		redacted := ln
		for _, s := range ddShapeRedact {
			redacted = s.re.ReplaceAllString(redacted, s.repl)
		}
		if redacted != ln {
			bad = append(bad, name+": holds a key, password, secret or hash that is not redacted")
			break
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

// qualVector is an authorize_command record's request vector as one command line.
func qualVector(r map[string]any) string {
	q, _ := r["request"].(map[string]any)
	vec, _ := q["vector"].([]any)
	words := make([]string, 0, len(vec))
	for _, w := range vec {
		s, _ := w.(string)
		words = append(words, s)
	}
	return strings.Join(words, " ")
}

// qualCommandRecords are recs' authorize_command records for command.
func qualCommandRecords(recs []map[string]any, command string) []map[string]any {
	var out []map[string]any
	for _, r := range recs {
		if r["event"] == "authorize_command" && qualVector(r) == command {
			out = append(out, r)
		}
	}
	return out
}

// The connection modes a TLS login verdict names first.
const (
	qualPerRequest       = "per-request (the device default)"
	qualSingleConnection = "single-connection on"
)

// qualTLSCommands is what a TLS login cell's commands did at port49, from its
// records alone: sent when the permitted and the denied command each have an
// authorize_command record (and then each must be proven), not_sent when
// neither has one (NX-OS 10.6(2)F over per-request TLS, L73 cell a, whose one
// authorize_command is for `end`), not_applicable where the device sends no
// per-command authorization (qualNoCommandAuth). One without the other is sent
// with a problem: never not_sent.
func qualTLSCommands(platform string, recs []map[string]any) (state string, problems []string) {
	if qualNoCommandAuth(platform) {
		return "not_applicable", nil
	}
	denied := qualDeniedCommand(platform)
	if len(qualCommandRecords(recs, "show version")) == 0 && len(qualCommandRecords(recs, denied)) == 0 {
		return "not_sent", nil
	}
	if err := qualPermitProven(recs, "show version"); err != nil {
		problems = append(problems, err.Error())
	}
	if err := qualDenyProven(recs, denied); err != nil {
		problems = append(problems, err.Error())
	}
	return "sent", problems
}

// qualTLSLoginVerdict grades a TLS login cell (a token login typing
// qualProbeCommands) on what arrived at port49, naming its connection mode
// first. firsts are each command's first output line, masked. A login whose
// commands never reached port49 passes as a login and says plainly that
// command authorization was not sent: a device fact, not a pass for it.
func qualTLSLoginVerdict(mode, platform, state string, problems, firsts []string) (result, why string) {
	if len(problems) > 0 {
		return "fail", mode + ": " + strings.Join(problems, "; ")
	}
	cmds := qualProbeCommands(platform)
	said := ""
	for i, f := range firsts {
		said += fmt.Sprintf("; `%s` said %q", cmds[min(i, len(cmds)-1)], f)
	}
	switch state {
	case "sent":
		return "pass", fmt.Sprintf("%s: a token login over RFC 9887; `show version` permitted and `%s` denied by port49 (authorize_command records); the stop record arrived.",
			mode, qualDeniedCommand(platform))
	case "not_sent":
		// "login only" first: run.json says pass, and that pass is the login's (review M1).
		return "pass", fmt.Sprintf("%s: login only: a token login over RFC 9887 and its stop record arrived; command authorization not sent: port49 received no "+
			"authorize_command for `show version` or `%s` (a device fact, as L73 cell a; not a pass for command authorization over TLS)%s.",
			mode, qualDeniedCommand(platform), said)
	}
	return "pass", fmt.Sprintf("%s: a token login over RFC 9887 ran `show version`, and its stop record arrived; %s.", mode, qualNoCommandAuthWhy(platform))
}

// qualDeniedCommandVerdict grades L80's cell: denied, the command the qual
// policy denies, typed alone over per-request TLS. out is its output, recs
// port49's records for the login. The cell is a measurement, not a
// qualification check, so a measured outcome is "observed", never "pass"
// (ruling 2026-10-21): a bypass never reads as a pass. The line states the
// outcome first, then the first output line and the record counts. ran is
// whether the first line shows the command ran (qualRan). It fails when port49
// permitted the command, when it ran although port49 denied it, and when there
// is no output to read.
func qualDeniedCommandVerdict(denied, out string, recs []map[string]any) (result string, ran bool, why string) {
	ran, says := qualRan(out)
	if says == "no output" {
		return "fail", false, fmt.Sprintf("`%s` gave no output, so whether it ran is unmeasured", denied)
	}
	asked := qualCommandRecords(recs, denied)
	others := -len(asked)
	for _, r := range recs {
		if r["event"] == "authorize_command" {
			others++
		}
	}
	verdicts := ""
	for _, r := range asked {
		v, _ := r["verdict"].(string)
		verdicts += " " + v
	}
	counts := fmt.Sprintf("%d authorize_command records for `%s`", len(asked), denied)
	if verdicts != "" {
		counts += " (" + strings.TrimSpace(verdicts) + ")"
	}
	counts += fmt.Sprintf(", %d for other commands", others)
	for _, r := range asked {
		if r["verdict"] == "permit" {
			return "fail", ran, fmt.Sprintf("port49 permitted `%s`, which the qual policy denies (first line %q; %s)", denied, says, counts)
		}
	}
	switch {
	case len(asked) > 0 && ran:
		return "fail", true, fmt.Sprintf("`%s` ran although port49 denied it (first line %q; %s)", denied, says, counts)
	case len(asked) > 0:
		return "observed", false, fmt.Sprintf("denied command refused: port49 denied `%s` and the device refused it (first line %q; %s).", denied, says, counts)
	case ran:
		return "observed", true, fmt.Sprintf("**denied command ran; port49 never asked (the device's local method, presumed)**: `%s` ran with no authorization request for it "+
			"reaching port49, so the qual policy's deny was not enforced over per-request TLS (first line %q; %s).", denied, says, counts)
	}
	return "observed", false, fmt.Sprintf("denied command refused: the device refused `%s` with no authorization request for it reaching port49 (first line %q; %s).",
		denied, says, counts)
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
// login's records. Junos (L18) and SR Linux (L76 cell b) send no command
// authorization, so both are not_applicable while the records hold no
// authorize_command: their refusals print text too, so output proves nothing.
// One that sends some fails both, so a firmware that starts asking port49 is
// graded, not hidden (final review M2).
func qualCommandCells(platform string, recs []map[string]any) (permitted, denied, why string) {
	if qualNoCommandAuth(platform) {
		n := 0
		for _, r := range recs {
			if r["event"] == "authorize_command" {
				n++
			}
		}
		if n > 0 {
			return "fail", "fail", fmt.Sprintf("the device sent %d authorize_command record(s), and %s is graded not_applicable only while it sends none: "+
				"grade its command cells like any other platform's", n, platform)
		}
		return "not_applicable", "not_applicable", qualNoCommandAuthWhy(platform)
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

// qualRefusedMarks are the device texts, beyond l73RefusalMarks, that say a
// command was refused: IOS XR prints "% This command is not authorized" when
// a session's task groups, or its absent attributes, forbid the command
// (measured in TestQualify on XRd 26.1.1, 2026-10-21), Junos "error:", IOS XE "% Authorization failed.", EOS "% Authorization denied for command" and SR Linux "Error: No authorization to execute command" (the texts in tests/lab/results).
// NX-OS's own role refuses with "% Permission denied for the role" (Junos says "error: permission
// denied"), Junos also prints "unknown command." and "syntax error." under a caret line, EOS
// "% Unavailable command" and IOS XE "% Unknown command or computer name": without them L80's cell
// would read a local refusal as a denied command that ran (task 14b review I1).
var qualRefusedMarks = []string{"This command is not authorized", "error:", "Authorization denied", "Authorization failed",
	"No authorization to execute", "Permission denied", "unknown command", "syntax error", "Unavailable command"}

// qualRan is whether a command's output shows the command ran: it is not
// empty and its first line is no refusal. A login that was answered with a
// refusal ran nothing, however many records it left.
func qualRan(out string) (ran bool, says string) {
	first := ""
	for _, ln := range strings.Split(strings.ReplaceAll(out, "\r", ""), "\n") {
		// Junos points a caret at the bad word on a line of its own, above the refusal.
		if first = strings.TrimSpace(ln); first != "" && first != "^" {
			break
		}
	}
	if first == "" {
		return false, "no output"
	}
	// Case-insensitive: IOS XE capitalises "Authorization failed", NX-OS prints "authorization failed".
	low := strings.ToLower(first)
	for _, m := range append(append([]string{}, qualRefusedMarks...), l73RefusalMarks...) {
		if strings.Contains(low, strings.ToLower(m)) {
			return false, first
		}
	}
	return true, first
}

// qualRetryUnreached runs login; on XRd it repeats a login the device refused
// with an authentication error, no faster than the sshd rate limit allows,
// until within has passed, unless refused() says port49 denied one. XR keeps a server it could not reach marked dead
// for a while, so the first logins after port49d returns are answered locally
// and never reach it. Every other platform runs login once. It returns the
// attempts made and the last error.
func qualRetryUnreached(platform string, login func() error, refused func() bool, within time.Duration, sleep func(time.Duration)) (int, error) {
	attempts := 0
	var waited time.Duration
	for {
		attempts++
		err := login()
		if err != nil && refused() {
			// port49 denied it: a real refusal, never to be retried into a pass.
			return attempts, fmt.Errorf("port49 denied a login the device sent it (attempt %d): %w", attempts, err)
		}
		if err == nil || platform != "cisco_xrd" || !strings.Contains(err.Error(), "unable to authenticate") || waited >= within {
			// A deny record can land after the attempt it answered was checked:
			// look once more over the whole window before a success stands.
			if err == nil && attempts > 1 && refused() {
				return attempts, fmt.Errorf("port49 denied a login the device sent it, and a later attempt (%d) succeeded", attempts)
			}
			return attempts, err
		}
		sleep(l73UnreachedEvery)
		waited += l73UnreachedEvery
	}
}

// qualDenied is whether recs hold a denied redeem: the proof a device sent
// port49d a credential, and port49d refused it.
func qualDenied(recs []map[string]any) bool {
	for _, r := range recs {
		if r["event"] == "redeem" && r["verdict"] == "deny" {
			return true
		}
	}
	return false
}

// qualStoreVerdict grades a store_unavailable cell (plain or TLS) from the
// token login's error and the cell's records: "pass" only when the login
// failed, no redeem was permitted, and port49 logged `redeem deny
// store_unavailable` for user. A login that failed for any other reason (the
// fault file not taking, the device never asking) measured nothing about the
// store (final review M1). why is "" on a pass.
func qualStoreVerdict(tokErr error, recs []map[string]any, user string) (result, why string) {
	storeDeny := false
	for _, r := range recs {
		if r["event"] != "redeem" {
			continue
		}
		sess, _ := r["session"].(map[string]any)
		switch {
		case r["verdict"] == "permit":
			return "fail", "a redeem was permitted with the store unavailable:"
		case r["verdict"] == "deny" && r["reason"] == "store_unavailable" && sess["username"] == user:
			storeDeny = true
		}
	}
	switch {
	case tokErr == nil:
		return "fail", "a token login succeeded with the store unavailable"
	case !storeDeny:
		return "fail", "the token login failed but port49d logged no redeem deny store_unavailable for it, so the store fault was not what refused it:"
	}
	return "pass", ""
}

// qualOperatorSection is what an operator of platform must know that the cells'
// verdicts alone do not say; "" for a platform with nothing to add. It is
// written by the harness so a regenerated note keeps it.
func qualOperatorSection(platform string) string {
	switch platform {
	case "cisco_iosxr":
		return qualOperatorXR
	case "nokia_srlinux":
		return qualOperatorSRLinux
	}
	return ""
}

// qualOperatorSRLinux is SR Linux's section. The device sends no per-command
// authorization (L76 cell b), so no port49 rule narrows a session: operator
// renders readonly's level, not admin's, until a level between 1 and 15 is
// measured (final review I1; fails restrictive, as on XR).
const qualOperatorSRLinux = `

## Operator requirements on SR Linux

- **port49 must render priv-lvl.** platform_set 1.3.0 has no ` + "`nokia_srlinux`" + ` adapter, so the generic adapter serves it and renders no attribute, and SR Linux then refuses every login: port49 permits the session and the device refuses the SSH login (QUAL-SR-Linux-26.7.2-519-nokia_srlinux-no-priv-lvl.md). This run passes with ` + "`platforms: nokia_srlinux`" + ` in tests/qual/qual-policy.yaml; L76 cells (a) and (h) measured the device reading ` + "`priv-lvl`" + ` 15 and 1 as p49-admin and p49-read. Add to the policy file:

` + "```yaml" + `
platforms:
  nokia_srlinux:
    privilege:
      readonly: ["priv-lvl=1"]
      operator: ["priv-lvl=1"]
      admin: ["priv-lvl=15"]
` + "```" + `

- **operator is read-only on SR Linux until a level between 1 and 15 is measured.** Port49 command permit and deny rules never apply on SR Linux, because the device sends no per-command authorization (L76 cell b): the session role, chosen by ` + "`priv-lvl`" + `, is the only bound. At 15 an operator would be device admin with nothing to narrow it, so operator renders level 1 (p49-read), as readonly does.
- **Set ` + "`priv-lvl-authorization true`" + ` on the device.** Its default is false, and then port49 is never asked to authorize (L76 cell i: 0 authorization requests); the YANG says the session then gets full admin access (srl_nokia-aaa.yang:254; YANG-stated, not measured).
`

// qualOperatorXR is XR's section.
const qualOperatorXR = `

## Operator requirements on XR

- **port49 must render priv-lvl.** This run passes with ` + "`platforms: cisco_iosxr`" + ` in tests/qual/qual-policy.yaml, which renders ` + "`priv-lvl=15`" + ` for the admin role. Without it (platform_set 1.3.0 has no cisco_iosxr adapter, so the generic adapter renders no attribute) XRd logs the token user in and then refuses every command locally with ` + "`% This command is not authorized`" + `, asking port49 about none (QUAL-XRd-control-plane-26.1.1-cisco_xrd-no-priv-lvl.md). That case fails safe: commands are refused, not allowed. ` + "`priv-lvl=15`" + ` alone was enough; no other attribute was tried. Add to the policy file:

` + "```yaml" + `
platforms:
  cisco_iosxr:
    privilege:
      readonly: ["priv-lvl=1"]
      operator: ["priv-lvl=1"]
      admin: ["priv-lvl=15"]
` + "```" + `

- **Command authorization must be configured on the device**: ` + "`aaa authorization commands default group <port49 group> local`" + `, as tests/lab/configs/xrd-startup.cfg has it. Without that line XR never asks port49 about a command, so no role rule applies and ` + "`priv-lvl`" + ` is the only bound (admin's 15 is whatever XR grants level 15, unmeasured).
- **Only level 15 was shown.** Level 1 (readonly, operator) was not measured. That it grants no more than the role says is reasoning, not measurement, and holds only with command authorization configured: XR then either refuses locally (fails safe) or asks port49, whose role bounds the command.
- **Break-glass fails when port49 answers ERROR** (its store is unavailable), over TCP and TLS: the cells ` + "`store_unavailable`" + ` and ` + "`tls_store_unavailable`" + ` record break-glass logged in false (L73 cell i: ok false in 860 ms), as on IOS XE 17.18.02. With the store down nobody logs in to this device by SSH; keep a path that does not depend on port49 answering.
- In this run ` + "`command_denied`" + ` passes through port49: ` + "`show users`" + ` has an authorize_command record denied with no_permit_dominates_deny.
`

// qualL80Applies is whether platform's firmware is the image spec §15 L80
// names: NX-OS 10.6(2)F. Any other image's denied-command cell is recorded in
// its QUAL note alone, never in an L80 note, and never over the closed one.
func qualL80Applies(platform, firmware string) bool {
	return platform == "cisco_nxos" && firmware == "Nexus 9300v 10.6(2)F"
}

// qualL80Note is the results note for spec §15 L80 from a TestQualify run's
// verdict lines: the per-request login's and the denied-command cell's, so
// the row can be closed on a note the harness wrote. ok is false when the
// cell did not run or was not measured (no observed line for it).
// qualL80Fix is what the L80 note says of decision 50 ruling 20: whether
// the build under test offers this platform single-connect over TLS, and the
// committed before-the-fix baseline directory ("" when none is committed).
type qualL80Fix struct {
	Offered  bool
	Baseline string
}

func qualL80Note(notes []string, evidence string, fix qualL80Fix) (claim, obs string, ok bool) {
	var lines []string
	var tok, den string
	for _, n := range notes {
		if strings.HasPrefix(n, "- `tls_token_login` ") || strings.HasPrefix(n, "- `tls_denied_command` ") {
			lines = append(lines, n)
			if strings.HasPrefix(n, "- `tls_token_login` ") {
				tok = n
			} else {
				den = n
			}
			ok = ok || (strings.HasPrefix(n, "- `tls_denied_command` ") && strings.Contains(n, "**observed**"))
		}
	}
	if ok {
		claim = "Whether a command port49's policy denies runs over per-request TLS (RFC 9887 with no single-connection, the device default) " +
			"when the device sends port49 no command authorization (policy engine spec §15 L80), measured by TestQualify's `tls_denied_command` " +
			"cell under tests/qual/qual-policy.yaml: one login typing only the denied command, graded from its first output line and port49's records."
		obs = strings.Join(lines, "\n") + fmt.Sprintf("\n\nEvidence: `tests/lab/evidence/%s/` (the cells' whitelisted records in decisions.jsonl; "+
			"the denied-command login's connections in tls_denied_command.tls.json).", evidence)
	} else if qualL80ObservedByTokenLogin(tok, den, fix) {
		// Under ruling 20 the device sends command authorization over per-request TLS, so
		// tls_denied_command is not run and tls_token_login holds the observation.
		ok = true
		claim = "Whether a command port49's policy denies runs on NX-OS 10.6 over per-request TLS (RFC 9887) when port49 offers the device " +
			"single-connect (policy engine spec §15 L80; decision 50 ruling 20), measured by TestQualify's `tls_token_login` cell under " +
			"tests/qual/qual-policy.yaml: a login typing `show version` and the denied command, graded from port49's authorize_command records."
		obs = strings.Join(lines, "\n") + fmt.Sprintf("\n\nEvidence: `tests/lab/evidence/%s/` (the cells' whitelisted records in decisions.jsonl; "+
			"the login's connections in tls_token_login.tls.json). Before the fix the device sent command authorization for some commands only, "+
			"so commands ran with no authorize_command record (the baseline evidence below); with the offer it asks about every command and "+
			"port49's deny holds (this cell, and the fixed arm below).", evidence)
	}
	if !ok {
		return "", "", false
	}
	if fix.Offered && fix.Baseline != "" {
		obs += fmt.Sprintf("\n\nUnder spec §13 decision 50 ruling 20 this build offers the device single-connect over "+
			"per-request TLS (platform.TLSServerSingleConnect), so a request NX-OS writes behind an accounting record "+
			"is read and decided on the same connection. The before-the-fix evidence, the same sequences on the build "+
			"before the fix, is committed under `%s` (make lab-l80 ARM=baseline); the fixed arm's idle-boundary, "+
			"concurrent-sessions and restart cells beside it, under `%s` (make lab-l80 ARM=fixed; the restart cell's "+
			"summary holds its verdict, `restart verdict:`, and what port49d's restart did to the held connection).",
			fix.Baseline, strings.TrimSuffix(fix.Baseline, "baseline/")+"fixed/")
	}
	return claim, obs, true
}

// qualL80SentLine is what tls_token_login's verdict says only when port49 proved
// a permit for `show version` and a deny of the denied command from its records
// (qualTLSCommands state "sent", no problems).
var qualL80SentLine = regexp.MustCompile("^- `tls_token_login` .*\\*\\*pass\\*\\*\\. .*`show version` permitted and `[^`]+` denied by port49 \\(authorize_command records\\)")

// qualL80ObservedByTokenLogin is whether tls_token_login may stand for L80's
// denied-command cell (ruling 2026-10-22): all of (a) the build offers
// single-connect and a baseline is committed, (b) tls_token_login passed with
// port49 permitting `show version` and denying the denied command, and (c)
// tls_denied_command was not run for exactly the reason that the device sent
// port49 command authorization. Anything else is INVALID, as before.
func qualL80ObservedByTokenLogin(tok, den string, fix qualL80Fix) bool {
	return fix.Offered && fix.Baseline != "" && // (a)
		qualL80SentLine.MatchString(tok) && // (b)
		strings.HasPrefix(den, "- `tls_denied_command` ") && strings.Contains(den, "**not_run**") &&
		strings.Contains(den, "per-request TLS sent port49 command authorization") // (c)
}

// qualWriteL80 writes L80's note through write when the run observed the
// denied-command cell. Otherwise it writes nothing and returns the INVALID
// error: a re-measure that observed nothing must never replace the closed
// row's note, which a later commit would then carry (final review I2).
func qualWriteL80(notes []string, evidence string, secrets []string, fix qualL80Fix, write func(claim, obs string)) error {
	if fix.Offered && fix.Baseline == "" {
		return errors.New("INVALID: this build offers single-connect (decision 50 ruling 20) and no before-the-fix baseline " +
			"is committed under tests/lab/evidence/L80-<platform>/baseline/: run make lab-l80 ARM=baseline and commit it first; " +
			"tests/lab/results/L80-cisco_nxos.md is left as committed")
	}
	claim, obs, ok := qualL80Note(notes, evidence, fix)
	if !ok {
		return errors.New("INVALID: L80 was re-measured and the denied-command cell was not observed " +
			"(see the QUAL note's tls_denied_command line); tests/lab/results/L80-cisco_nxos.md is left as committed")
	}
	if bad := qualNoteGate(claim+"\n"+obs, secrets); len(bad) > 0 {
		return fmt.Errorf("INVALID: the L80 note was not written:\n  %s", strings.Join(bad, "\n  "))
	}
	write(claim, obs)
	return nil
}

// qualSwitchedFor runs body between do and undo with undo already deferred when
// do starts, so a Fatal inside do, which may have half-applied the switch, still
// undoes it. body gets the once-only undo to call on its normal path.
func qualSwitchedFor(do, undo func(), body func(undo func())) {
	u := qualUndoOnce(undo)
	defer u()
	do()
	body(u)
}

// qualUndoOnce wraps undo so it runs at most once: a cell defers it, so a Fatal
// mid-cell still runs it, and calls it on its normal path too.
func qualUndoOnce(undo func()) func() {
	done := false
	return func() {
		if !done {
			done = true
			undo()
		}
	}
}
