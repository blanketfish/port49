//go:build lab

package lab

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestQualRecordKeepsOnlyTheWhitelist(t *testing.T) {
	in := map[string]any{"event": "redeem", "verdict": "permit", "reason": "context_matched",
		"auth":          map[string]any{"method": "token", "credential_sha256": "ab12"},
		"device":        map[string]any{"name": "nx1", "platform": "cisco_nxos", "transport": "tls", "cert_sha256": "cd34"},
		"session":       map[string]any{"username": "qual01", "port": "0", "rem_addr": "172.100.100.1", "privilege": 1.0, "ctx_id": "x"},
		"packet_fields": map[string]any{"action": "login", "authen_type": "pap", "service": "login", "priv_lvl": 1.0},
		"server_msg":    "anything"}
	out, ok := qualRecord(in, "qual01")
	if !ok {
		t.Fatal("a redeem record is kept")
	}
	b, _ := json.Marshal(out)
	for _, never := range []string{"credential_sha256", "cert_sha256", "ab12", "cd34", "ctx_id", "server_msg", "qual01"} {
		if strings.Contains(string(b), never) {
			t.Fatalf("kept %q: %s", never, b)
		}
	}
	for _, want := range []string{`"authen_type":"pap"`, `"port":"0"`, `"username":"{user}"`, `"rem_addr":"{rem_addr}"`} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("lacks %s: %s", want, b)
		}
	}
}

// Whatever key carries a hash or a secret is dropped wherever it sits, top level or nested in a
// kept block; only the key names are in the failure.
func TestQualRecordNeverPassesAHashOrASecret(t *testing.T) {
	leaky := []string{"credential_sha256", "token_sha256", "body_sha256", "token", "password", "response", "challenge", "body"}
	in := map[string]any{"event": "authorize_session", "verdict": "permit"}
	pf := map[string]any{"authen_type": "pap"}
	for _, k := range leaky {
		in[k] = "VALUE-" + k
		pf[k] = "VALUE-" + k
	}
	in["packet_fields"] = pf
	in["auth"] = map[string]any{"credential_sha256": "VALUE-auth"}
	in["request"] = map[string]any{"service": "shell", "raw": []any{"service=shell"}, "token_sha256": "VALUE-req"}
	in["record"] = map[string]any{"raw": []any{"task_id=7"}, "body_sha256": "VALUE-rec"}
	in["reply"] = map[string]any{"attributes": []any{"priv-lvl=15"}, "password": "VALUE-reply"}
	out, ok := qualRecord(in, "qual01")
	if !ok {
		t.Fatal("an authorize_session record is kept")
	}
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), "VALUE-") {
		for _, k := range append(leaky, "auth", "req", "rec", "reply") {
			if strings.Contains(string(b), "VALUE-"+k) {
				t.Errorf("key %q passed the filter", k)
			}
		}
		t.FailNow()
	}
}

// An unvalidated record's body hash and source never pass, whichever diagnosis.
func TestQualRecordDropsAnUnvalidatedBody(t *testing.T) {
	out, ok := qualRecord(map[string]any{"event": "unvalidated", "unvalidated": map[string]any{
		"diagnosis": "tls_refused", "transport": "tls", "tls_outcome": "unknown_ca",
		"body_sha256": "VALUE-b", "source": "VALUE-s", "cert_sha256": "VALUE-c", "detail": "VALUE-d"}}, "qual01")
	b, _ := json.Marshal(out)
	if !ok || strings.Contains(string(b), "VALUE-") {
		t.Fatalf("%v %s", ok, b)
	}
}

func TestQualRecordKeepsEscalateAndDropsTheRest(t *testing.T) {
	if _, ok := qualRecord(map[string]any{"event": "escalate"}, "qual01"); !ok {
		t.Fatal("escalate is a validated request record")
	}
	// A bare unvalidated record is dropped; only the tls_refused diagnosis is
	// kept (TestQualRecordKeepsATLSRefusalsOutcomeOnly below).
	for _, ev := range []string{"mint", "unvalidated", "issue", "revoke", "authenticate"} {
		if _, ok := qualRecord(map[string]any{"event": ev}, "qual01"); ok {
			t.Fatalf("%s is not stimulus evidence", ev)
		}
	}
}

// Only the minted user becomes {user}: a device's own account (SR Linux's root,
// on port unknown) keeps its name, so genprofile can tell the login's records
// from the device's (re-review 3 Minor). A lab system account is no secret.
func TestQualRecordTemplatesOnlyTheMintedUser(t *testing.T) {
	out, _ := qualRecord(map[string]any{"event": "account", "session": map[string]any{"username": "root", "port": "unknown"}}, "qual01")
	if b, _ := json.Marshal(out); !strings.Contains(string(b), `"username":"root"`) {
		t.Fatalf("%s", b)
	}
}

// port49's own tls_refused record is kept as diagnosis, transport and
// tls_outcome only: never its source, detail or cert_sha256 (re-review I-H).
func TestQualRecordKeepsATLSRefusalsOutcomeOnly(t *testing.T) {
	out, ok := qualRecord(map[string]any{"event": "unvalidated", "unvalidated": map[string]any{
		"source": "172.100.100.31:40001", "diagnosis": "tls_refused", "transport": "tls", "tls_outcome": "unknown_ca",
		"detail": "x509: certificate signed by unknown authority", "cert_sha256": strings.Repeat("c", 64)}}, "qual01")
	b, _ := json.Marshal(out)
	if !ok || string(b) != `{"diagnosis":"tls_refused","event":"unvalidated","tls_outcome":"unknown_ca","transport":"tls"}` {
		t.Fatalf("%v %s", ok, b)
	}
	if _, ok := qualRecord(map[string]any{"event": "unvalidated", "unvalidated": map[string]any{"diagnosis": "bad_key"}}, "qual01"); ok {
		t.Fatal("any other unvalidated record is dropped")
	}
}

// A record holding a credential this run used is refused, and the message names the event, not the credential.
func TestQualRecordsRefuseARecordHoldingASecret(t *testing.T) {
	const secret = "s3cr3t-not-in-any-real-log"
	recs := []map[string]any{{"event": "authorize_session", "verdict": "permit", "server_msg": "hi " + secret}}
	_, err := qualRecords(recs, "qual01", []string{secret})
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("want a refusal that does not print the secret: %v", err)
	}
	if _, err := qualRecords(recs, "qual01", []string{"another"}); err != nil {
		t.Fatalf("a clean record is kept: %v", err)
	}
}

func TestQualRecordsRefuseASeedAnswer(t *testing.T) {
	recs := []map[string]any{{"event": "redeem", "auth": map[string]any{"method": "lab"}}}
	if _, err := qualRecords(recs, "qual01", nil); err == nil {
		t.Fatal("a redeem a lab seed answered makes the run invalid")
	}
}

func TestQualGateRefusesWhatEvidenceMustNotHold(t *testing.T) {
	const secret = "tok-0123456789"
	cases := map[string]string{
		"secret.json":     `{"a":"` + secret + `"}`,
		"hash.json":       `{"credential_sha256":"ab"}`,
		"bodyhash.json":   `{"body_sha256":"ab"}`,
		"password.json":   `{"password":"x"}`,
		"pem.json":        `-----BEGIN CERTIFICATE-----`,
		"longhex.json":    `{"a":"` + strings.Repeat("ab", 40) + `"}`,
		"longbase64.json": `{"a":"` + strings.Repeat("Ab", 30) + `"}`,
	}
	for name, body := range cases {
		bad := qualGate(map[string][]byte{name: []byte(body)}, []string{secret})
		if len(bad) == 0 {
			t.Errorf("%s passed the gate", name)
		}
		for _, m := range bad {
			if strings.Contains(m, secret) {
				t.Errorf("%s: the message prints the secret", name)
			}
		}
	}
	if bad := qualGate(map[string][]byte{"ok.json": []byte(`{"event":"redeem","reason":"context_matched"}`)}, []string{secret}); len(bad) != 0 {
		t.Fatalf("clean evidence refused: %v", bad)
	}
}

// qualRoot is the repository root; a pure test runs with the harness's root unset.
func qualRoot(t *testing.T) string {
	t.Helper()
	r, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func denyRec(reason string, verdict string, vector ...string) map[string]any {
	v := make([]any, len(vector))
	for i, w := range vector {
		v[i] = w
	}
	return map[string]any{"event": "authorize_command", "verdict": verdict, "reason": reason, "request": map[string]any{"vector": v}}
}

// command_denied proves the policy's deny: any other refusal of the command, or a refusal of another command, fails.
func TestQualDenyProvenIsStrict(t *testing.T) {
	good := denyRec("no_permit_dominates_deny", "deny", "show", "users")
	if err := qualDenyProven([]map[string]any{good}, "show users"); err != nil {
		t.Fatal(err)
	}
	for name, recs := range map[string][]map[string]any{
		"privilege_exceeded":  {denyRec("privilege_exceeded", "deny", "show", "users")},
		"no_rule_matched":     {denyRec("no_rule_matched", "deny", "show", "users")},
		"another command":     {denyRec("no_permit_dominates_deny", "deny", "show", "clock")},
		"permitted":           {denyRec("context_matched", "permit", "show", "users")},
		"no record":           nil,
		"mixed, one unproven": {good, denyRec("privilege_exceeded", "deny", "show", "users")},
	} {
		if err := qualDenyProven(recs, "show users"); err == nil {
			t.Errorf("%s: the cell passed", name)
		}
	}
}

func TestQualPermitProven(t *testing.T) {
	if err := qualPermitProven([]map[string]any{denyRec("context_matched", "permit", "show", "version")}, "show version"); err != nil {
		t.Fatal(err)
	}
	if err := qualPermitProven([]map[string]any{denyRec("no_permit_dominates_deny", "deny", "show", "version")}, "show version"); err == nil {
		t.Fatal("a denied command is not a permit")
	}
}

// The command the cells send is the one tests/qual/qual-policy.yaml denies on that platform. Both
// are read from the file: if the policy and the helper drift, this fails.
func TestQualDeniedCommandMatchesThePolicy(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(qualRoot(t), "tests", "qual", "qual-policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var pol struct {
		Scopes []struct {
			Name  string
			Match struct {
				Platform any
			}
		}
		Roles []struct {
			Name string
			Deny []string
		}
		Grants []struct {
			Scope string
			Roles []string
		}
	}
	if err := yaml.Unmarshal(raw, &pol); err != nil {
		t.Fatal(err)
	}
	deny := map[string][]string{}
	for _, r := range pol.Roles {
		deny[r.Name] = r.Deny
	}
	// platform -> the commands the grants of scopes naming it deny
	denied := map[string][]string{}
	for _, g := range pol.Grants {
		for _, s := range pol.Scopes {
			if s.Name != g.Scope {
				continue
			}
			var plats []string
			switch p := s.Match.Platform.(type) {
			case string:
				plats = []string{p}
			case []any:
				for _, x := range p {
					plats = append(plats, x.(string))
				}
			}
			for _, p := range plats {
				for _, r := range g.Roles {
					denied[p] = append(denied[p], deny[r]...)
				}
			}
		}
	}
	platforms := []string{"arista_eos", "cisco_iosxe", "cisco_iosxr", "cisco_nxos", "nokia_srlinux", "juniper_junos"}
	for _, p := range platforms {
		if got := denied[p]; !slices.Equal(got, []string{qualDeniedCommand(p)}) {
			t.Errorf("%s: the policy denies %q, qualDeniedCommand says %q", p, got, qualDeniedCommand(p))
		}
	}
	if len(denied) != len(platforms) {
		t.Errorf("the policy scopes %d platforms, the test knows %d", len(denied), len(platforms))
	}
}

func TestQualProbeCommandsSkipTheDenyOnJunos(t *testing.T) {
	if got := qualProbeCommands("juniper_junos"); !slices.Equal(got, []string{"show version"}) {
		t.Fatalf("%q", got)
	}
	if got := qualProbeCommands("cisco_nxos"); !slices.Equal(got, []string{"show version", "show users"}) {
		t.Fatalf("%q", got)
	}
}

func TestQualConfigAnswersFromThePolicyAlone(t *testing.T) {
	lab, _ := os.ReadFile(filepath.Join(qualRoot(t), "tests", "lab", "port49d-lab.yaml"))
	broker, _ := os.ReadFile(filepath.Join(qualRoot(t), "tests", "lab", "slice", "broker.yaml"))
	frag, _ := os.ReadFile(filepath.Join(qualRoot(t), "tests", "qual", "qual-daemon.yaml"))
	out, err := qualConfigYAML(string(lab), string(broker), string(frag), "/x/qual-policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, never := range []string{"session_attributes", "command_attributes", "deny_prefixes", "seed_token", "slice/policy.yaml"} {
		if strings.Contains(out, never) {
			t.Fatalf("the conformance config keeps %q: a seed or the lab instrument could answer", never)
		}
	}
	for _, want := range []string{"policy_file: /x/qual-policy.yaml", "fault_file:", "staleness_ceiling: 0s"} {
		if !strings.Contains(out, want) {
			t.Fatalf("lacks %q", want)
		}
	}
}

func TestQualCellsCiteRows(t *testing.T) {
	for _, c := range qualCells {
		if len(c.Rows) == 0 {
			t.Errorf("%s cites no register row", c.Name)
		}
	}
}

// The TLS cells' daemon keeps the conformance config's broker block (and so its policy_file) and adds tls_listener.
func TestQualTLSDaemonYAMLKeepsTheBroker(t *testing.T) {
	lab, _ := os.ReadFile(filepath.Join(qualRoot(t), "tests", "lab", "port49d-lab.yaml"))
	broker, _ := os.ReadFile(filepath.Join(qualRoot(t), "tests", "lab", "slice", "broker.yaml"))
	frag, _ := os.ReadFile(filepath.Join(qualRoot(t), "tests", "qual", "qual-daemon.yaml"))
	base, err := qualConfigYAML(string(lab), string(broker), string(frag), "/x/qual-policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	out, err := l73DaemonYAML(base, l73Daemon{Inventory: "/x/inv.yaml", TLSListen: "172.100.100.1:300",
		Cert: "/x/c", Key: "/x/k", ClientCA: "/x/ca", StateDir: "/x/s", Status: "{disabled: true}"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"policy_file: /x/qual-policy.yaml", "tls_listener:", "fault_file:"} {
		if !strings.Contains(out, want) {
			t.Fatalf("lacks %q:\n%s", want, out)
		}
	}
}

// The results note is gated like L73's: a planted secret or hash value is refused, and the
// message names the kind, never the value.
func TestQualNoteGateRefusesASecretOrAHash(t *testing.T) {
	const secret = "planted-secret-value-7"
	hash := strings.Repeat("ab", 32)
	for name, note := range map[string]string{
		"secret": "the login used " + secret,
		"hash":   `{"credential_sha256": "` + hash + `"}`,
	} {
		bad := qualNoteGate(note, []string{secret})
		if len(bad) == 0 {
			t.Errorf("%s: the note passed the gate", name)
		}
		for _, m := range bad {
			if strings.Contains(m, secret) || strings.Contains(m, hash) {
				t.Errorf("%s: the message prints the value: %q", name, m)
			}
		}
	}
	if bad := qualNoteGate("every cell passed", []string{secret}); len(bad) != 0 {
		t.Fatalf("a clean note was refused: %v", bad)
	}
}

// Junos sends no command authorization (L18), so neither command cell can be proven, whatever
// the output: both are not_applicable. Elsewhere the strict checks decide.
func TestQualCommandCellsOnJunosAreNotApplicable(t *testing.T) {
	p, d, _ := qualCommandCells("juniper_junos", nil)
	if p != "not_applicable" || d != "not_applicable" {
		t.Fatalf("junos: %s %s", p, d)
	}
	good := []map[string]any{denyRec("context_matched", "permit", "show", "version"), denyRec("no_permit_dominates_deny", "deny", "show", "users")}
	if p, d, _ := qualCommandCells("cisco_nxos", good); p != "pass" || d != "pass" {
		t.Fatalf("nxos good: %s %s", p, d)
	}
	if p, d, _ := qualCommandCells("cisco_nxos", nil); p != "fail" || d != "fail" {
		t.Fatalf("nxos empty: %s %s", p, d)
	}
}

// A gate hit, in the files or in the note, leaves what was on disk untouched: nothing new is written.
func TestQualWriteEvidenceWritesNothingOnAHit(t *testing.T) {
	const secret = "planted-secret-value-9"
	dir := filepath.Join(t.TempDir(), "QUAL-x")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(dir, "old.json")
	if err := os.WriteFile(old, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	clean := map[string][]byte{"run.json": []byte(`{"a":1}`)}
	for name, c := range map[string]struct {
		files map[string][]byte
		note  string
	}{
		"note hit":  {clean, "mentions " + secret},
		"files hit": {map[string][]byte{"run.json": []byte(secret)}, "fine"},
	} {
		bad := qualWriteEvidence(dir, c.files, c.note, []string{secret})
		if len(bad) == 0 {
			t.Fatalf("%s: not refused", name)
		}
		if _, err := os.Stat(old); err != nil {
			t.Fatalf("%s: the old evidence was removed", name)
		}
		if _, err := os.Stat(filepath.Join(dir, "run.json")); err == nil {
			t.Fatalf("%s: new evidence was written", name)
		}
	}
	if bad := qualWriteEvidence(dir, clean, "fine", []string{secret}); len(bad) != 0 {
		t.Fatal(bad)
	}
	if _, err := os.Stat(filepath.Join(dir, "run.json")); err != nil {
		t.Fatal("a clean run writes its evidence")
	}
}

// genprofile cuts the records into cells by their time, so every kept record
// carries its ts, tls_refused ones included.
func TestQualRecordKeepsItsTimestamp(t *testing.T) {
	const at = "2026-10-20T12:00:01.000Z"
	for _, in := range []map[string]any{
		{"ts": at, "event": "redeem", "verdict": "permit"},
		{"ts": at, "event": "unvalidated", "unvalidated": map[string]any{"diagnosis": "tls_refused", "tls_outcome": "unknown_ca"}},
	} {
		out, ok := qualRecord(in, "qual01")
		if !ok || out["ts"] != at {
			t.Fatalf("%v: kept %v with ts %v", in["event"], ok, out["ts"])
		}
	}
}

func TestQualRecordMasksALongRunInAnAccountingArgument(t *testing.T) {
	path := "/components/component/properties/property[name='state']/"
	out, _ := qualRecord(map[string]any{"event": "account", "record": map[string]any{
		"raw": []any{"task_id=1", `cmd=set: [x] "` + path + `"<cr>`}}}, "qual01")
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), "components/component") || !strings.Contains(string(b), "{long_run}") {
		t.Fatalf("%s", b)
	}
	if bad := qualGate(map[string][]byte{"decisions.jsonl": b}, nil); len(bad) != 0 {
		t.Fatalf("the gate still refuses it: %v", bad)
	}
}

func TestQualSRLinuxSendsNoCommandAuthorizationEither(t *testing.T) {
	p, d, why := qualCommandCells("nokia_srlinux", nil)
	if p != "not_applicable" || d != "not_applicable" || !strings.Contains(why, "L76") {
		t.Fatalf("srlinux: %s %s %q", p, d, why)
	}
	if got := qualProbeCommands("nokia_srlinux"); !slices.Equal(got, []string{"show version"}) {
		t.Fatalf("%q", got)
	}
}

// A known secret in an account argument is refused on the raw record, before the
// {long_run} mask could rewrite the argument and hide it.
func TestQualRecordsRefuseASecretInAnAccountArgBeforeTheMask(t *testing.T) {
	const secret = "tok-0123456789abcdef0123456789abcdef0123456789"
	recs := []map[string]any{{"event": "account", "record": map[string]any{"raw": []any{"task_id=1", "cmd=" + secret}}}}
	if _, err := qualRecords(recs, "qual01", []string{secret}); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("want a refusal that does not print the secret: %v", err)
	}
}

// A command answered with a refusal ran nothing (the L78 grader once counted
// any answer as a run).
func TestQualRanReadsTheFirstLineOfTheOutput(t *testing.T) {
	for out, want := range map[string]bool{
		"Cisco IOS XR Software, Version 26.1.1\nCopyright":        true,
		"% This command is not authorized":                        false,
		"\n% This command is not authorized\nxrd1#":               false,
		"error: command not allowed":                              false,
		"":                                                        false,
		"% Invalid input detected":                                false,
		"% Authorization failed.":                                 false, // IOS XE
		"% Authorization denied for command 'show version'":       false, // EOS
		"Error: No authorization to execute command show version": false, // SR Linux
		"Error: AAA authorization failed":                         false, // NX-OS
	} {
		if got, says := qualRan(out); got != want {
			t.Errorf("%q: ran %v (%s), want %v", out, got, says, want)
		}
	}
}

// The plain single-connection cell on XRd types the keyword on its own line and commits it: the
// image's help lists nothing after `single-connection`, and XR applies nothing before `commit`.
func TestSingleConnectionOnXRdIsALineOfItsOwnAndCommitted(t *testing.T) {
	ps := singleConnectionPlaces("cisco_xrd")
	if len(ps) != 1 || !slices.Equal(ps[0].lines, []string{"tacacs-server host 172.100.100.1 single-connection", "commit"}) {
		t.Fatalf("%+v", ps)
	}
}

// XRd repeats a login it answered locally, no faster than once a second and
// only for an authentication error; every other platform logs in once.
func TestQualRetryUnreachedRepeatsOnlyXRdAuthRefusals(t *testing.T) {
	refused := errors.New("ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password]")
	var slept []time.Duration
	sleep := func(d time.Duration) { slept = append(slept, d) }
	never := func() bool { return false }
	calls := 0
	n, err := qualRetryUnreached("cisco_xrd", func() error {
		if calls++; calls < 3 {
			return refused
		}
		return nil
	}, never, time.Minute, sleep)
	if n != 3 || err != nil || len(slept) != 2 || slept[0] < time.Second {
		t.Fatalf("xrd: %d attempts, %v, slept %v", n, err, slept)
	}
	if n, _ := qualRetryUnreached("cisco_iosxe", func() error { return refused }, never, time.Minute, sleep); n != 1 {
		t.Fatalf("iosxe tried %d times", n)
	}
	other := errors.New("dial tcp: i/o timeout")
	if n, _ := qualRetryUnreached("cisco_xrd", func() error { return other }, never, time.Minute, sleep); n != 1 {
		t.Fatalf("a non-auth error was retried %d times", n)
	}
	slept = nil
	n, err = qualRetryUnreached("cisco_xrd", func() error { return refused }, never, 30*time.Second, sleep)
	if err == nil || len(slept) != 3 {
		t.Fatalf("the deadline: %d attempts, slept %v", n, slept)
	}
}

// A wrong-credential login that never reached port49d proves nothing: only a
// denied redeem record does.
func TestQualDeniedNeedsADeniedRedeem(t *testing.T) {
	deny := map[string]any{"event": "redeem", "verdict": "deny", "reason": "token_not_found"}
	permit := map[string]any{"event": "redeem", "verdict": "permit"}
	acct := map[string]any{"event": "account"}
	if !qualDenied([]map[string]any{acct, deny}) {
		t.Fatal("a denied redeem was not counted")
	}
	if qualDenied([]map[string]any{acct, permit}) || qualDenied(nil) {
		t.Fatal("no denied redeem was counted as one")
	}
}

// A port49 deny is a real refusal: a deny followed by a success must not be retried into a pass.
func TestQualRetryUnreachedStopsOnAPort49Deny(t *testing.T) {
	refused := errors.New("ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password]")
	calls, denied := 0, false
	n, err := qualRetryUnreached("cisco_xrd", func() error {
		calls++
		if calls == 2 {
			denied = true // the second login reached port49d and was denied
		}
		if calls < 3 {
			return refused
		}
		return nil
	}, func() bool { return denied }, time.Minute, func(time.Duration) {})
	if err == nil || n != 2 || !strings.Contains(err.Error(), "port49 denied") {
		t.Fatalf("%d attempts, %v: a deny was retried into a pass", n, err)
	}
}

// The XR note carries the facts an operator needs at 3am; no other platform gets the section.
func TestQualOperatorSectionIsXROnlyAndNamesTheTwoFacts(t *testing.T) {
	got := qualOperatorSection("cisco_iosxr")
	for _, want := range []string{"priv-lvl", "aaa authorization commands default group", "Break-glass fails", "reasoning, not measurement"} {
		if !strings.Contains(got, want) {
			t.Errorf("the XR section lacks %q", want)
		}
	}
	for _, p := range []string{"cisco_iosxe", "arista_eos", "nokia_srlinux", "juniper_junos", "cisco_nxos"} {
		if qualOperatorSection(p) != "" {
			t.Errorf("%s got an XR section", p)
		}
	}
}
