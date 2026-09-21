//go:build lab

// Transport tests: what AAA looks like when the operator is not at an
// interactive SSH login.
//
// Everything else in this directory measures one transport — a person typing at
// an SSH session — and every claim the register has closed so far is a claim
// about that transport. The product is not used that way. eAPI and NX-API are
// how configuration is actually pushed in the environment this server is being
// built for, NETCONF is how the automation that replaces it will push it, and
// nothing about how a device runs AAA for those has ever been measured here.
//
// Three questions, and the third is the one that decides a design:
//
//  1. How many TACACS+ authentication exchanges does ONE API request cost, and
//     does the device send an authorization request at all — with what
//     `service`, `cmd` and `cmd-arg`, and what in `port` and `rem_addr`?
//  2. Does a configuration request over an API look any different from a read?
//  3. **Does a second request with the same credential re-authenticate?**
//
// Question 3 is why this file exists. port49 tokens are single-use: redemption
// deletes the token. A transport that runs every HTTP request through a fresh
// authentication exchange therefore spends a token per request, and an operator
// who pastes a token into a script that makes forty calls gets one success and
// thirty-nine denials — at 3am, with no obvious cause, because the first call
// worked. Spec §13 decision 15 ("reusable tokens") is provisional on exactly
// this measurement, and register entry L7 is the row it is provisional on.
//
// These tests have NOT been run. They were written against the harness, the
// device documentation and the vrnetlab launchers, and every payload below that
// is a guess is marked as one. A guessed payload that the device rejects is not
// a failed test: the rejection is recorded verbatim in the note and the payload
// is fixed from what the device said, not from more documentation. What IS a
// failed test is a run that produced no TACACS+ record at all, because then
// nothing was measured — the same rule the register tests follow.
package lab

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/tests/lab/labpcap"
)

// ---------------------------------------------------------------------------
// Logins
// ---------------------------------------------------------------------------

// transportLogin is a seeded (username, token) pair from port49d-lab.yaml.
//
// These are a pool of their own rather than more alice names from nextLogin,
// and the reason is the measurement. nextLogin hands out a fresh username per
// login precisely so that no two logins collide on the receipt key, which is
// the right thing for a test that asks what a device does on its own. It is the
// wrong thing here: the question is what happens when the SAME credential is
// presented twice, so the username has to be the same twice too.
type transportLogin struct {
	user   string
	secret string
}

var (
	// The `01` login is presented twice with the same token. That repeat is the
	// re-authentication measurement of question 3 above.
	eapiRead    = transportLogin{"eapi01", "p49_labeapi01"}
	nxapiRead   = transportLogin{"nxapi01", "p49_labnxapi01"}
	netconfRead = transportLogin{"netconf01", "p49_labnetconf01"}

	// The `02` login carries a fresh token for the configuration request, so a
	// spent `01` token cannot block the half of each test that asks whether a
	// configuration change produces an authorization request at all.
	eapiConfig    = transportLogin{"eapi02", "p49_labeapi02"}
	nxapiConfig   = transportLogin{"nxapi02", "p49_labnxapi02"}
	netconfConfig = transportLogin{"netconf02", "p49_labnetconf02"}
)

// check fails the test if port49d-lab.yaml does not seed this login for this
// platform's NAS. The same drift trap nextLogin guards: a test whose token is
// not in the config measures a denial and reports it as device behavior.
func (tl transportLogin) check(t *testing.T, l *lab) transportLogin {
	t.Helper()
	mustBeSeeded(t, tl.secret)
	want := fmt.Sprintf("{nas: %s, username: %s,", l.p.node, tl.user)
	if !strings.Contains(labYAML, want) {
		t.Fatalf("tests/lab/port49d-lab.yaml seeds no `%s` login for NAS %q; the harness and the config have drifted apart",
			tl.user, l.p.node)
	}
	return tl
}

// ---------------------------------------------------------------------------
// Where each platform serves each transport
// ---------------------------------------------------------------------------

// netconfPort is the TCP port this platform serves NETCONF over SSH on, or ""
// if this lab does not enable NETCONF there.
//
// EOS is the odd one and it is not a typo. `management api netconf` with
// `transport ssh def` — what configs/eos-startup.cfg sets — serves NETCONF as a
// subsystem of the ordinary SSH server on port 22. Junos `system services
// netconf ssh` and the NX-OS `feature netconf` agent both open TCP 830.
func netconfPort(p platform) string {
	switch p.name {
	case "arista_eos":
		return "22"
	case "juniper_vjunos-router", "juniper_vsrx", "cisco_nxos":
		return "830"
	}
	return ""
}

// ---------------------------------------------------------------------------
// One step of a transport test
// ---------------------------------------------------------------------------

// transportStep is one API request or one NETCONF session, and everything the
// decision log said while it was happening.
type transportStep struct {
	name    string
	user    string
	took    time.Duration
	err     error  // the transport failed: connection refused, HTTP 401, rpc-error
	said    string // what the device answered, trimmed for the note
	recs    []map[string]any
	skipped string // why this step was not attempted, when it was not
}

// run performs one step: mark the log, do the thing, then wait for records.
//
// The wait has two halves and both are deliberate. The first waits for any
// record naming this user, which is what proves the device ran AAA for this
// request. The second drains a further window whatever the first found, because
// accounting arrives after the exchange by way of the durable spool, and a step
// that stopped reading at the redeem would report "no accounting" for a record
// that was still in flight.
//
// A step that produces nothing is not an error here. "This request cost zero
// authentication exchanges" is a finding — the best possible one for decision
// 15 — so the absence has to be reportable rather than fatal. The test as a
// whole still fails if NO step measured anything; see transportAssert.
func (l *lab) runStep(name, user string, do func() (string, error)) transportStep {
	s := transportStep{name: name, user: user}
	off := l.mark()
	t0 := time.Now()
	s.said, s.err = do()
	s.took = time.Since(t0)
	l.waitForRecords(off, 20*time.Second, func(rs []map[string]any) bool {
		return len(recordsForUser(rs, user)) > 0
	})
	s.recs = l.drainRecords(off, 10*time.Second)
	return s
}

func skippedStep(name, why string) transportStep {
	return transportStep{name: name, skipped: why}
}

// ---------------------------------------------------------------------------
// Reading the decision log for a transport
// ---------------------------------------------------------------------------

func recordsForUser(recs []map[string]any, user string) []map[string]any {
	var out []map[string]any
	for _, r := range recs {
		if s := sub(r, "session"); s != nil && str(s, "username") == user {
			out = append(out, r)
		}
	}
	return out
}

func countEvent(recs []map[string]any, event string) int {
	n := 0
	for _, r := range recs {
		if str(r, "event") == event {
			n++
		}
	}
	return n
}

// uniqueField collects the distinct values of one field of the session object,
// in sorted order, rendering the empty string visibly. An empty `port` is a
// measurement — it is what Junos reports over SSH — so it must not look like a
// missing value.
func uniqueField(recs []map[string]any, field string) []string {
	seen := map[string]bool{}
	for _, r := range recs {
		if s := sub(r, "session"); s != nil {
			seen[str(s, field)] = true
		}
	}
	var out []string
	for v := range seen {
		if v == "" {
			out = append(out, "(empty string)")
			continue
		}
		out = append(out, "`"+v+"`")
	}
	sort.Strings(out)
	return out
}

func uniqueAuthMethods(recs []map[string]any) []string {
	seen := map[string]bool{}
	for _, r := range recs {
		if a := sub(r, "auth"); a != nil {
			if m := str(a, "method"); m != "" {
				seen[m] = true
			}
		}
	}
	var out []string
	for v := range seen {
		out = append(out, "`"+v+"`")
	}
	sort.Strings(out)
	return out
}

// stepDetail renders every record one step produced, with the AV pairs of any
// authorization request spelled exactly as they arrived. The AV pairs are the
// whole point of question 1: a device that sends `service=shell cmd=configure`
// for an API call and a device that sends nothing at all need completely
// different things from an adapter.
func stepDetail(s transportStep) string {
	mine := recordsForUser(s.recs, s.user)
	if len(mine) == 0 {
		return fmt.Sprintf("No decision record named `%s` at all. Other records in the same window: %s\n",
			s.user, summarize(s.recs))
	}
	var b strings.Builder
	for _, r := range mine {
		fmt.Fprintf(&b, "%s event=%s verdict=%s reason=%s", str(r, "ts"), str(r, "event"), str(r, "verdict"), str(r, "reason"))
		if f := str(r, "flags"); f != "" {
			fmt.Fprintf(&b, " flags=%s", f)
		}
		if a := sub(r, "auth"); a != nil {
			fmt.Fprintf(&b, " auth.method=%s", str(a, "method"))
		}
		if sess := sub(r, "session"); sess != nil {
			fmt.Fprintf(&b, " port=%q rem_addr=%q", str(sess, "port"), str(sess, "rem_addr"))
		}
		b.WriteString("\n")
		for _, a := range strs(sub(r, "request"), "raw") {
			fmt.Fprintf(&b, "    request AV: %s\n", a)
		}
		for _, a := range rawOf(r) {
			fmt.Fprintf(&b, "    accounting AV: %s\n", a)
		}
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// The observation
// ---------------------------------------------------------------------------

// transportObservation renders the note body every transport test writes.
func transportObservation(l *lab, transport string, steps []transportStep, payloads, caveats string) string {
	var b strings.Builder

	fmt.Fprintf(&b, "Transport measured: **%s**. Each step below was a separate request or session; "+
		"the decision log was read from a mark taken immediately before it, and drained for a further "+
		"10 seconds afterwards so that accounting arriving by way of the spool is counted in the step "+
		"that produced it.\n\n", transport)

	b.WriteString("| step | user | device answered | authentications | session authz | command authz | accounting | elapsed |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|\n")
	for _, s := range steps {
		if s.skipped != "" {
			fmt.Fprintf(&b, "| %s | — | **not attempted**: %s | — | — | — | — | — |\n",
				s.name, oneLine(s.skipped))
			continue
		}
		mine := recordsForUser(s.recs, s.user)
		answered := "yes"
		if s.err != nil {
			answered = "**no**: " + oneLine(s.err.Error())
		}
		fmt.Fprintf(&b, "| %s | `%s` | %s | %d | %d | %d | %s | %s |\n",
			s.name, s.user, answered,
			countEvent(mine, "redeem"),
			countEvent(mine, "authorize_session"),
			countEvent(mine, "authorize_command"),
			accountFlagsTable(recordsOfEvent(mine, "account")),
			s.took.Round(10*time.Millisecond))
	}

	b.WriteString("\n### Does a second request with the same token re-authenticate?\n\n")
	b.WriteString(transportReauthVerdict(steps))

	b.WriteString("\n### `port` and `rem_addr` over this transport\n\n")
	var all []map[string]any
	for _, s := range steps {
		all = append(all, recordsForUser(s.recs, s.user)...)
	}
	if len(all) == 0 {
		b.WriteString("Not measured: no record for any of these users reached the decision log.\n")
	} else {
		fmt.Fprintf(&b, "- `port`: %s\n- `rem_addr`: %s\n- `auth.method`: %s\n",
			joinOrNone(uniqueField(all, "port")), joinOrNone(uniqueField(all, "rem_addr")),
			joinOrNone(uniqueAuthMethods(all)))
		b.WriteString("\nThese are the values this transport produced. Compare them with the SSH figures in " +
			"`L1-" + l.p.name + ".md`. Nothing keys on `port` any more (spec §13, decision 15), so a " +
			"transport reporting the same constant as SSH no longer costs anything; what these values are " +
			"still for is accounting annotation and the record an operator reads at 3am.\n")
	}

	b.WriteString("\n### How many TCP connections the device opened to port49d\n\n")
	b.WriteString(transportConnectionNote(l))

	b.WriteString("\n### Every record, per step\n\n")
	for _, s := range steps {
		if s.skipped != "" {
			fmt.Fprintf(&b, "**%s** — not attempted: %s\n\n", s.name, s.skipped)
			continue
		}
		fmt.Fprintf(&b, "**%s** (as `%s`)\n\n```\n%s```\n\n", s.name, s.user, stepDetail(s))
		if s.said != "" {
			fmt.Fprintf(&b, "What the device answered:\n\n```\n%s\n```\n\n", trimForNote(s.said))
		}
	}

	if payloads != "" {
		b.WriteString("### The requests that were sent\n\n" + payloads + "\n")
	}
	b.WriteString("\n### Not measured\n\n" + caveats)
	return b.String()
}

// transportReauthVerdict answers question 3 from the steps, rather than
// asserting it. The two steps that share a user are the comparison.
func transportReauthVerdict(steps []transportStep) string {
	byUser := map[string][]transportStep{}
	var order []string
	for _, s := range steps {
		if s.skipped != "" {
			continue
		}
		if _, ok := byUser[s.user]; !ok {
			order = append(order, s.user)
		}
		byUser[s.user] = append(byUser[s.user], s)
	}
	for _, u := range order {
		ss := byUser[u]
		if len(ss) < 2 {
			continue
		}
		first := countEvent(recordsForUser(ss[0].recs, u), "redeem")
		second := countEvent(recordsForUser(ss[1].recs, u), "redeem")
		switch {
		case first == 0:
			return fmt.Sprintf("**Not measured.** The first request as `%s` produced no authentication "+
				"exchange at all, so the second one has nothing to be compared against. Whatever the device "+
				"did, it did not ask port49 about this credential.\n", u)
		case second == 0:
			return fmt.Sprintf("**No.** The first request as `%s` cost %d authentication exchange(s); the "+
				"second, with the same token, cost none. This transport authenticates once and then carries "+
				"the result, so a single-use token survives a session of repeated requests. Spec §13 decision "+
				"15 can rest on this row for this transport.\n", u, first)
		default:
			// The repeat re-authenticated. Whether that BREAKS anything is a
			// second question, and the answer is in the record rather than in
			// this sentence. Asserting "and so it is denied" here would be a
			// note contradicting its own table: the first eAPI run measured a
			// repeat that re-authenticated and was *permitted*, because port49
			// answers a replayed credential from the receipt it kept.
			verdict, reason := reauthVerdict(ss[1], u)
			// The scope of this sentence is the whole finding, and an earlier
			// version overstated it. What this test drives is a client that
			// sends Basic credentials on a FRESH CONNECTION every time —
			// `DisableKeepAlives`, no cookie jar — which is the worst case and
			// not how either API is meant to be used. "Every request is a
			// fresh authentication over this transport" is a claim about the
			// transport; what was measured is a claim about this client. The
			// cookie flows (`/login` on eAPI, `nxapi_auth` on NX-API) and
			// kept-alive connections are what L7 still lists as unmeasured,
			// and they are exactly the shapes that would make the count lower.
			out := fmt.Sprintf("**Yes, for a client shaped like this one.** The first request as `%s` cost %d "+
				"authentication exchange(s) and the second, with the same token, cost %d more. **This client "+
				"sends HTTP Basic credentials on a fresh TCP connection every call** (`DisableKeepAlives`, no "+
				"cookie jar), so what is measured here is that the device runs AAA for each such request — not "+
				"that the transport cannot do better. The `/login` session-cookie flow and HTTP keep-alive are "+
				"the obvious ways a real client avoids this, and both are separately measured (L7).\n\n",
				u, first, second)
			switch {
			case verdict == "permit":
				out += fmt.Sprintf("**And it was allowed anyway**: `verdict=%s reason=%s`. The token was spent "+
					"by the first call, and the second was answered out of the receipt port49 kept for "+
					"`(nas, username, credential_sha256)` rather than out of the store — the same credential "+
					"hashes to the same key, so a repeat finds its own receipt. So a script that makes forty calls "+
					"with one token works — for as long as that receipt lives. What decision 15 rests on is "+
					"therefore not \"does it re-authenticate\" but **`receipt_ttl`**: past it, the next call in "+
					"the same script is the first denial, and nothing about the credential has changed.\n", verdict, reason)
			case verdict == "":
				out += "The repeat produced no redeem record, which contradicts the count above and should be " +
					"investigated before this note is trusted.\n"
			default:
				out += fmt.Sprintf("**And it was refused**: `verdict=%s reason=%s`. A single-use token is spent "+
					"by the first call and every later call in the same script is denied. That is the failure "+
					"mode decision 15 is provisional on: the operator sees one success and then a run of "+
					"denials with a working credential in hand.\n", verdict, reason)
			}
			return out
		}
	}
	return "**Not measured.** No two steps in this run presented the same credential twice.\n"
}

// reauthVerdict returns what port49 decided on the repeat, using the verdict
// and reason the daemon actually wrote. Never guess a reason code: spec §5.7 is
// a closed vocabulary and this reads it out of the record. An empty verdict
// means no redeem record was found at all.
func reauthVerdict(s transportStep, user string) (verdict, reason string) {
	for _, r := range recordsForUser(s.recs, user) {
		if str(r, "event") == "redeem" {
			return str(r, "verdict"), str(r, "reason")
		}
	}
	return "", ""
}

func joinOrNone(vs []string) string {
	if len(vs) == 0 {
		return "not present on any record"
	}
	return strings.Join(vs, ", ")
}

func trimForNote(s string) string {
	s = strings.TrimRight(s, "\n")
	const max = 4000
	if len(s) > max {
		return s[:max] + "\n... (truncated for this note; the full answer is in the test log)"
	}
	return s
}

// ---------------------------------------------------------------------------
// The note
// ---------------------------------------------------------------------------

// resultOver is result() for a transport that is not SSH.
//
// It is a separate function rather than a parameter on result() on purpose:
// result() is being edited on another branch for the L4 and L13 work, and a
// signature change there would collide with every caller. Fold the two together
// once both branches have landed — they differ only in the Transport line and
// in nothing else.
func (l *lab) resultOver(t *testing.T, entry, transport, claim, observation string) {
	t.Helper()
	dir := filepath.Join(root, "tests", "lab", "results")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("results directory: %v", err)
	}
	capLine := l.captureLine(t)

	path := filepath.Join(dir, fmt.Sprintf("%s-%s.md", entry, l.p.name))
	var b strings.Builder
	fmt.Fprintf(&b, "# %s — %s\n\n", entry, l.p.name)
	fmt.Fprintf(&b, "- **Date measured:** %s\n", time.Now().UTC().Format("2006-01-02"))
	fmt.Fprintf(&b, "- **Platform:** %s (containerlab node `%s`, %s)\n", l.p.name, l.p.node, l.p.addr)
	fmt.Fprintf(&b, "- **Image version:** %s (`%s`)\n", l.p.version, l.p.image)
	fmt.Fprintf(&b, "- **Topology:** `tests/lab/%s`\n", l.p.topo)
	fmt.Fprintf(&b, "- **Capture:** %s\n", capLine)
	fmt.Fprintf(&b, "- **Transport:** %s\n", transport)
	if l.configWarn != "" {
		fmt.Fprintf(&b, "- **Caveat:** %s\n", l.configWarn)
	}
	fmt.Fprintf(&b, "\n## Claim\n\n%s\n\n## Observation\n\n%s\n", claim, observation)
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	t.Logf("wrote %s", path)
}

// transportAssert is the rule that keeps a transport test honest: a run that
// produced no TACACS+ record at all measured nothing, and a test that measured
// nothing fails. Whichever way the device behaved is the result; silence is
// not a result, it is a broken setup.
func transportAssert(t *testing.T, transport string, steps []transportStep) {
	t.Helper()
	records, attempted := 0, 0
	for _, s := range steps {
		if s.skipped != "" {
			continue
		}
		attempted++
		records += len(recordsForUser(s.recs, s.user))
	}
	if attempted == 0 {
		t.Fatalf("%s: no step was attempted, so nothing was measured", transport)
	}
	if records == 0 {
		var b strings.Builder
		for _, s := range steps {
			if s.skipped != "" {
				continue
			}
			fmt.Fprintf(&b, "\n  %s as %s: err=%v, device said %q", s.name, s.user, s.err, oneLine(s.said))
		}
		t.Fatalf("%s: %d step(s) ran and not one decision record named any of their users reached the log, so "+
			"neither the authentication cost nor the authorization shape of this transport was measured. "+
			"The likeliest causes are that the transport is not enabled on the device, that the request never "+
			"reached it, or that the device authenticated the request locally without asking port49 — and the "+
			"third would be a finding, but it cannot be told from the first two without a capture that shows "+
			"the request arriving. What the steps did:%s", transport, attempted, b.String())
	}
}

// ---------------------------------------------------------------------------
// HTTPS
// ---------------------------------------------------------------------------

// apiPost sends one JSON request to a device's HTTP API and returns the status
// line and the body.
//
// A fresh client per call, never a shared one, and that is a measurement
// decision rather than tidiness. Go's default transport keeps connections
// alive, and a device that skipped authentication on a kept-alive connection
// would answer question 3 with "no" for a reason that is about TCP rather than
// about tokens. Each step therefore opens its own connection, and what a
// kept-alive connection does is listed as unmeasured in every note this file
// writes.
//
// InsecureSkipVerify is for the device's self-signed certificate. This is a
// lab on a private bridge; nothing here is a statement about how port49 itself
// should treat certificates.
func apiPost(url, user, password, contentType string, body any, timeout time.Duration) (string, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", contentType)
	req.SetBasicAuth(user, password)

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	text := fmt.Sprintf("HTTP %s\n%s", resp.Status, out)
	if resp.StatusCode != http.StatusOK {
		// Not a Go error: a 401 is the most interesting answer this call can
		// give, because it means the device ran AAA and port49 said no. The
		// caller records it and carries on.
		return text, fmt.Errorf("HTTP %s", resp.Status)
	}
	return text, nil
}

// prettyJSON renders a request body for the note, so a reader can reproduce the
// call without reading the test.
func prettyJSON(v any) string {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("(could not be rendered: %v)", err)
	}
	return string(raw)
}

// ---------------------------------------------------------------------------
// L7 — Arista eAPI
// ---------------------------------------------------------------------------

// eapiBody is the JSON-RPC envelope eAPI takes at https://<device>/command-api.
func eapiBody(id string, cmds []string) map[string]any {
	return map[string]any{
		"jsonrpc": "2.0",
		"method":  "runCmds",
		"id":      id,
		"params": map[string]any{
			"version": 1,
			"cmds":    cmds,
			"format":  "json",
		},
	}
}

// eapiMarker is the value written by the configuration step. It is an SNMP
// location string: it changes nothing about how the device forwards, it is
// visible in `show running-config`, and it is harmless to leave behind.
const eapiMarker = "port49-lab-eapi"

func TestL7EAPI(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if l.p.name != "arista_eos" {
			t.Skipf("%s: eAPI is an EOS transport", l.p.name)
		}
		read := eapiRead.check(t, l)
		conf := eapiConfig.check(t, l)

		stop := l.capture(t, "L7-eapi")
		defer stop()

		url := "https://" + l.p.addr + "/command-api"
		readBody := eapiBody("1", []string{"show version"})
		confBody := eapiBody("2", []string{"enable", "configure", "snmp-server location " + eapiMarker, "end"})

		steps := []transportStep{
			l.runStep("read `show version`", read.user, func() (string, error) {
				return apiPost(url, read.user, read.secret, "application/json", readBody, 60*time.Second)
			}),
			l.runStep("read again, same token", read.user, func() (string, error) {
				return apiPost(url, read.user, read.secret, "application/json", readBody, 60*time.Second)
			}),
			l.runStep("configure `snmp-server location`", conf.user, func() (string, error) {
				return apiPost(url, conf.user, conf.secret, "application/json", confBody, 60*time.Second)
			}),
		}

		payloads := fmt.Sprintf("Read (steps 1 and 2), POSTed to `%s` with HTTP Basic authentication, the token "+
			"as the password:\n\n```json\n%s\n```\n\nConfiguration (step 3):\n\n```json\n%s\n```\n",
			url, prettyJSON(readBody), prettyJSON(confBody))

		obs := transportObservation(l, "eAPI (HTTPS JSON-RPC `runCmds`)", steps, payloads, eapiCaveats)
		l.resultOver(t, "L7", "eAPI over HTTPS JSON-RPC", l7Claim, obs)
		transportAssert(t, "eAPI", steps)
	})
}

const eapiCaveats = "- The `/login` session-cookie flow. L7 names it explicitly, and this test does not use " +
	"it: every request here carries HTTP Basic credentials. A cookie session is the obvious way a device " +
	"would avoid re-authenticating, so if the table above shows an authentication per request, the cookie " +
	"flow is the next thing to measure, not a conclusion to draw.\n" +
	"- HTTP keep-alive. Each step opens its own TCP connection (`DisableKeepAlives`), so nothing here says " +
	"whether a second request on an already-open connection re-authenticates.\n" +
	"- `unix-socket` and HTTP (not HTTPS) eAPI transports.\n" +
	"- Whether eAPI accounting distinguishes the API from a shell session at all.\n"

const l7Claim = "Whether eAPI and NX-API run each HTTP request through AAA authentication, whether session " +
	"cookies (`/login`) change that, and whether API commands produce per-command authorization requests."

// ---------------------------------------------------------------------------
// L7 — Cisco NX-API
// ---------------------------------------------------------------------------

// nxapiBody is the `ins_api` envelope NX-OS takes at https://<device>/ins.
//
// `cli_show` and `cli_conf` are the two types this test uses. NX-API also has a
// separate JSON-RPC dialect on the same endpoint (`Content-Type:
// application/json-rpc`, `"method": "cli"`), and the two are not the same code
// path on the device. This measures the `ins_api` one; the JSON-RPC dialect is
// listed as unmeasured below rather than assumed to behave alike.
func nxapiBody(kind, input string) map[string]any {
	return map[string]any{
		"ins_api": map[string]any{
			"version":       "1.0",
			"type":          kind,
			"chunk":         "0",
			"sid":           "1",
			"input":         input,
			"output_format": "json",
		},
	}
}

const nxapiMarker = "port49-lab-nxapi"

func TestL7NXAPI(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if l.p.name != "cisco_nxos" {
			t.Skipf("%s: NX-API is an NX-OS transport", l.p.name)
		}
		read := nxapiRead.check(t, l)
		conf := nxapiConfig.check(t, l)

		stop := l.capture(t, "L7-nxapi")
		defer stop()

		url := "https://" + l.p.addr + "/ins"
		readBody := nxapiBody("cli_show", "show version")
		confBody := nxapiBody("cli_conf", "snmp-server location "+nxapiMarker)

		steps := []transportStep{
			l.runStep("cli_show `show version`", read.user, func() (string, error) {
				return apiPost(url, read.user, read.secret, "application/json", readBody, 60*time.Second)
			}),
			l.runStep("cli_show again, same token", read.user, func() (string, error) {
				return apiPost(url, read.user, read.secret, "application/json", readBody, 60*time.Second)
			}),
			l.runStep("cli_conf `snmp-server location`", conf.user, func() (string, error) {
				return apiPost(url, conf.user, conf.secret, "application/json", confBody, 60*time.Second)
			}),
		}

		payloads := fmt.Sprintf("Read (steps 1 and 2), POSTed to `%s` with HTTP Basic authentication, the token "+
			"as the password:\n\n```json\n%s\n```\n\nConfiguration (step 3):\n\n```json\n%s\n```\n",
			url, prettyJSON(readBody), prettyJSON(confBody))

		obs := transportObservation(l, "NX-API (HTTPS `ins_api`, `cli_show` and `cli_conf`)", steps, payloads, nxapiCaveats)
		l.resultOver(t, "L7", "NX-API over HTTPS `ins_api`", l7Claim, obs)
		transportAssert(t, "NX-API", steps)
	})
}

const nxapiCaveats = "- The NX-API JSON-RPC dialect (`Content-Type: application/json-rpc`, `\"method\": \"cli\"`). " +
	"Only the `ins_api` envelope is measured here, and the two are different code paths on the device.\n" +
	"- The NX-API sandbox and any cookie or session id the device may hand back in `sid`; every request here " +
	"sends `sid: \"1\"` and carries HTTP Basic credentials.\n" +
	"- HTTP keep-alive: each step opens its own TCP connection.\n" +
	"- `aaa authentication login ascii-authentication` is left at the NX-OS default, so the `auth.method` " +
	"reported above is whatever that default produces. The other setting is unmeasured.\n" +
	"- Whether `aaa authorization config-commands` changes what step 3 sends; this run has it configured and " +
	"nothing to compare it against.\n"

// ---------------------------------------------------------------------------
// NETCONF over SSH
// ---------------------------------------------------------------------------

// netconfEOM is the NETCONF 1.0 end-of-message marker. This client advertises
// base:1.0 only, so every message — in both directions — is terminated by it,
// and the chunked framing of base:1.1 never comes into play. That is a
// deliberate simplification of the client, not a claim about the device.
const netconfEOM = "]]>]]>"

const netconfClientHello = `<?xml version="1.0" encoding="UTF-8"?>
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>urn:ietf:params:netconf:base:1.0</capability>
  </capabilities>
</hello>`

// netconfConn is a NETCONF session over the SSH `netconf` subsystem.
//
// A pump goroutine rather than a plain Read, because ssh.Session has no read
// deadline: a device that accepts the subsystem request and then says nothing
// would hang the test forever, and "the device said nothing" is a result this
// test has to be able to write down.
type netconfConn struct {
	// closeAll tears down the SSH session and its client together. It is a
	// closure rather than the *ssh.Client itself so that this file needs no
	// import of the ssh package: the algorithm lists that make these handshakes
	// work live in harness_test.go, and there should be exactly one copy of them.
	closeAll func()
	data     chan []byte
	errc     chan error
	in       io.WriteCloser
	buf      strings.Builder
	readErr  error
	closed   bool
}

// netconfDial opens a NETCONF session and completes the hello exchange. The
// password is a port49 token, presented exactly as the SSH tests present one.
func (l *lab) netconfDial(user, password string) (*netconfConn, string, error) {
	port := netconfPort(l.p)
	if port == "" {
		return nil, "", fmt.Errorf("this lab does not enable NETCONF on %s", l.p.name)
	}
	c, err := l.dialHostPort(user, password, l.p.addr+":"+port, 60*time.Second)
	if err != nil {
		return nil, "", fmt.Errorf("SSH to the NETCONF port %s: %w", port, err)
	}
	sess, err := c.NewSession()
	if err != nil {
		c.Close()
		return nil, "", fmt.Errorf("open a session on the NETCONF connection: %w", err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		sess.Close()
		c.Close()
		return nil, "", err
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		sess.Close()
		c.Close()
		return nil, "", err
	}
	if err := sess.RequestSubsystem("netconf"); err != nil {
		sess.Close()
		c.Close()
		return nil, "", fmt.Errorf("request the netconf subsystem on port %s: %w", port, err)
	}

	n := &netconfConn{
		data: make(chan []byte, 16),
		errc: make(chan error, 1),
		in:   stdin,
	}
	n.closeAll = func() {
		sess.Close()
		c.Close()
	}
	go func() {
		r := bufio.NewReader(stdout)
		buf := make([]byte, 8192)
		for {
			nn, err := r.Read(buf)
			if nn > 0 {
				cp := make([]byte, nn)
				copy(cp, buf[:nn])
				n.data <- cp
			}
			if err != nil {
				n.errc <- err
				return
			}
		}
	}()

	deviceHello, err := n.read(45 * time.Second)
	if err != nil {
		n.Close()
		return nil, "", fmt.Errorf("the device sent no NETCONF hello: %w", err)
	}
	if err := n.write(netconfClientHello); err != nil {
		n.Close()
		return nil, deviceHello, fmt.Errorf("send the client hello: %w", err)
	}
	return n, deviceHello, nil
}

func (n *netconfConn) write(msg string) error {
	_, err := io.WriteString(n.in, msg+"\n"+netconfEOM+"\n")
	return err
}

// read returns the next complete NETCONF message, without its marker.
func (n *netconfConn) read(within time.Duration) (string, error) {
	deadline := time.Now().Add(within)
	for {
		if i := strings.Index(n.buf.String(), netconfEOM); i >= 0 {
			all := n.buf.String()
			msg := all[:i]
			rest := all[i+len(netconfEOM):]
			n.buf.Reset()
			n.buf.WriteString(rest)
			return strings.TrimSpace(msg), nil
		}
		if n.readErr != nil {
			// The channel is gone and what was buffered holds no complete
			// message. Report the bytes anyway: a device that closed the
			// connection mid-reply has said something worth reading.
			return strings.TrimSpace(n.buf.String()), fmt.Errorf("the NETCONF channel closed: %w", n.readErr)
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return strings.TrimSpace(n.buf.String()),
				fmt.Errorf("no NETCONF end-of-message marker within %v (%d bytes received so far)", within, n.buf.Len())
		}
		select {
		case b := <-n.data:
			n.buf.Write(b)
		case err := <-n.errc:
			// Remember it rather than returning now: the pump may have handed
			// over a complete message just before the channel closed, and the
			// loop above must get a chance to find it.
			n.readErr = err
		case <-time.After(remaining):
		}
	}
}

// rpc sends one RPC and returns the reply. An `<rpc-error>` in the reply is not
// a Go error: it is the device telling this test that the payload below was
// wrong, which is a finding to record rather than a run to abandon.
func (n *netconfConn) rpc(id int, body string) (string, error) {
	msg := fmt.Sprintf(`<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="%d">%s</rpc>`, id, body)
	if err := n.write(msg); err != nil {
		return "", err
	}
	return n.read(60 * time.Second)
}

func (n *netconfConn) Close() {
	if n == nil || n.closed {
		return
	}
	n.closed = true
	if n.in != nil {
		n.in.Close()
	}
	if n.closeAll != nil {
		n.closeAll()
	}
}

// netconfEdit is the per-platform `<edit-config>` payload and the target it
// writes to.
//
// EVERY PAYLOAD HERE IS A GUESS and none has been sent to a device. They were
// written from each vendor's model documentation, which is exactly the kind of
// source this repository does not treat as a measurement. The first run will
// very likely have one or more of them rejected with an `<rpc-error>`; that
// error is recorded verbatim in the note and is what the payload should then be
// rewritten from. The harmless-leaf choice is deliberate in each case — an SNMP
// location or a description changes nothing about how the device forwards.
func netconfEdit(p platform) (target, config, commit string, ok bool) {
	switch p.name {
	case "juniper_vjunos-router", "juniper_vsrx":
		// Junos: candidate datastore, then an explicit commit. This is the one
		// of the three that is closest to certain, because Junos NETCONF has
		// worked this way since it existed.
		return "candidate",
			`<configuration><snmp><location>port49-lab-netconf</location></snmp></configuration>`,
			`<commit/>`, true
	case "cisco_nxos":
		// NX-OS: the device YANG model, written straight to running. Both the
		// namespace and the element names under `snmp-items` are unverified.
		return "running",
			`<System xmlns="http://cisco.com/ns/yang/cisco-nx-os-device">` +
				`<snmp-items><inst-items><locationstring>port49-lab-netconf</locationstring></inst-items></snmp-items>` +
				`</System>`,
			"", true
	case "arista_eos":
		// EOS: OpenConfig, written straight to running. EOS serves several
		// models over NETCONF and which one is mounted depends on configuration
		// this lab does not set, so this is the least certain of the three.
		return "running",
			`<system xmlns="http://openconfig.net/yang/system"><config>` +
				`<login-banner>port49-lab-netconf</login-banner>` +
				`</config></system>`,
			"", true
	}
	return "", "", "", false
}

func TestNETCONFTransportAAA(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		port := netconfPort(l.p)
		if port == "" {
			t.Skipf("%s: this lab does not enable NETCONF on this platform", l.p.name)
		}
		read := netconfRead.check(t, l)
		conf := netconfConfig.check(t, l)

		stop := l.capture(t, "netconf")
		defer stop()

		var hello string
		steps := []transportStep{
			l.runStep("session 1: open and `get-config running`", read.user, func() (string, error) {
				n, dh, err := l.netconfDial(read.user, read.secret)
				hello = dh
				if err != nil {
					return dh, err
				}
				defer n.Close()
				return n.rpc(1, `<get-config><source><running/></source></get-config>`)
			}),
			l.runStep("session 2: open again with the same token", read.user, func() (string, error) {
				n, dh, err := l.netconfDial(read.user, read.secret)
				if err != nil {
					return dh, err
				}
				defer n.Close()
				return n.rpc(1, `<get-config><source><running/></source></get-config>`)
			}),
		}

		target, config, commit, ok := netconfEdit(l.p)
		if !ok {
			steps = append(steps, skippedStep("session 3: edit-config",
				"no edit-config payload is written for this platform in netconfEdit"))
		} else {
			steps = append(steps, l.runStep("session 3: `edit-config` and commit", conf.user, func() (string, error) {
				n, dh, err := l.netconfDial(conf.user, conf.secret)
				if err != nil {
					return dh, err
				}
				defer n.Close()
				edit := fmt.Sprintf(`<edit-config><target><%s/></target><config>%s</config></edit-config>`, target, config)
				out, err := n.rpc(1, edit)
				if err != nil || commit == "" {
					return out, err
				}
				more, err := n.rpc(2, commit)
				return out + "\n\n--- commit ---\n" + more, err
			}))
		}

		payloads := fmt.Sprintf("NETCONF over the SSH `netconf` subsystem on **port %s**, the token presented as "+
			"the SSH password exactly as the interactive tests present one.\n\n"+
			"Read (sessions 1 and 2):\n\n```xml\n<get-config><source><running/></source></get-config>\n```\n\n"+
			"Write (session 3), target `%s`:\n\n```xml\n%s\n```\n\n"+
			"**The write payload above is unverified.** It was written from model documentation and has never "+
			"been sent to this image. If the reply is an `<rpc-error>`, that error — not the documentation — is "+
			"what the payload should be rewritten from.\n\n"+
			"The device's NETCONF hello:\n\n```xml\n%s\n```\n",
			port, target, config, trimForNote(hello))

		obs := transportObservation(l, "NETCONF over SSH (port "+port+")", steps, payloads, netconfCaveats)
		l.resultOver(t, "netconf", "NETCONF over SSH (port "+port+")", netconfClaim, obs)
		transportAssert(t, "NETCONF", steps)
	})
}

// netconfClaim is deliberately not an L-number. Spec §15 has no row for NETCONF
// AAA behavior: L1 asks what `port` contains over NETCONF and L7 covers eAPI
// and NX-API only, so nothing in the register asks whether a NETCONF session
// produces an authorization request at all. Adding a row is not this test's to
// do — see the rules at the top of §15 — so this note is filed under its
// transport, the way `results/juniper_vsrx-config-verified.md` is, and a row is
// proposed in the report that accompanies this branch. Rename the note the day
// the row exists.
const netconfClaim = "Whether a NETCONF session over SSH authenticates through TACACS+ the way an interactive " +
	"login does, whether any authorization request is sent for the session or for an `<edit-config>` and with " +
	"what `service`, `cmd` and `cmd-arg`, what `port` and `rem_addr` contain, what accounting arrives, and " +
	"whether a second session with the same token re-authenticates."

const netconfCaveats = "- base:1.1 chunked framing. This client advertises base:1.0 only.\n" +
	"- Whether a long-lived NETCONF session re-authenticates during its life; each session here is opened, " +
	"used once and closed.\n" +
	"- Key-based SSH authentication to the NETCONF port, which is how automation would really connect and " +
	"would not involve port49 at all.\n" +
	"- `<lock>`, `<validate>` and confirmed commit, any of which may authorize differently from a bare " +
	"`<edit-config>`.\n" +
	"- Whether the `<edit-config>` payload above is even correct for this image; see the note under it.\n"

// ---------------------------------------------------------------------------
// How many TCP connections the device opened
// ---------------------------------------------------------------------------

// transportConnectionNote reads the capture back and reports how many separate
// TCP connections the device opened to port 49 during this test.
//
// This is the single-connect measurement, and it is taken from the capture
// because it cannot be taken from the decision log: a record carries a ctx_id
// and a session, not the TCP connection it arrived on. It matters for the same
// reason Junos's behaviour over SSH mattered — Junos opens a new connection
// with a fresh header session_id per exchange — and a transport that opens one
// connection per API request has a different cost profile at scale from one
// that multiplexes.
func transportConnectionNote(l *lab) string {
	opens, ports, err := pcapTACACSOpens(l.capAbs)
	if err != nil {
		return fmt.Sprintf("Not measured: the capture could not be read back (%v).\n", err)
	}
	if opens == 0 {
		return "No TCP SYN toward port 49 appears in this capture at all. Either the device reused a " +
			"connection opened before this test's capture started, or it never connected.\n"
	}
	shown := ports
	if len(shown) > 12 {
		shown = append(append([]string{}, shown[:12]...), "...")
	}
	return fmt.Sprintf("**%d** TCP connection(s) were opened toward port49d during this test, from source "+
		"port(s) %s.\n\nRead this against the step table above. One connection per authentication exchange "+
		"means the device is not using single-connect; one connection carrying several exchanges means it is, "+
		"or that it is holding the connection across requests. Count them yourself with "+
		"`tcpdump -r %s -n 'tcp port 49 and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'`.\n",
		opens, strings.Join(shown, ", "), l.evidencePath)
}

// pcapTACACSOpens counts the bare SYNs toward TCP 49 in a capture and returns
// the source ports they came from.
//
// It reads the capture through tests/lab/labpcap, the same parser pcapCounts
// and the redactor use, and stops at the same kinds of file rather than
// guessing. A bare SYN — SYN set, ACK clear — is one connection attempt;
// counting SYN-ACKs too would double every connection.
func pcapTACACSOpens(path string) (opens int, srcPorts []string, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, nil, err
	}
	f, err := labpcap.Parse(raw)
	if err != nil {
		return 0, nil, fmt.Errorf("%s: %w", path, err)
	}
	_, subnet, err := net.ParseCIDR(labSubnet)
	if err != nil {
		return 0, nil, err
	}

	seen := map[string]bool{}
	for _, r := range f.Records {
		fl, ok := labpcap.FlowOf(f.Link, f.Bytes(r))
		if !ok || !subnet.Contains(fl.Src) {
			continue
		}
		if fl.DstPort != labpcap.Port || !fl.SYN() {
			continue
		}
		opens++
		p := fmt.Sprintf("%d", fl.SrcPort)
		if !seen[p] {
			seen[p] = true
			srcPorts = append(srcPorts, p)
		}
	}
	sort.Strings(srcPorts)
	return opens, srcPorts, nil
}
