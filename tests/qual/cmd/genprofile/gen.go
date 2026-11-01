package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/blanketfish/port49/internal/devicemock"
)

var allowedFiles = []string{"run.json", "decisions.jsonl", "*.conns.json", "*.tls.json"}

var forbidden = []string{"_sha256", "password", "secret", "BEGIN "}

// hashKey finds a *_sha256 key by name, so a refusal can name it and never its value.
var hashKey = regexp.MustCompile(`"([A-Za-z0-9_]*_sha256)"\s*:`)

const tsLayout = time.RFC3339Nano

// run is run.json as qualRun (Task 12) writes it: the same snake_case tags,
// so lab_platform decodes (encoding/json matches only case, not underscores).
type run struct {
	Platform    string            `json:"platform"`
	LabPlatform string            `json:"lab_platform"`
	Firmware    string            `json:"firmware"`
	Image       string            `json:"image"`
	Commit      string            `json:"commit"`
	Date        string            `json:"date"`
	Transports  []string          `json:"transports"`
	Cells       map[string]string `json:"cells"` // cell -> start time, RFC 3339
	BreakGlass  map[string]bool   `json:"break_glass"`
	Results     map[string]string `json:"results"` // cell -> pass, fail, not_applicable, not_run; observed (observationCells)
	// CommandAuthorization is what a TLS login cell's commands did: sent (port49
	// decided them) or not_sent (no authorize_command for them arrived). A run
	// that predates it graded tls_token_login pass only when they were sent.
	CommandAuthorization map[string]string `json:"command_authorization"`
	// DeniedCommandRan is L80's cell: whether a command port49's policy denies
	// ran over per-request TLS that sent port49 no command authorization.
	DeniedCommandRan map[string]bool `json:"denied_command_ran"`
	// DeniedCommandAsked is whether that command reached port49 as an
	// authorize_command: refused by port49, not by the device (review M2).
	DeniedCommandAsked map[string]bool `json:"denied_command_asked"`
	// TLSServerSingleConnectOffered is whether the build under test offers
	// single-connect to this platform over per-request TLS (decision 50
	// ruling 20): the harness writes it from platform.TLSServerSingleConnect,
	// since the flag itself is inside the ciphertext.
	TLSServerSingleConnectOffered bool `json:"tls_server_single_connect_offered"`
	// TLSCaptureStartedClean is whether no connection was open before or at
	// tls_token_login's capture's start, so none whose SYN the capture
	// missed was open in it (review O1, R3).
	TLSCaptureStartedClean bool `json:"tls_capture_started_clean"`
}

type plainHeader struct {
	Version uint8 `json:"version"`
	Type    uint8 `json:"type"`
	SeqNo   uint8 `json:"seq_no"`
	Flags   uint8 `json:"flags"`
}

type clientHello struct {
	LegacyVersion    uint16   `json:"legacy_version"`
	Versions         []uint16 `json:"supported_versions"`
	Suites           []uint16 `json:"cipher_suites"`
	HasSNI           bool     `json:"has_sni"`
	SNI              string   `json:"sni"`
	Groups           []uint16 `json:"supported_groups"`
	SigAlgs          []uint16 `json:"signature_algorithms"`
	ALPN             []string `json:"alpn"`
	PSKIdentities    int      `json:"psk_identities"`
	PSKModes         []uint8  `json:"psk_key_exchange_modes"`
	CompressCertAlgs []uint16 `json:"compress_certificate_algorithms"` // absent in older summaries: not offered
	KeyShareGroups   []uint16 `json:"key_share_groups"`                // absent in older summaries: not recorded
	Extensions       []uint16 `json:"extensions"`
}

type serverHello struct {
	SelectedVersion   uint16 `json:"selected_version"`
	CipherSuite       uint16 `json:"cipher_suite"`
	HelloRetryRequest bool   `json:"hello_retry_request"`
}

type conn struct {
	Server         string        `json:"server"`
	Plain          []plainHeader `json:"plain_tacacs_from_device"`
	Hello          *clientHello  `json:"client_hello"`
	ServerHello    *serverHello  `json:"server_hello"`
	ServerFlightAt time.Time     `json:"server_flight_at"`
	DeviceReplyAt  time.Time     `json:"device_reply_at"`
	SYNAt          time.Time     `json:"syn_at"`
	End            string        `json:"end"` // device-fin, server-fin, device-rst, server-rst, open
	EndAt          time.Time     `json:"end_at"`
}

// rec is one whitelisted decision record (qualRecord's shape).
type rec struct {
	TS           string `json:"ts"`
	Event        string `json:"event"`
	Verdict      string `json:"verdict"`
	Reason       string `json:"reason"`
	Flags        string `json:"flags"`
	Diagnosis    string `json:"diagnosis"`
	Transport    string `json:"transport"` // an unvalidated record's own
	TLSOutcome   string `json:"tls_outcome"`
	PacketFields *struct {
		Action       string `json:"action"`
		AuthenType   string `json:"authen_type"`
		Service      string `json:"service"`
		AuthenMethod string `json:"authen_method"`
		PrivLvl      *uint8 `json:"priv_lvl"`
	} `json:"packet_fields"`
	Device struct {
		Transport string `json:"transport"`
	} `json:"device"`
	Session struct {
		Port     string `json:"port"`
		Username string `json:"username"`
	} `json:"session"`
	Request struct {
		Raw []string `json:"raw"`
	} `json:"request"`
	Reply struct {
		Attributes []string `json:"attributes"`
	} `json:"reply"`
	Record struct {
		Raw []string `json:"raw"`
	} `json:"record"`

	at time.Time
	n  int // position in the file, for messages
}

func (r *rec) transport() string {
	if r.Device.Transport != "" {
		return r.Device.Transport
	}
	return r.Transport
}

// scenarioCells: which lab cells' windows make each mock scenario's golden, and
// over which transport. The mock's token_login plays every stimulus step, which
// the lab spreads over four cells; their records, in stimulus step order, are
// that golden. The TLS cell runs the same sequence (Task 12), so it is one cell.
// flight_delay plays tls_token_login's login alone.
var scenarioCells = map[string]struct {
	cells     []string
	transport string
}{
	"token_login":           {[]string{"token_login", "command_permitted", "command_denied", "accounting"}, "tcp"},
	"wrong_credential":      {[]string{"wrong_credential"}, "tcp"},
	"store_unavailable":     {[]string{"store_unavailable"}, "tcp"},
	"single_connection":     {[]string{"single_connection"}, "tcp"}, // the full sequence in one cell (Task 12)
	"tls_token_login":       {[]string{"tls_token_login"}, "tls"},
	"tls_store_unavailable": {[]string{"tls_store_unavailable"}, "tls"},
	"flight_delay":          {[]string{"tls_token_login"}, "tls"},
	"tls_single_connection": {[]string{"tls_single_connection"}, "tls"},
}

// scenarioOrder is the order scenarios are listed in; tls_unknown_ca is built apart.
var scenarioOrder = []string{"token_login", "wrong_credential", "store_unavailable", "single_connection",
	"tls_token_login", "tls_store_unavailable", "tls_unknown_ca", "flight_delay", "tls_single_connection"}

// Generate builds a profile's stimulus and a first golden from one
// conformance run's evidence directory, and pre-fills the reactions it shows.
// It refuses any file it does not know, and any file holding a forbidden
// string, before it reads a record.
func Generate(evDir, repoRoot string) (*devicemock.Profile, devicemock.Golden, error) {
	var g devicemock.Golden
	if err := audit(evDir); err != nil {
		return nil, g, err
	}
	var r run
	if err := readJSON(filepath.Join(evDir, "run.json"), &r); err != nil {
		return nil, g, err
	}
	recs, err := readRecords(filepath.Join(evDir, "decisions.jsonl"))
	if err != nil {
		return nil, g, err
	}
	if err := checkResults(&r); err != nil {
		return nil, g, err
	}
	win, err := cellWindows(r.Cells)
	if err != nil {
		return nil, g, err
	}
	slug := devicemock.Slug(r.Firmware)
	// The conformance note is no register row: it re-measures the rows its cells
	// cite (decision 52 ruling 10), so its sources name "QUAL" as the register.
	note := devicemock.Source{Note: fmt.Sprintf("tests/lab/results/QUAL-%s-%s.md", slug, r.LabPlatform), Register: "QUAL"}
	p := &devicemock.Profile{SchemaVersion: 1, Platform: r.Platform, LabPlatform: r.LabPlatform, Firmware: r.Firmware,
		Image: r.Image, Transports: r.Transports,
		Vetted: devicemock.Vetted{Date: r.Date, Commit: r.Commit,
			Evidence: fmt.Sprintf("tests/lab/evidence/QUAL-%s-%s/", slug, r.LabPlatform), Notes: []string{note.Note}},
		Golden: fmt.Sprintf("tests/qual/golden/%s/%s.json", r.Platform, slug)}
	p.Stimulus.Sources = []devicemock.Source{note}

	base := "token_login"
	if !slices.Contains(r.Transports, "tcp") {
		base = "tls_token_login"
	}
	baseRecs, err := scenarioRecords(recs, win, &r, base)
	if err != nil {
		return nil, g, err
	}
	if p.Stimulus.Steps, err = steps(baseRecs, &r); err != nil {
		return nil, g, err
	}
	// The marker is read from run.json, not inferred from steps(): both command cells
	// must be graded not_applicable (the device sends no per-command authorization).
	if r.Results["command_permitted"] == "not_applicable" && r.Results["command_denied"] == "not_applicable" {
		// A missing L18 note only means L18 measured no firmware of this lab platform.
		l18, _ := os.ReadFile(filepath.Join(repoRoot, "tests/lab/results", "L18-"+r.LabPlatform+".md"))
		p.EngineGaps = append(p.EngineGaps, noCommandAuthorizationGap(r.Platform, r.Firmware, l18, note))
	}
	if p.DeviceFacts, err = tlsFacts(&r, note); err != nil {
		return nil, g, err
	}
	if r.TLSServerSingleConnectOffered {
		var cs []conn
		if err := readJSON(filepath.Join(evDir, "tls_token_login.tls.json"), &cs); err != nil {
			return nil, g, err
		}
		tlsRecs, err := scenarioRecords(recs, win, &r, "tls_token_login")
		if err != nil {
			return nil, g, err
		}
		if f := serverSingleConnectFact(true, r.TLSCaptureStartedClean, cs, tlsRecs, note); f != nil {
			p.DeviceFacts = append(p.DeviceFacts, *f)
		}
	}
	if err := minorVersions(evDir, &r, p, note); err != nil {
		return nil, g, err
	}
	if p.Stimulus.Connections, err = connPattern(evDir, len(p.Stimulus.Steps)); err != nil {
		return nil, g, err
	}
	if tls, err := tlsStimulus(evDir, note); err != nil {
		return nil, g, err
	} else if tls != nil {
		p.Stimulus.TLS = tls
	}
	var all []*rec
	for _, x := range recs {
		if x.Event != "unvalidated" && x.Session.Username == "{user}" {
			all = append(all, x)
		}
	}
	p.Reactions = prefillReactions(all, &r, note)
	p.Acceptance = prefillAcceptance(all, note)
	p.Scenarios = scenarios(&r)
	if p.Stimulus.TLS != nil && p.Stimulus.TLS.FlightDelay == 0 {
		p.Scenarios = slices.DeleteFunc(p.Scenarios, func(sc string) bool { return sc == "flight_delay" })
	}
	if g, err = goldenFrom(p, recs, win, &r); err != nil {
		return nil, g, err
	}
	return p, g, nil
}

// tlsFacts are the device facts run.json's command_authorization records: a
// TLS login cell whose commands reached port49 as no authorize_command is a
// measured fact citing the run's note, never an engine gap and never inferred
// from absent records. The per-request fact says what single-connection and
// L80's cell measured, because an operator acts on them.
func tlsFacts(r *run, note devicemock.Source) ([]devicemock.DeviceFact, error) {
	// L80's cell writes a note of its own; its fact cites that note.
	l80 := []devicemock.Source{{Note: fmt.Sprintf("tests/lab/results/L80-%s.md", r.LabPlatform), Register: "L80"}}
	for cell, v := range r.CommandAuthorization {
		if v != "sent" && v != "not_sent" && v != "not_applicable" {
			return nil, fmt.Errorf("run.json: command_authorization %s is %q, neither sent, not_sent nor not_applicable", cell, v)
		}
	}
	src := []devicemock.Source{note}
	var out []devicemock.DeviceFact
	if r.CommandAuthorization["tls_token_login"] == "not_sent" {
		what := "Over per-request TLS (the device default) the device sent port49 no command authorization for the commands typed (QUAL tls_token_login)"
		switch r.CommandAuthorization["tls_single_connection"] {
		case "sent":
			what += "; with single-connection on it did (QUAL tls_single_connection): configure single-connection on its TLS servers, or port49's command rules never see a command"
		case "not_sent":
			what += "; with single-connection on it sent none either (QUAL tls_single_connection)"
		default:
			what += "; single-connection was not measured"
		}
		ran, measured := r.DeniedCommandRan["tls_denied_command"]
		if !measured {
			what += "; whether a command port49's policy denies then runs is unmeasured here (L80 is open)"
		}
		out = append(out, devicemock.DeviceFact{ID: devicemock.FactTLSPerRequestNoCommands, What: what, Status: "measured", Sources: src})
		switch {
		case measured && ran:
			out = append(out, devicemock.DeviceFact{ID: devicemock.FactTLSPerRequestDeniedRuns, Status: "measured", Sources: l80,
				What: "Over per-request TLS a command port49's policy denies runs: port49 was never asked about the denied command, and the device ran it (L80). " +
					"Port49's command rules do not hold on this device over per-request TLS"})
		case measured && r.DeniedCommandAsked["tls_denied_command"]:
			out = append(out, devicemock.DeviceFact{ID: devicemock.FactTLSPerRequestDeniedByPort49, Status: "measured", Sources: l80,
				What: "Over per-request TLS the device asked port49 about a command port49's policy denies, and port49 denied it (L80)"})
		case measured:
			out = append(out, devicemock.DeviceFact{ID: devicemock.FactTLSPerRequestDeniedRefused, Status: "measured", Sources: l80,
				What: "Over per-request TLS a command port49's policy denies was refused by the device itself, port49 never asked (L80)"})
		}
	}
	if r.CommandAuthorization["tls_single_connection"] == "not_sent" {
		out = append(out, devicemock.DeviceFact{ID: devicemock.FactTLSSingleNoCommands,
			What:   "With single-connection on, over TLS the device sent port49 no command authorization for the commands typed (QUAL tls_single_connection)",
			Status: "measured", Sources: src})
	}
	return out, nil
}

// StimulusEqual compares what genprofile generates and nothing reviewed:
// stimulus, platform, firmware and transports. client_chain and server_identity
// are review-left defaults, so they are blanked on both sides.
func StimulusEqual(a, b *devicemock.Profile) bool {
	return a.Platform == b.Platform && a.Firmware == b.Firmware &&
		slices.Equal(a.Transports, b.Transports) && stimulusYAML(a) == stimulusYAML(b)
}

// stimulusYAML is the stimulus as it is written, so a profile read back from
// disk (empty lists) equals one just generated (nil lists).
func stimulusYAML(p *devicemock.Profile) string {
	st := p.Stimulus
	if st.TLS != nil {
		t := *st.TLS
		t.ClientChain, t.ServerIdentity = "", ""
		st.TLS = &t
	}
	b, err := yaml.Marshal(st)
	if err != nil {
		return err.Error()
	}
	return string(b)
}

// audit refuses any file that is not whitelisted evidence and any whitelisted
// file holding a forbidden string. It names files and keys, never content.
func audit(evDir string) error {
	entries, err := os.ReadDir(evDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		ok := false
		for _, pat := range allowedFiles {
			if m, _ := filepath.Match(pat, e.Name()); m {
				ok = true
			}
		}
		if !ok {
			return fmt.Errorf("%s: %s is not evidence genprofile reads (it never reads a capture)", evDir, e.Name())
		}
		body, err := os.ReadFile(filepath.Join(evDir, e.Name()))
		if err != nil {
			return err
		}
		for _, f := range forbidden {
			if !strings.Contains(string(body), f) {
				continue
			}
			what := f
			if m := hashKey.FindSubmatch(body); f == "_sha256" && m != nil {
				what = string(m[1])
			}
			return fmt.Errorf("%s/%s holds %q: refused, never filtered here", evDir, e.Name(), what)
		}
	}
	return nil
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	return nil
}

func readRecords(path string) ([]*rec, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []*rec
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		r := &rec{n: n}
		if err := json.Unmarshal([]byte(line), r); err != nil {
			return nil, fmt.Errorf("decisions.jsonl line %d: %w", n, err)
		}
		if r.at, err = time.Parse(tsLayout, r.TS); err != nil {
			return nil, fmt.Errorf("decisions.jsonl line %d (event %q): no usable ts; the run predates the ts field", n, r.Event)
		}
		out = append(out, r)
	}
	return out, sc.Err()
}

// observationCells are measurement cells, not qualification checks: their
// verdict is observed, whatever the device did (L80's, ruling 2026-10-21).
var observationCells = map[string]bool{"tls_denied_command": true}

// checkResults refuses a run with a cell that failed or has no result.
// not_applicable and not_run pass: TestQualify grades the TLS cells not_run on
// an image with no RFC 9887 client and single_connection not_run on one with no
// single-connection form, and a scenario whose cell did not run is not listed.
func checkResults(r *run) error {
	var bad []string
	cells := map[string]bool{}
	for c := range r.Cells {
		cells[c] = true
	}
	for c := range r.Results {
		cells[c] = true
	}
	for cell := range cells {
		switch v := r.Results[cell]; {
		case v == "pass" || v == "not_applicable" || v == "not_run":
		case v == "observed" && observationCells[cell]:
		case v == "":
			bad = append(bad, cell+" (no result)")
		default:
			bad = append(bad, cell+" ("+v+")")
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return fmt.Errorf("run.json: cells failed or have no result: %s", strings.Join(bad, ", "))
	}
	return nil
}

type window struct{ start, end time.Time } // end is zero for the last window

func (w window) has(t time.Time) bool {
	return !t.Before(w.start) && (w.end.IsZero() || t.Before(w.end))
}

// cellWindows gives each cell the span from its start to the next strictly
// later start time of any cell. Cells that share a start time (TestQualify's
// command_permitted and command_denied come from one login) share a window.
func cellWindows(cells map[string]string) (map[string]window, error) {
	starts := map[string]time.Time{}
	var distinct []time.Time
	for name, s := range cells {
		t, err := time.Parse(tsLayout, s)
		if err != nil {
			return nil, fmt.Errorf("run.json: cell %s has no usable start time", name)
		}
		starts[name] = t
		distinct = append(distinct, t)
	}
	sort.Slice(distinct, func(i, j int) bool { return distinct[i].Before(distinct[j]) })
	out := map[string]window{}
	for name, t := range starts {
		w := window{start: t}
		for _, d := range distinct {
			if d.After(t) {
				w.end = d
				break
			}
		}
		out[name] = w
	}
	return out, nil
}

// cellsOf is a scenario's cells that ran. A cell with no start time is allowed
// only when run.json grades it not_applicable (Junos command cells, L18).
func cellsOf(r *run, sc string) ([]string, error) {
	var out []string
	for _, c := range scenarioCells[sc].cells {
		if _, ok := r.Cells[c]; ok {
			out = append(out, c)
		} else if r.Results[c] != "not_applicable" {
			return nil, fmt.Errorf("scenario %s: cell %s has no start time in run.json", sc, c)
		}
	}
	return out, nil
}

// scenarioRecords is the scenario's records, in file order, each once: those
// inside any of its cells' windows, on its transport.
func scenarioRecords(recs []*rec, win map[string]window, r *run, sc string) ([]*rec, error) {
	cells, err := cellsOf(r, sc)
	if err != nil {
		return nil, err
	}
	var out []*rec
	for _, x := range recs {
		if x.Event == "unvalidated" || !transportIs(x, scenarioCells[sc].transport) {
			continue
		}
		for _, c := range cells {
			if win[c].has(x.at) {
				out = append(out, x)
				break
			}
		}
	}
	return out, nil
}

func transportIs(x *rec, want string) bool {
	if want == "tls" {
		return x.transport() == "tls"
	}
	return x.transport() != "tls"
}

// stepOf is the stimulus step a record belongs to, or "".
func stepOf(x *rec) string {
	switch x.Event {
	case "redeem":
		return "login"
	case "authorize_session":
		return "authorize_session"
	case "authorize_command":
		switch x.Verdict {
		case "permit":
			return "command_permitted"
		case "deny":
			return "command_denied"
		}
	case "account":
		switch x.Flags {
		case "start":
			return "account_start"
		case "stop":
			return "account_stop"
		}
	}
	return ""
}

var stepOrder = []string{"login", "authorize_session", "command_permitted", "command_denied", "account_start", "account_stop"}

var stepType = map[string]string{"login": "authen", "authorize_session": "author", "command_permitted": "author",
	"command_denied": "author", "account_start": "acct", "account_stop": "acct"}

// first is the first record for step by the login's own user ({user}): a
// device's own accounts (SR Linux's root, on port unknown) are never the login's.
func first(rs []*rec, step string) *rec {
	for _, x := range rs {
		if x.Session.Username == "{user}" && stepOf(x) == step {
			return x
		}
	}
	return nil
}

// steps reads each step's fields from the first matching {user} record. A
// command step is skipped only when run.json grades its cell not_applicable.
func steps(rs []*rec, r *run) ([]devicemock.Step, error) {
	var out []devicemock.Step
	for _, name := range stepOrder {
		x := first(rs, name)
		if x == nil {
			if r.Results[name] == "not_applicable" && strings.HasPrefix(name, "command_") {
				continue
			}
			return nil, fmt.Errorf("no %s record for the login in the token_login cells", name)
		}
		if x.PacketFields == nil || x.PacketFields.PrivLvl == nil {
			return nil, fmt.Errorf("%s (decisions.jsonl line %d) has no packet_fields.priv_lvl; the run predates Task 5", name, x.n)
		}
		pf := x.PacketFields
		s := devicemock.Step{Name: name, Type: stepType[name], Port: x.Session.Port,
			Fields: devicemock.PacketFields{Action: pf.Action, AuthenType: pf.AuthenType, Service: pf.Service,
				AuthenMethod: pf.AuthenMethod, PrivLvl: *pf.PrivLvl}}
		switch stepType[name] {
		case "author":
			s.Args = x.Request.Raw
		case "acct":
			s.Args, s.Flags = x.Record.Raw, x.Flags
		}
		out = append(out, s)
	}
	return out, nil
}

// readConns reads one cell's connection summaries; a cell with no file has none.
func readConns(evDir, name string) ([]conn, error) {
	var cs []conn
	err := readJSON(filepath.Join(evDir, name), &cs)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return cs, err
}

var plainCells = []string{"token_login", "command_permitted", "command_denied", "accounting"}

// plainConns is the union of the token_login scenario's cells' connections: a
// login's steps are spread over several cells, so one file undercounts.
func plainConns(evDir string) ([]conn, error) {
	var out []conn
	for _, c := range plainCells {
		cs, err := readConns(evDir, c+".conns.json")
		if err != nil {
			return nil, err
		}
		out = append(out, cs...)
	}
	return out, nil
}

var typeCode = map[string]uint8{"authen": 1, "author": 2, "acct": 3}

// minorVersionFile is the conns file a step's header comes from.
var minorVersionFile = map[string]string{"login": "token_login", "authorize_session": "token_login",
	"command_permitted": "command_permitted", "command_denied": "command_denied",
	"account_start": "accounting", "account_stop": "accounting"}

// minorVersions sets each step's minor version from the first header of its
// type (M4: the low nibble of the version byte). A run with a tcp transport has
// the headers, and a missing type is an error. Only a run with no tcp transport
// hides them: its authen steps get 1 for pap, chap, mschap and mschapv2 (RFC
// 8907 section 5.4.2) and every other step 0, each with an engine gap saying so.
func minorVersions(evDir string, r *run, p *devicemock.Profile, note devicemock.Source) error {
	cs, err := plainConns(evDir)
	if err != nil {
		return err
	}
	single, err := readConns(evDir, "single_connection.conns.json")
	if err != nil {
		return err
	}
	versions := map[uint8]uint8{}
	for _, c := range append(cs, single...) {
		for _, h := range c.Plain {
			if _, ok := versions[h.Type]; !ok {
				versions[h.Type] = h.Version & 0x0f
			}
		}
	}
	tlsOnly := !slices.Contains(r.Transports, "tcp")
	for i := range p.Stimulus.Steps {
		s := &p.Stimulus.Steps[i]
		if v, ok := versions[typeCode[s.Type]]; ok {
			s.MinorVersion = v
			continue
		}
		if !tlsOnly {
			return fmt.Errorf("step %s: no %s header in %s.conns.json; a tcp run's minor version is read, never inferred",
				s.Name, s.Type, minorVersionFile[s.Name])
		}
		if s.Type == "authen" && slices.Contains([]string{"pap", "chap", "mschap", "mschapv2"}, s.Fields.AuthenType) {
			s.MinorVersion = 1
		}
		p.EngineGaps = append(p.EngineGaps, devicemock.EngineGap{ID: "minor_version_inferred_over_tls",
			What:    fmt.Sprintf("step %s: TLS hides the header, so its minor version %d is inferred from authen_type", s.Name, s.MinorVersion),
			Sources: []devicemock.Source{note}})
	}
	return nil
}

// connPattern decides per_step or single_connection from the connections the
// token_login scenario's cells made together, never from one cell. With
// neither condition met it leaves the mode empty, so the profile fails Load
// loudly: a mode is never guessed.
func connPattern(evDir string, n int) (devicemock.ConnPattern, error) {
	var cp devicemock.ConnPattern
	cs, err := plainConns(evDir)
	if err != nil {
		return cp, err
	}
	flag := func(c conn) bool { return len(c.Plain) > 0 && c.Plain[0].Flags&0x04 != 0 }
	if len(cs) >= n && n > 0 {
		cp.Mode, cp.SingleConnectFlag = "per_step", flag(cs[0])
		return cp, nil
	}
	single, err := readConns(evDir, "single_connection.conns.json")
	if err != nil {
		return cp, err
	}
	for _, c := range single {
		if len(c.Plain) >= n && n > 0 {
			cp.Mode, cp.SingleConnectFlag = "single_connection", flag(c)
			return cp, nil
		}
	}
	return cp, nil
}

// tlsStimulus returns nil when the run recorded no TLS summary.
func tlsStimulus(evDir string, note devicemock.Source) (*devicemock.TLSStimulus, error) {
	files, _ := filepath.Glob(filepath.Join(evDir, "*.tls.json"))
	if len(files) == 0 {
		return nil, nil
	}
	sort.Strings(files)
	var login []conn
	if err := readJSON(filepath.Join(evDir, "tls_token_login.tls.json"), &login); err != nil {
		return nil, err
	}
	t := &devicemock.TLSStimulus{ClientChain: "leaf_and_intermediate", ServerIdentity: "chain_only",
		Sources: []devicemock.Source{note}}
	found := false
	for _, c := range login {
		// A full handshake's hello, never a resumption's (I3).
		if c.Hello == nil || c.ServerHello == nil || c.Hello.PSKIdentities != 0 {
			continue
		}
		h := c.Hello
		t.ClientHello = devicemock.Hello{LegacyVersion: h.LegacyVersion, SupportedVersions: h.Versions,
			CipherSuites: h.Suites, SupportedGroups: h.Groups, SignatureAlgorithms: h.SigAlgs, ALPN: h.ALPN,
			PSKModes: h.PSKModes, CompressCertAlgs: h.CompressCertAlgs, KeyShareGroups: h.KeyShareGroups, Extensions: h.Extensions}
		host := c.Server
		if i := strings.LastIndex(host, ":"); i >= 0 {
			host = host[:i]
		}
		if h.HasSNI && h.SNI == host {
			t.ClientHello.SNI = "{server_ip}"
		}
		t.ServerHello = devicemock.ServerHello(*c.ServerHello)
		found = true
		break
	}
	if !found {
		return nil, errors.New("tls_token_login.tls.json holds no full handshake (psk_identities 0) with both hellos")
	}
	var min time.Duration
	for _, f := range files {
		var cs []conn
		if err := readJSON(f, &cs); err != nil {
			return nil, err
		}
		for _, c := range cs {
			if c.ServerFlightAt.IsZero() || c.DeviceReplyAt.IsZero() {
				continue
			}
			if d := c.DeviceReplyAt.Sub(c.ServerFlightAt); d >= 0 && (min == 0 || d < min) {
				min = d
			}
		}
	}
	// No observed delay: none is written, and Generate drops the flight_delay scenario.
	t.FlightDelay = time.Duration(math.Round(float64(min)/1e7) * 1e7)
	return t, nil
}

func add(rs *[]devicemock.Reaction, x devicemock.Reaction) {
	for _, e := range *rs {
		if e.Step == x.Step && e.On == x.On {
			return
		}
	}
	*rs = append(*rs, x)
}

// eventOf is the class event the mock sees for the reply to a record, and the
// reply arguments it carries.
func eventOf(x *rec) (string, []string, error) {
	switch x.Event {
	case "redeem":
		switch {
		case x.Reason == "store_unavailable":
			return "authen_error", nil, nil
		case x.Verdict == "permit":
			return "authen_pass", nil, nil
		case x.Verdict == "deny":
			return "authen_fail", nil, nil
		}
	case "authorize_session", "authorize_command":
		switch x.Verdict {
		case "permit":
			return "author_pass_add", x.Reply.Attributes, nil
		case "deny":
			return "author_fail", nil, nil
		}
	case "account":
		// port49d's account record carries no verdict (acct.go): a logged account
		// record was acknowledged SUCCESS unless the spool's sync failed, which a
		// lab run does not show. A record with a verdict is not port49d's.
		if x.Verdict == "" {
			return "acct_success", nil, nil
		}
	}
	return "", nil, fmt.Errorf("decisions.jsonl line %d: %s record with verdict %q has no reply class", x.n, x.Event, x.Verdict)
}

// prefillReactions writes one measured entry per (step, event) the records
// show, citing the run's own note. Reactions are reviewed by hand afterwards.
func prefillReactions(rs []*rec, r *run, note devicemock.Source) []devicemock.Reaction {
	var out []devicemock.Reaction
	src := []devicemock.Source{note}
	for _, x := range rs {
		step := stepOf(x)
		if step == "" && x.Event == "redeem" {
			step = "login"
		}
		ev, _, err := eventOf(x)
		if step == "" || err != nil {
			continue
		}
		re := devicemock.Reaction{Step: step, On: ev, Status: "measured", Sources: src}
		switch ev {
		case "authen_pass", "author_pass_add", "author_fail", "acct_success":
			re.Then = "next_step"
		case "authen_fail":
			re.Then, re.Outcome = "stop", "login_refused"
		case "authen_error":
			re.Then, re.Outcome = "give_up", "break_glass_fails"
			if r.BreakGlass["store_unavailable"] {
				re.Then, re.Outcome = "failover_local", "falls_to_local"
			}
		default:
			continue
		}
		if step == "login" && x.PacketFields != nil && x.PacketFields.AuthenType == "ascii" {
			add(&out, devicemock.Reaction{Step: step, On: "authen_getpass", Then: "send_credential", Status: "measured", Sources: src})
		}
		add(&out, re)
	}
	return out
}

// prefillAcceptance writes the one rule the records can suggest: the range of
// priv_lvl the device sent, unmeasured, since seeing values measures no limit.
// A rule is measured only when a results note for this firmware measured it
// (ruling 4), so none is generated measured; unmeasured rules never gate.
func prefillAcceptance(rs []*rec, note devicemock.Source) []devicemock.AcceptanceRule {
	lo, hi := 256, -1
	for _, x := range rs {
		if x.PacketFields == nil || x.PacketFields.PrivLvl == nil {
			continue
		}
		v := int(*x.PacketFields.PrivLvl)
		lo, hi = min(lo, v), max(hi, v)
	}
	if hi < 0 {
		return nil
	}
	return []devicemock.AcceptanceRule{{ID: "priv_lvl_range", Kind: "priv_lvl_range", Applies: "authorize_session",
		Min: lo, Max: hi, Status: "unmeasured", Sources: []devicemock.Source{note},
		Note: "the privilege levels the device sent; seeing values measures no limit"}}
}

// scenarios lists the scenarios the run recorded, in the order of scenarioOrder.
func scenarios(r *run) []string {
	var out []string
	for _, sc := range scenarioOrder {
		cell := sc
		if sc == "flight_delay" {
			cell = "tls_token_login"
		}
		if _, ok := r.Cells[cell]; !ok || r.Results[cell] == "not_run" {
			continue
		}
		if tr := devicemock.ScenarioTransport(sc); slices.Contains(r.Transports, tr) {
			out = append(out, sc)
		}
	}
	return out
}

// goldenFrom builds each scenario's golden from the explicit map of lab cells
// to scenarios, in the order the mock plays the steps. The outcome is the
// profile's own reaction to the first step that did not pass, else login_ok.
func goldenFrom(p *devicemock.Profile, recs []*rec, win map[string]window, r *run) (devicemock.Golden, error) {
	g := devicemock.Golden{Scenarios: map[string]devicemock.GoldenScenario{}}
	for _, sc := range p.Scenarios {
		if sc == "tls_unknown_ca" {
			gs, err := unknownCA(recs, win, sc)
			if err != nil {
				return g, err
			}
			g.Scenarios[sc] = gs
			continue
		}
		rs, err := scenarioRecords(recs, win, r, sc)
		if err != nil {
			return g, err
		}
		gs := devicemock.GoldenScenario{Outcome: "login_ok"}
	steps:
		for _, name := range devicemock.PlayedSteps(p, sc) {
			x := first(rs, name)
			if x == nil {
				return g, fmt.Errorf("scenario %s: no %s record in its cells", sc, name)
			}
			ev, args, err := eventOf(x)
			if err != nil {
				return g, fmt.Errorf("scenario %s: %w", sc, err)
			}
			gs.Steps = append(gs.Steps, devicemock.GoldenStep{Step: name, Event: ev, Args: args})
			re, err := p.React(name, ev)
			if err != nil {
				return g, fmt.Errorf("scenario %s: no reaction for %s at %s", sc, ev, name)
			}
			switch re.Then {
			case "next_step", "reuse_connection", "new_connection":
			default:
				gs.Outcome = re.Outcome
				break steps
			}
		}
		g.Scenarios[sc] = gs
	}
	return g, nil
}

// unknownCA is the class event on the login: the device's refusal is an alert
// or a reset that race, and under TLS 1.3 the alert is encrypted. It requires
// port49's own unvalidated record in the cell's window, naming the cell if absent.
func unknownCA(recs []*rec, win map[string]window, sc string) (devicemock.GoldenScenario, error) {
	w, ok := win[sc]
	if ok {
		for _, x := range recs {
			if x.Event == "unvalidated" && x.Diagnosis == "tls_refused" && x.TLSOutcome == "unknown_ca" && w.has(x.at) {
				return devicemock.GoldenScenario{Outcome: "handshake_refused",
					Steps: []devicemock.GoldenStep{{Step: "login", Event: "tls_refused"}}}, nil
			}
		}
	}
	return devicemock.GoldenScenario{}, fmt.Errorf("cell %s holds no tls_refused / unknown_ca record from port49", sc)
}

// noCommandAuthorizationGap is the engine gap for a device that sends no
// per-command authorization: Junos's is L18's, SR Linux's is L76 cell b's. A
// Junos firmware L18 did not measure (l18, its note, names no such image) is
// backed by its own QUAL records, as L18 found: "(QUAL; as L18)".
func noCommandAuthorizationGap(platform, firmware string, l18 []byte, note devicemock.Source) devicemock.EngineGap {
	if platform == "nokia_srlinux" {
		return devicemock.EngineGap{ID: "command_authorization_not_sent",
			What:    "the device sends no per-command authorization (L76 cell b); its command cells are not_applicable",
			Sources: []devicemock.Source{note, {Note: "tests/lab/results/L76-nokia_srlinux.md", Register: "L76"}}}
	}
	cite := "QUAL; as L18"
	if devicemock.NoteNamesFirmware(l18, firmware) {
		cite = "L18"
	}
	return devicemock.EngineGap{ID: "command_authorization_not_sent",
		What:    "the device sends no per-command authorization (" + cite + "); its command cells are not_applicable",
		Sources: []devicemock.Source{note}}
}

// serverSingleConnectFact grades whether the device honored port49's offer
// of single-connect over per-request TLS (spec §13 decision 50 ruling 20;
// design Task 7 RI4), in header terms only: the TLS cell's connections from
// its header-only summary, and port49's own records of the cell. The
// TACACS+ header is inside the ciphertext, so whether port49 offered is
// run.json's, which the harness writes from the build under test's own wire
// fact.
//
// A record carries no connection identity (no source port or connection id;
// cert_sha256 is the device's on every connection), so it is placed by time.
// The fact is absent, never a guess, when the capture did not start clean
// (clean: no connection open before or at its start, so none whose SYN it
// missed was open), when any two of the cell's connections overlap, or when
// a record falls in no connection.
//
//   - honored: a connection carried a session after a completed one that
//     was not accounting. That is reuse, not arm E's pipelining behind an
//     accounting record.
//   - ignored: every connection that carried a session carried exactly one.
//   - nil, no claim: port49 did not offer, a record could not be placed, or
//     neither holds.
func serverSingleConnectFact(offered, clean bool, conns []conn, recs []*rec, note devicemock.Source) *devicemock.DeviceFact {
	if !offered || !clean {
		return nil
	}
	open := func(c conn) time.Time {
		if c.End == "open" || c.EndAt.IsZero() {
			return time.Time{}
		}
		return c.EndAt
	}
	// overlaps reports whether a and b were open at once.
	overlaps := func(a, b conn) bool {
		aEnd, bEnd := open(a), open(b)
		return (aEnd.IsZero() || !b.SYNAt.After(aEnd)) && (bEnd.IsZero() || !a.SYNAt.After(bEnd))
	}
	// Any two connections open at once make the cell no claim: an
	// overlapping pair with no records looks just like parallel
	// connections refused, the ignored signature (review O2).
	for i := range conns {
		for j := i + 1; j < len(conns); j++ {
			if overlaps(conns[i], conns[j]) {
				return nil
			}
		}
	}
	per := make([][]*rec, len(conns))
	for _, x := range recs {
		in := slices.IndexFunc(conns, func(c conn) bool {
			end := open(c)
			return !x.at.Before(c.SYNAt) && (end.IsZero() || !x.at.After(end))
		})
		if in < 0 {
			return nil // inside no connection
		}
		per[in] = append(per[in], x)
	}
	reused, carried, single := false, 0, true
	for _, rs := range per {
		if len(rs) == 0 {
			continue
		}
		carried++
		single = single && len(rs) == 1
		slices.SortFunc(rs, func(a, b *rec) int { return a.at.Compare(b.at) })
		for i := 1; i < len(rs); i++ {
			reused = reused || rs[i-1].Event != "account"
		}
	}
	src := []devicemock.Source{note}
	switch {
	case reused:
		return &devicemock.DeviceFact{ID: devicemock.FactTLSServerSingleConnectHonored, Status: "measured", Sources: src,
			What: "Over per-request TLS the device honored the single-connect port49 offers it (decision 50 ruling 20): " +
				"it sent a later session on the connection after a completed one (QUAL tls_token_login)"}
	case carried > 0 && single:
		return &devicemock.DeviceFact{ID: devicemock.FactTLSServerSingleConnectIgnored, Status: "measured", Sources: src,
			What: "Over per-request TLS the device ignored the single-connect port49 offers it (decision 50 ruling 20): " +
				"every connection carried one session (QUAL tls_token_login)"}
	}
	return nil
}
