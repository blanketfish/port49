// Package devicemock plays a vendor device's TACACS+ behavior against port49
// from a profile: what the device sends, how it reacts, what it refuses.
package devicemock

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rhwendt/port49/internal/tacacs/wire"
)

type Profile struct {
	SchemaVersion int              `yaml:"schema_version"` // 1
	Platform      string           `yaml:"platform"`       // port49 inventory platform: cisco_nxos
	LabPlatform   string           `yaml:"lab_platform"`   // results-note platform name
	Firmware      string           `yaml:"firmware"`       // as the note's Image version line names it: 10.6(2)F
	Image         string           `yaml:"image"`
	Vetted        Vetted           `yaml:"vetted"`
	Transports    []string         `yaml:"transports"` // tcp, tls
	Scenarios     []string         `yaml:"scenarios"`
	Stimulus      Stimulus         `yaml:"stimulus"`
	Reactions     []Reaction       `yaml:"reactions"`
	Acceptance    []AcceptanceRule `yaml:"acceptance"`
	DeviceFacts   []DeviceFact     `yaml:"device_facts"`
	EngineGaps    []EngineGap      `yaml:"engine_gaps"`
	Golden        string           `yaml:"golden"` // relative to the repository root; "" for a fixture with none
}

type Vetted struct {
	Date     string   `yaml:"date"`
	Commit   string   `yaml:"commit"`
	Evidence string   `yaml:"evidence"` // tests/lab/evidence/QUAL-<firmware_slug>-<lab_platform>/
	Notes    []string `yaml:"notes"`
}

type Source struct {
	Note     string `yaml:"note"`     // tests/lab/results/...
	Register string `yaml:"register"` // L73
}

type Stimulus struct {
	TLS         *TLSStimulus `yaml:"tls"`
	Connections ConnPattern  `yaml:"connections"`
	Steps       []Step       `yaml:"steps"`
	Sources     []Source     `yaml:"sources"`
}

type TLSStimulus struct {
	ClientHello    Hello         `yaml:"client_hello"`
	ServerHello    ServerHello   `yaml:"server_hello"`
	FlightDelay    time.Duration `yaml:"flight_delay"`
	ClientChain    string        `yaml:"client_chain"`    // leaf, leaf_and_intermediate
	ServerIdentity string        `yaml:"server_identity"` // chain_only, ip, dns
	Sources        []Source      `yaml:"sources"`
}

type Hello struct {
	LegacyVersion       uint16   `yaml:"legacy_version"`
	SupportedVersions   []uint16 `yaml:"supported_versions"`
	CipherSuites        []uint16 `yaml:"cipher_suites"`
	SupportedGroups     []uint16 `yaml:"supported_groups"`
	SignatureAlgorithms []uint16 `yaml:"signature_algorithms"`
	SNI                 string   `yaml:"sni"` // "" none; "{server_ip}" the literal address
	ALPN                []string `yaml:"alpn"`
	PSKModes            []uint8  `yaml:"psk_key_exchange_modes"`
	CompressCertAlgs    []uint16 `yaml:"compress_certificate_algorithms"` // extension 27
	Extensions          []uint16 `yaml:"extensions"`                      // in the device's order
}

type ServerHello struct {
	SelectedVersion   uint16 `yaml:"selected_version"`
	CipherSuite       uint16 `yaml:"cipher_suite"`
	HelloRetryRequest bool   `yaml:"hello_retry_request"`
}

type ConnPattern struct {
	Mode              string `yaml:"mode"` // per_step, single_connection
	SingleConnectFlag bool   `yaml:"single_connect_flag"`
}

type Step struct {
	Name         string       `yaml:"name"`          // login, authorize_session, command_permitted, command_denied, account_start, account_stop
	Type         string       `yaml:"type"`          // authen, author, acct
	MinorVersion uint8        `yaml:"minor_version"` // from the 12-byte header summary, never derived
	Fields       PacketFields `yaml:"fields"`
	Port         string       `yaml:"port"`
	Args         []string     `yaml:"args"`  // with {user} {rem_addr} {task_id} {start_time} {stop_time}
	Flags        string       `yaml:"flags"` // acct: start, stop, watchdog
}

type PacketFields struct {
	Action       string `yaml:"action"`
	AuthenType   string `yaml:"authen_type"`
	Service      string `yaml:"service"`
	AuthenMethod string `yaml:"authen_method"`
	PrivLvl      uint8  `yaml:"priv_lvl"`
}

type Reaction struct {
	Step    string   `yaml:"step"` // a step name, or "*"
	On      string   `yaml:"on"`
	Then    string   `yaml:"then"`
	Outcome string   `yaml:"outcome"`
	Status  string   `yaml:"status"` // measured, unmeasured
	Sources []Source `yaml:"sources"`
}

type AcceptanceRule struct {
	ID      string   `yaml:"id"`
	Kind    string   `yaml:"kind"`    // max_attribute_bytes, max_reply_bytes, priv_lvl_range, attribute_refused, role_names
	Applies string   `yaml:"applies"` // authorize_session, command_permitted, any
	Max     int      `yaml:"max"`
	Min     int      `yaml:"min"`
	Names   []string `yaml:"names"`
	Effect  string   `yaml:"effect"` // lockout, session_refused, attribute_ignored
	Status  string   `yaml:"status"`
	Sources []Source `yaml:"sources"`
	Note    string   `yaml:"note"`
}

// DeviceFact is a measured claim about what the device does that no reaction
// or acceptance rule says: a device fact, never an engine gap (decision 52
// ruling 1 keeps those for what a profile cannot say and Go must do). Its id
// is from deviceFacts, and the mock and the qualified-platforms page read it.
type DeviceFact struct {
	ID      string   `yaml:"id"`
	What    string   `yaml:"what"`
	Status  string   `yaml:"status"` // measured: an unmeasured fact is not listed
	Sources []Source `yaml:"sources"`
}

// Device facts. Each names the transport it holds on.
const (
	// FactTLSPerRequestNoCommands: over per-request TLS (the device default) the
	// device sends no command authorization, so tls_token_login plays no command
	// step (NX-OS 10.6(2)F, L73 cell a).
	FactTLSPerRequestNoCommands = "tls_per_request_no_command_authorization"
	// FactTLSSingleNoCommands: the same with single-connection on, for
	// tls_single_connection.
	FactTLSSingleNoCommands = "tls_single_connection_no_command_authorization"
)

var deviceFacts = map[string]string{FactTLSPerRequestNoCommands: "tls", FactTLSSingleNoCommands: "tls"}

// noCommandFact is the fact under which a scenario plays no command step.
var noCommandFact = map[string]string{"tls_token_login": FactTLSPerRequestNoCommands, "tls_single_connection": FactTLSSingleNoCommands}

// HasFact reports whether the profile records device fact id.
func (p *Profile) HasFact(id string) bool {
	return slices.ContainsFunc(p.DeviceFacts, func(f DeviceFact) bool { return f.ID == id })
}

type EngineGap struct {
	ID      string   `yaml:"id"`
	What    string   `yaml:"what"`
	Code    string   `yaml:"code"` // the Go file that covers it, or "" when uncovered
	Sources []Source `yaml:"sources"`
}

var (
	stepTypes = set("authen", "author", "acct")
	stepNames = set("login", "authorize_session", "command_permitted", "command_denied", "account_start", "account_stop")
	// A scenario's transport is its prefix: tls_* and flight_delay over RFC 9887,
	// the rest over 49 (ScenarioTransport).
	scenarios = set("token_login", "wrong_credential", "store_unavailable", "single_connection",
		"tls_token_login", "tls_store_unavailable", "tls_unknown_ca", "flight_delay", "tls_single_connection")
	reactOn = set("authen_pass", "authen_fail", "authen_getpass", "authen_getuser", "authen_getdata", "authen_error",
		"author_pass_add", "author_pass_repl", "author_fail", "author_error", "acct_success", "acct_error",
		"conn_reset", "conn_closed", "reply_single_connect", "alert_unknown_ca", "alert_bad_certificate",
		"alert_certificate_expired", "alert_handshake_failure", "handshake_timeout")
	reactThen = set("next_step", "send_credential", "stop", "retry", "failover_local", "failover_next_server",
		"give_up", "reuse_connection", "new_connection")
	// outcomes: what a reaction ends in, and the engine's own ends of a play.
	outcomes = set("", "login_ok", "login_refused", "falls_to_local", "break_glass_fails", "command_permitted",
		"command_denied", "accounted", "rejected_by_device", "handshake_ok", "handshake_refused")
	ruleKinds = set("max_attribute_bytes", "max_reply_bytes", "priv_lvl_range", "attribute_refused", "role_names")

	transports       = set("tcp", "tls")
	connModes        = set("per_step", "single_connection")
	acctFlags        = set("start", "stop", "watchdog")
	appliesTo        = set("authorize_session", "command_permitted", "any")
	effects          = set("lockout", "session_refused", "attribute_ignored")
	clientChains     = set("leaf", "leaf_and_intermediate")
	serverIdentities = set("chain_only", "ip", "dns")

	shortSHA  = regexp.MustCompile(`^[0-9a-f]{12}$`)
	imageLine = regexp.MustCompile(`(?m)^- \*\*Image version:\*\* (.*)$`)
	slugBad   = regexp.MustCompile(`[^A-Za-z0-9.]+`)
)

// Codes are the wire values the engine sends for a step's field names. A
// name the engine cannot send (mschap, mschapv2, krb5, guest, radius) is
// refused by Validate, naming it: such a device is an engine gap, not a
// silent default.
var Codes = map[string]map[string]uint8{
	"action":        {"login": wire.AuthenActionLogin, "chpass": wire.AuthenActionChPass, "sendauth": wire.AuthenActionSendAuth},
	"authen_type":   {"not_set": 0, "ascii": wire.AuthenTypeASCII, "pap": wire.AuthenTypePAP, "chap": wire.AuthenTypeCHAP},
	"service":       {"none": wire.AuthenServiceNone, "login": wire.AuthenServiceLogin, "enable": wire.AuthenServiceEnable, "ppp": wire.AuthenServicePPP},
	"authen_method": {"not_set": wire.AuthenMethodNotSet, "none": wire.AuthenMethodNone, "line": wire.AuthenMethodLine, "enable": wire.AuthenMethodEnable, "local": wire.AuthenMethodLocal, "tacacsplus": wire.AuthenMethodTACACSPlus},
}

func set(xs ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// ScenarioTransport is the transport a scenario runs over: "tls" for tls_* and
// flight_delay, "tcp" for the rest. The harness admits the device on that
// transport for that scenario, and genprofile splits records the same way
// (by device.transport).
func ScenarioTransport(sc string) string {
	if strings.HasPrefix(sc, "tls_") || sc == "flight_delay" {
		return "tls"
	}
	return "tcp"
}

// BaseScenario is sc without its tls_ prefix: what the engine plays.
func BaseScenario(sc string) string { return strings.TrimPrefix(sc, "tls_") }

// Slug is a firmware version as a path element: every run of characters
// other than letters, digits and dots becomes one dash, trimmed at the ends.
func Slug(firmware string) string {
	return strings.Trim(slugBad.ReplaceAllString(firmware, "-"), "-")
}

// Load reads a profile strictly: credential-shaped keys and values, unknown
// keys and failed validation are all errors.
func Load(path, repoRoot string) (*Profile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := credentialShaped(&doc, ""); err != nil {
		return nil, fmt.Errorf("%s: %w; a profile never carries a credential or key", path, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var p Profile
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := p.Validate(repoRoot); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &p, nil
}

func (p *Profile) Validate(repoRoot string) error {
	if p.SchemaVersion != 1 {
		return fmt.Errorf("schema_version %d; this engine reads 1", p.SchemaVersion)
	}
	var errs []error
	if p.Vetted.Commit != "" && !shortSHA.MatchString(p.Vetted.Commit) {
		errs = append(errs, errors.New("vetted.commit must be exactly 12 lowercase hex characters (a short SHA)"))
	}
	if p.Firmware == "" {
		errs = append(errs, errors.New("firmware is empty; a note's Image version line must name one"))
	}
	enum := func(where, v string, allowed map[string]bool, optional bool) {
		if (v == "" && optional) || allowed[v] {
			return
		}
		errs = append(errs, fmt.Errorf("%s: %q is not in the closed vocabulary", where, v))
	}
	for _, t := range p.Transports {
		enum("transports", t, transports, false)
	}
	enum("stimulus.connections.mode", p.Stimulus.Connections.Mode, connModes, false)
	if t := p.Stimulus.TLS; t != nil {
		enum("stimulus.tls.client_chain", t.ClientChain, clientChains, true)
		enum("stimulus.tls.server_identity", t.ServerIdentity, serverIdentities, true)
	}
	if err := goldenPath(p.Golden); err != nil {
		errs = append(errs, err)
	}
	for _, n := range p.Vetted.Notes {
		if err := notePath(n); err != nil {
			errs = append(errs, fmt.Errorf("vetted.notes: %w", err))
		} else if _, err := os.Stat(filepath.Join(repoRoot, n)); err != nil {
			errs = append(errs, fmt.Errorf("vetted.notes: %s: %v", n, err))
		}
	}
	// cite checks one source. measured: the note's Image version line must
	// name this firmware (decision 52 ruling 4); unmeasured: the note need
	// only exist, as the one that left the claim open.
	cite := func(where string, s Source, measured bool) {
		if s.Note == "" || s.Register == "" {
			errs = append(errs, fmt.Errorf("%s: a source needs note and register", where))
			return
		}
		if err := notePath(s.Note); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", where, err))
			return
		}
		body, err := os.ReadFile(filepath.Join(repoRoot, s.Note))
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %s: %v", where, s.Note, err))
			return
		}
		if !measured {
			return
		}
		// A note may hold several sections (addenda), each with its own line.
		named := false
		for _, m := range imageLine.FindAllStringSubmatch(string(body), -1) {
			named = named || namesFirmware(m[1], p.Firmware)
		}
		if !named {
			errs = append(errs, fmt.Errorf("%s: %s's Image version line does not name firmware %q; "+
				"a claim measured on another firmware is unmeasured here", where, s.Note, p.Firmware))
		}
	}
	if len(p.Stimulus.Sources) == 0 {
		errs = append(errs, errors.New("stimulus: no source"))
	}
	for _, s := range p.Stimulus.Sources {
		cite("stimulus", s, true)
	}
	if p.Stimulus.TLS != nil {
		for _, s := range p.Stimulus.TLS.Sources {
			cite("stimulus.tls", s, true)
		}
	}
	for i, s := range p.Stimulus.Steps {
		if !stepTypes[s.Type] || !stepNames[s.Name] {
			errs = append(errs, fmt.Errorf("steps[%d]: type %q name %q", i, s.Type, s.Name))
		}
		enum(fmt.Sprintf("steps[%d].flags", i), s.Flags, acctFlags, true)
		for field, v := range map[string]string{"action": s.Fields.Action, "authen_type": s.Fields.AuthenType,
			"service": s.Fields.Service, "authen_method": s.Fields.AuthenMethod} {
			if v == "" {
				continue
			}
			if _, ok := Codes[field][v]; !ok {
				errs = append(errs, fmt.Errorf("steps[%d]: %s %q has no wire value in this engine (an engine gap)", i, field, v))
			}
		}
	}
	for _, sc := range p.Scenarios {
		if !scenarios[sc] {
			errs = append(errs, fmt.Errorf("scenario %q is not in the conformance set", sc))
		} else if tr := ScenarioTransport(sc); !slices.Contains(p.Transports, tr) {
			errs = append(errs, fmt.Errorf("scenario %q needs transport %s, which the profile does not list", sc, tr))
		}
	}
	for i, r := range p.Reactions {
		if !reactOn[r.On] || !reactThen[r.Then] || !outcomes[r.Outcome] {
			errs = append(errs, fmt.Errorf("reactions[%d]: on %q then %q outcome %q", i, r.On, r.Then, r.Outcome))
		}
		if r.Step != "*" {
			enum(fmt.Sprintf("reactions[%d].step", i), r.Step, stepNames, false)
		}
		errs = append(errs, statusErr(fmt.Sprintf("reactions[%d]", i), r.Status, r.Sources)...)
		for _, s := range r.Sources {
			cite(fmt.Sprintf("reactions[%d]", i), s, r.Status == "measured")
		}
	}
	if err := p.refusalDisagreement(); err != nil {
		errs = append(errs, err)
	}
	for _, a := range p.Acceptance {
		if !ruleKinds[a.Kind] {
			errs = append(errs, fmt.Errorf("acceptance %s: kind %q", a.ID, a.Kind))
		}
		enum("acceptance "+a.ID+".applies", a.Applies, appliesTo, true)
		enum("acceptance "+a.ID+".effect", a.Effect, effects, true)
		errs = append(errs, statusErr("acceptance "+a.ID, a.Status, a.Sources)...)
		for _, s := range a.Sources {
			cite("acceptance "+a.ID, s, a.Status == "measured")
		}
	}
	for _, f := range p.DeviceFacts {
		where := "device_facts " + f.ID
		if tr, ok := deviceFacts[f.ID]; !ok {
			errs = append(errs, fmt.Errorf("%s: not in the closed vocabulary", where))
		} else if !slices.Contains(p.Transports, tr) {
			errs = append(errs, fmt.Errorf("%s needs transport %s, which the profile does not list", where, tr))
		}
		if f.Status != "measured" || len(f.Sources) == 0 {
			errs = append(errs, fmt.Errorf("%s: a device fact is measured, with a source, or not listed", where))
		}
		for _, s := range f.Sources {
			cite(where, s, true)
		}
	}
	for _, g := range p.EngineGaps {
		for _, s := range g.Sources {
			cite("engine_gaps "+g.ID, s, false)
		}
	}
	return errors.Join(errs...)
}

// notePath accepts only a Markdown note under tests/lab/results/, so a
// profile cannot make the loader read any other file.
func notePath(n string) error {
	c := path.Clean(n)
	if strings.Contains(n, "..") || c != n || !strings.HasPrefix(c, "tests/lab/results/") || !strings.HasSuffix(c, ".md") {
		return fmt.Errorf("note %q must be a clean .md path under tests/lab/results/", n)
	}
	return nil
}

// goldenPath accepts "" (a fixture with no golden) or a clean .json path under
// tests/qual/golden/, so a profile cannot make a consumer read any other file.
// The error does not echo the value.
func goldenPath(g string) error {
	if g == "" {
		return nil
	}
	c := path.Clean(g)
	if strings.Contains(g, "..") || c != g || !strings.HasPrefix(c, "tests/qual/golden/") || !strings.HasSuffix(c, ".json") {
		return errors.New("golden: must be a clean relative .json path under tests/qual/golden/")
	}
	return nil
}

// namesFirmware reports whether an Image version line names firmware fw as a
// whole token: 23.4R2 is not named by a line that says 23.4R2-S2.1.
func namesFirmware(line, fw string) bool {
	if fw == "" {
		return false
	}
	re := regexp.MustCompile(`(^|[^A-Za-z0-9._-])` + regexp.QuoteMeta(fw) + `($|\.($|[^A-Za-z0-9])|[^A-Za-z0-9_.(-])`)
	return re.MatchString(line)
}

func statusErr(where, status string, src []Source) []error {
	switch {
	case status == "measured" && len(src) == 0:
		return []error{fmt.Errorf("%s: measured with no source", where)}
	case status != "measured" && status != "unmeasured":
		return []error{fmt.Errorf("%s: status %q is neither measured nor unmeasured", where, status)}
	}
	return nil
}
