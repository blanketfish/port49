package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/blanketfish/port49/internal/agent"
	"github.com/blanketfish/port49/internal/broker/api"
	"github.com/blanketfish/port49/internal/hwkey"
	"github.com/blanketfish/port49/internal/hwkey/pkcs11"
	"github.com/blanketfish/port49/internal/hwkey/serialmask"
	"github.com/blanketfish/port49/internal/hwkeysetup"
	"github.com/blanketfish/port49/internal/userconfig"
)

// moduleRoot stands for "/" in the module probe: tests point it at a temp tree.
var moduleRoot = "/"

// hwkeyStdin is where setup reads its answer to "change it?" from.
var hwkeyStdin io.Reader = os.Stdin

// maskWriter masks the serial in everything written through it. Every line
// port49 hwkey prints, error lines included, goes through one (spec §13
// decision 55 ruling 16): a pkcs11 error can name other tokens.
type maskWriter struct{ w io.Writer }

func (m maskWriter) Write(p []byte) (int, error) {
	if _, err := io.WriteString(m.w, serialmask.MaskSerial(string(p))); err != nil {
		return 0, err
	}
	return len(p), nil
}

const hwkeyUsage = "usage: port49 hwkey setup  [--module PATH] [--token N] [--session-slot 9a|9e] [--roots FILE] [--broker URL]\n" +
	"       port49 hwkey status [--module PATH] [--token N] [--session-slot 9a|9e] [--roots FILE] [--broker URL] [--json]\n"

const notOnAToken = "`hardware_key_touch` needs the session key and the touch key on one YubiKey; this login's session key is not on a token. " +
	"Your site's other per-login factor is `idp_mfa`."

// hwkeyCmd is `port49 hwkey setup|status` (decision 55 rulings 16 and 17):
// 0 ready, 1 action needed, 2 error. Read-only on the token: it opens no key
// with a PIN and writes no object.
func hwkeyCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "setup" && args[0] != "status") {
		fmt.Fprint(stderr, hwkeyUsage)
		return 2
	}
	setup := args[0] == "setup"
	stdout, stderr = maskWriter{stdout}, maskWriter{stderr}
	fs := flag.NewFlagSet("port49 hwkey "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	module := fs.String("module", "", "the PKCS#11 module (libykcs11); found on this system when left out")
	tokenN := fs.Int("token", 0, "which token, by its number in the list, when the module shows more than one")
	sessionSlot := fs.String("session-slot", "9a", "the PIV slot of the session key: 9a, or 9e where a site keeps it")
	rootsFile := fs.String("roots", "", "the attestation roots (PEM), in place of the broker's")
	broker := fs.String("broker", "", "the broker to fetch the attestation roots from (the config's broker by default)")
	asJSON := fs.Bool("json", false, "status: print the report as JSON")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() != 0 || (setup && *asJSON) {
		fmt.Fprint(stderr, hwkeyUsage)
		return 2
	}
	if _, ok := hwkeysetup.SlotIDs[*sessionSlot]; !ok || *sessionSlot == "9c" {
		fmt.Fprintf(stderr, "port49: --session-slot %q: use 9a, or 9e where a site keeps the session key\n", *sessionSlot)
		return 2
	}
	h := &hwkeyRun{stdout: stdout, stderr: stderr, setup: setup, json: *asJSON, slot: *sessionSlot}

	userPath := userconfig.Path()
	cfg, _, err := userconfig.LoadAll(userPath, false)
	if err != nil {
		fmt.Fprintf(stderr, "port49: %v\n", err)
		return 2
	}
	user, _, err := userconfig.Load(userPath)
	if err != nil {
		fmt.Fprintf(stderr, "port49: %v\n", err)
		return 2
	}
	h.cfg, h.user, h.userPath = cfg, user, userPath

	// A session key in a TPM or a file cannot be on the token (ruling 16).
	store := cfg.IssuedKeyStore
	if st, err := agent.NewClient(agent.SocketPath()).Status(context.Background()); err == nil {
		h.agentStatus = &st
		if st.SessionKeyStore != "" {
			store = st.SessionKeyStore
		}
	}
	if store == "tpm" || store == "file" || store == "secure_enclave" {
		// One plain statement and exit 1: no advice (setup would generate over a slot the user did not
		// mean) and no pointer to setup, which refuses this case too.
		if h.json {
			return h.finish(hwkeysetup.Report{Checks: []hwkeysetup.Check{{Name: hwkeysetup.CheckSessionSlot, Why: notOnAToken}}})
		}
		fmt.Fprintln(stdout, notOnAToken)
		return 1
	}

	// The roots come first, and the output starts with them.
	url := *broker
	if url == "" {
		url = cfg.Broker
	}
	roots, rc := h.loadRoots(*rootsFile, url)
	if rc != 0 {
		return rc
	}
	// The JSON object is all of stdout; its roots are in it.
	info := stdout
	if h.json {
		info = stderr
	}
	h.info = info
	fmt.Fprintf(info, "roots: %s\n", roots.Source)

	path, rc := h.findModule(*module)
	if rc != 0 {
		return rc
	}
	tokens, err := listTokens(path)
	if err != nil {
		fmt.Fprintf(stderr, "port49: reading the tokens of %s: %v\n", path, err)
		return 2
	}
	var tok pkcs11.Token
	switch {
	case len(tokens) == 0:
		fmt.Fprintf(stdout, "no token found in %s: insert your security key\n", path)
		return 1
	case *tokenN == 0 && len(tokens) > 1:
		fmt.Fprintf(stderr, "port49: %d tokens are present; pick one with --token N:\n", len(tokens))
		for i, t := range tokens {
			fmt.Fprintf(stderr, "  %d  %s  %s\n", i+1, t.Model, t.MaskedLabel)
		}
		return 2
	case *tokenN == 0:
		tok = tokens[0]
	case *tokenN < 1 || *tokenN > len(tokens):
		fmt.Fprintf(stderr, "port49: --token %d: the module shows %d token(s)\n", *tokenN, len(tokens))
		return 2
	default:
		tok = tokens[*tokenN-1]
	}

	keys := hwkeysetup.Keys{SessionSlot: h.slot, RootsFrom: roots.Source}
	var closers []hwkey.Key
	closeKeys := func() {
		for _, k := range closers {
			_ = k.Close()
		}
		closers = nil
	}
	defer closeKeys()
	open := func(slot string) (hwkey.Key, string) {
		u, err := hwkeysetup.SlotURI(path, tok.Label, slot)
		if err != nil {
			return nil, err.Error()
		}
		pu, err := pkcs11.ParseURI(u)
		if err != nil {
			return nil, err.Error()
		}
		k, err := openToken(pu, nil)
		if err != nil {
			return nil, fmt.Sprintf("slot %s: %v", slot, err)
		}
		closers = append(closers, k)
		return k, ""
	}
	keys.Session, keys.SessionWhy = open(h.slot)
	keys.Touch, keys.TouchWhy = open("9c")

	h.module, h.token = path, tok
	h.keys = keys
	report := hwkeysetup.Inspect(keys, &roots.Anchors, time.Now())
	report.Token, report.Roots = tok.MaskedLabel, roots.Source
	if !setup {
		h.statusChecks(&report)
	}
	closeKeys() // before setup writes the config
	return h.finish(report)
}

// hwkeyRun is one run's state.
type hwkeyRun struct {
	stdout, stderr io.Writer
	info           io.Writer // the roots and module lines: stdout, or stderr under --json
	setup, json    bool
	slot           string
	cfg, user      userconfig.File
	userPath       string
	agentStatus    *agent.Status
	module         string
	token          pkcs11.Token
	keys           hwkeysetup.Keys
}

// loadRoots is the roots, or the exit code that says why not.
func (h *hwkeyRun) loadRoots(rootsFile, broker string) (hwkeysetup.Roots, int) {
	fetch := func(ctx context.Context) (api.Config, error) {
		if len(h.cfg.BrokerCAPEM) == 0 {
			return api.Config{}, fmt.Errorf("%w: broker_ca is not set", hwkeysetup.ErrBrokerUntrusted)
		}
		sf := &sessionFlags{broker: broker, brokerCRL: cmpOr(h.cfg.BrokerCRL, "check")}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(h.cfg.BrokerCAPEM)
		verify, err := sf.verifyBroker(h.stderr)
		if err != nil {
			return api.Config{}, err
		}
		conf, err := fetchBrokerConfig(ctx, broker, pool, verify)
		var cert *brokerCertError
		if errors.As(err, &cert) || refusedByCRL(err) != nil {
			return api.Config{}, fmt.Errorf("%w: %v", hwkeysetup.ErrBrokerUntrusted, err)
		}
		return conf, err
	}
	r, err := hwkeysetup.LoadRoots(context.Background(), rootsFile, broker, fetch)
	if err != nil {
		fmt.Fprintf(h.stderr, "port49: %v\n", err)
		return r, 2
	}
	return r, 0
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// findModule is the module by ruling 16's order: --module, then an existing
// key's module-path, then the probe. Each is held to userconfig.CheckOwned
// before anything loads it.
func (h *hwkeyRun) findModule(flagPath string) (string, int) {
	from := func(label, p string) (string, int) {
		if err := userconfig.CheckOwned(p); err != nil {
			fmt.Fprintf(h.stderr, "port49: %s %s is refused as a PKCS#11 module: %v\n", label, p, err)
			return "", 2
		}
		fmt.Fprintf(h.info, "module: %s\n", p)
		return p, 0
	}
	if flagPath != "" {
		return from("--module", flagPath)
	}
	for _, ref := range []string{h.cfg.IssuedKey, h.cfg.TouchKey} {
		if u, err := pkcs11.ParseURI(ref); err == nil && u.ModulePath != "" {
			return from("the module-path of your config's key,", u.ModulePath)
		}
	}
	p, err := hwkeysetup.FindModule(moduleRoot, runtime.GOOS, runtime.GOARCH, userconfig.CheckOwned,
		func(s string) { fmt.Fprintf(h.stderr, "port49: %s\n", s) })
	if err != nil {
		fmt.Fprintf(h.stderr, "port49: %v\n", err)
		return "", 2
	}
	fmt.Fprintf(h.info, "module: %s (found)\n", p)
	return p, 0
}

// statusChecks adds ruling 17's checks to the report.
func (h *hwkeyRun) statusChecks(r *hwkeysetup.Report) {
	want := func(slot string) string {
		u, err := hwkeysetup.SlotURI(h.module, h.token.Label, slot)
		if err != nil {
			return ""
		}
		return u
	}
	names := func(name, slot, have string) hwkeysetup.Check {
		if have == "" {
			return hwkeysetup.Check{Name: name, Why: "not set: run `port49 hwkey setup`"}
		}
		u, err := pkcs11.ParseURI(have)
		w, _ := pkcs11.ParseURI(want(slot))
		if err != nil || !bytes.Equal(u.ID, w.ID) || u.Token != w.Token {
			return hwkeysetup.Check{Name: name, Why: "does not name slot " + slot + " on this token: run `port49 hwkey setup`"}
		}
		return hwkeysetup.Check{Name: name, OK: true}
	}
	r.Append(names(hwkeysetup.CheckConfigIssuedKey, h.slot, h.cfg.IssuedKey),
		names(hwkeysetup.CheckConfigTouchKey, "9c", h.cfg.TouchKey))

	cert := hwkeysetup.Check{Name: hwkeysetup.CheckIssuedCertificate, OK: true, Why: "no certificate yet"}
	exp := hwkeysetup.Check{Name: hwkeysetup.CheckCertificateExpiry, OK: true, Why: "no certificate yet"}
	if h.cfg.IssuedKey != "" && h.cfg.Broker != "" {
		if p, err := userconfig.IssuedTokenPaths(h.cfg.Broker, tokenKeyName(h.cfg.IssuedKey)); err == nil {
			if raw, err := os.ReadFile(p); err == nil {
				cert, exp = h.certificateChecks(raw)
			}
		}
	}
	r.Append(cert, exp)

	ag := hwkeysetup.Check{Name: hwkeysetup.CheckAgent, OK: true, Why: "no agent running"}
	if st := h.agentStatus; st != nil {
		switch {
		case st.TouchKey:
			ag = hwkeysetup.Check{Name: hwkeysetup.CheckAgent, OK: true, Why: "touch_key: true"}
		case st.TouchKeyUnusable != "":
			ag = hwkeysetup.Check{Name: hwkeysetup.CheckAgent, Why: "touch_key_unusable: " + st.TouchKeyUnusable}
		default:
			ag = hwkeysetup.Check{Name: hwkeysetup.CheckAgent, Why: "touch_key: false"}
		}
	}
	r.Append(ag)
}

// certificateChecks are issued_certificate and certificate_expiry for the held certificate raw.
func (h *hwkeyRun) certificateChecks(raw []byte) (cert, exp hwkeysetup.Check) {
	cert = hwkeysetup.Check{Name: hwkeysetup.CheckIssuedCertificate}
	exp = hwkeysetup.Check{Name: hwkeysetup.CheckCertificateExpiry}
	block, _ := pem.Decode(raw)
	var c *x509.Certificate
	var err error
	if block != nil {
		c, err = x509.ParseCertificate(block.Bytes)
	}
	if block == nil || err != nil {
		cert.Why = "the held certificate does not parse: log in again"
		exp.Why = "not checked: the held certificate does not parse"
		return
	}
	switch {
	case h.keys.Session == nil:
		cert.Why = "not checked: the session key did not open"
	case !publicEqual(c.PublicKey, h.keys.Session.Public()):
		cert.Why = "the held certificate is for another key than the session slot's: run `port49 hwkey setup`, then `port49 login --sign-in`"
	default:
		cert.OK = true
	}
	if left := time.Until(c.NotAfter); left <= 0 {
		exp.Why = "expired " + c.NotAfter.UTC().Format(time.RFC3339) + ": run `port49 login --sign-in`"
	} else {
		exp.OK, exp.Why = true, "expires in "+left.Round(time.Minute).String()
	}
	return
}

func publicEqual(a, b any) bool {
	eq, ok := a.(interface{ Equal(x crypto.PublicKey) bool })
	return ok && eq.Equal(b)
}

// finish prints the report and returns the exit code (setup writes the config
// first, when ready).
func (h *hwkeyRun) finish(r hwkeysetup.Report) int {
	r = finishReport(r)
	if h.json {
		// Not HTML-escaped: "\u003cserial\u003e" would meet maskWriter's rule and be cut.
		enc := json.NewEncoder(h.stdout)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(r)
		return exitOf(r)
	}
	if r.Token != "" {
		fmt.Fprintf(h.stdout, "token: %s\n", r.Token)
	}
	for _, c := range r.Checks {
		switch {
		case c.OK && c.Why == "":
			fmt.Fprintf(h.stdout, "ok    %s\n", c.Name)
		case c.OK:
			fmt.Fprintf(h.stdout, "ok    %s: %s\n", c.Name, c.Why)
		default:
			fmt.Fprintf(h.stdout, "FAIL  %s: %s\n", c.Name, c.Why)
		}
	}
	if !r.Ready {
		if h.setup {
			for _, l := range hwkeysetup.Advice(r, h.slot) {
				fmt.Fprintln(h.stdout, l)
			}
		} else {
			fmt.Fprintln(h.stdout, "not ready: run `port49 hwkey setup`")
		}
		return 1
	}
	if h.setup {
		return h.writeKeys()
	}
	fmt.Fprintln(h.stdout, "ready")
	return 0
}

func finishReport(r hwkeysetup.Report) hwkeysetup.Report {
	r.Ready = len(r.Checks) > 0
	for _, c := range r.Checks {
		r.Ready = r.Ready && c.OK
	}
	return r
}

func exitOf(r hwkeysetup.Report) int {
	if r.Ready {
		return 0
	}
	return 1
}

// writeKeys is setup's last step, on a ready token: issued_key and touch_key
// in the user's config, if they are not already there.
func (h *hwkeyRun) writeKeys() int {
	issued, err := hwkeysetup.SlotURI(h.module, h.token.Label, h.slot)
	if err == nil {
		var touch string
		if touch, err = hwkeysetup.SlotURI(h.module, h.token.Label, "9c"); err == nil {
			return h.setKeys(issued, touch)
		}
	}
	fmt.Fprintf(h.stderr, "port49: %v\n", err)
	return 2
}

func (h *hwkeyRun) setKeys(issued, touch string) int {
	// A key the system config supplies is reported, not edited.
	for _, k := range []struct{ name, merged, user, want string }{
		{"issued_key", h.cfg.IssuedKey, h.user.IssuedKey, issued},
		{"touch_key", h.cfg.TouchKey, h.user.TouchKey, touch},
	} {
		if k.user == "" && k.merged != "" && k.merged != k.want {
			fmt.Fprintf(h.stdout, "%s comes from the system config (/etc/port49/config.yaml) as %s, not from %s; port49 does not edit it. "+
				"Ask your administrator to change it, or set it in your own file.\n", k.name, k.merged, h.userPath)
			return 1
		}
	}
	for _, k := range []struct{ name, user, want string }{{"issued_key", h.user.IssuedKey, issued}, {"touch_key", h.user.TouchKey, touch}} {
		if k.user != "" && k.user != k.want {
			fmt.Fprintf(h.stdout, "%s in %s is\n  %s\nthe key found is\n  %s\n", k.name, h.userPath, k.user, k.want)
			if !stdinIsTerminal() {
				fmt.Fprintln(h.stdout, "nothing changed: run port49 hwkey setup at a terminal to replace it")
				return 1
			}
			fmt.Fprint(h.stdout, "replace it? [y/N] ")
			ans, _ := bufio.NewReader(hwkeyStdin).ReadString('\n')
			if a := strings.ToLower(strings.TrimSpace(ans)); a != "y" && a != "yes" {
				fmt.Fprintln(h.stdout, "nothing changed")
				return 1
			}
		}
	}
	changed, err := userconfig.SetKeys(h.userPath, issued, touch)
	if err != nil {
		fmt.Fprintf(h.stderr, "port49: %v\n", err)
		return 2
	}
	if !changed {
		fmt.Fprintf(h.stdout, "issued_key and touch_key in %s already name this token; nothing changed\n", h.userPath)
		return 0
	}
	fmt.Fprintf(h.stdout, "wrote issued_key and touch_key to %s\n", h.userPath)
	return 0
}
