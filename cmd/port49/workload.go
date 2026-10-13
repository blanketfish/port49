package main

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/clientkey"
	"github.com/rhwendt/port49/internal/hwkey"
	"github.com/rhwendt/port49/internal/printsafe"
	"github.com/rhwendt/port49/internal/workload"
)

// exitTemporary is EX_TEMPFAIL: the broker could not answer by the deadline,
// and a later run may succeed (decision 40 ruling 10). The pages minted
// before it are written.
const exitTemporary = 75

// exitFinal is EX_NOPERM: nothing was minted, and a run again will not change
// that until someone acts (the certificate, a final refusal, every device
// denied). Nothing is written, so a wrapper keeps its last output
// (pre-flight I-1).
const exitFinal = 77

// safeLimit is the longest a broker's text is printed.
const safeLimit = 512

// safe is text the broker (or an error quoting it) sent, as one printable
// line: it is untrusted, and a terminal or a cron mail reads stderr.
func safe(s string) string { return printsafe.Line(s, safeLimit) }

// errWorkloadUsage is a run missing a required flag: usage, exit 2.
var errWorkloadUsage = errors.New("--broker, --broker-ca, --cert and --key are all required")

// workloadCmd is `port49 workload`: a workload's own commands, with no agent
// (design §17; plan 8).
func workloadCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "token":
		return workloadToken(args[1:], stdout, stderr)
	case "identity":
		return workloadIdentity(args[1:], stdout, stderr)
	}
	fmt.Fprint(stderr, usage)
	return 2
}

// workloadFlags are a workload's broker and certificate files.
type workloadFlags struct {
	broker, brokerCA, cert, key string
	deadline                    time.Duration
	brokerCRL                   string
	// touchKey is a key reference whose touch proves a per-login requirement
	// (decision 45): on the workload key's own token, its PIN from the
	// reference's pin-source alone.
	touchKey string
}

func (w *workloadFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&w.broker, "broker", "", "the broker, https://host:port")
	fs.StringVar(&w.brokerCA, "broker-ca", "", "the CA that issued the broker's certificate (PEM)")
	fs.StringVar(&w.cert, "cert", "", "the workload's certificate (PEM), read at every run")
	fs.StringVar(&w.key, "key", "", "its private key (PEM, readable by its owner alone), or a key reference "+
		"(pkcs11:…;pin-source=file:///path, tpm:file=…): a workload has no terminal, so a token's PIN is read from the "+
		"reference's pin-source")
	fs.StringVar(&w.touchKey, "touch-key", "", "a key reference on the same token as --key, touched to prove a device's "+
		"per-login second factor (pkcs11:…;pin-source=file:///path); without it such a device is reported, not minted")
	fs.StringVar(&w.brokerCRL, "broker-crl", "", "check the broker's certificate against the CRLs it names: check "+
		"(the default) refuses a revoked one, require refuses one that cannot be checked too, or that names no http(s) CRL distribution point, off checks nothing")
	fs.DurationVar(&w.deadline, "deadline", workload.DefaultDeadline, "how long to retry a broker that cannot answer now")
}

func (w *workloadFlags) client(stderr io.Writer, cmd string) (*workload.Client, error) {
	if w.broker == "" || w.brokerCA == "" || w.cert == "" || w.key == "" {
		return nil, errWorkloadUsage
	}
	caPEM, err := os.ReadFile(w.brokerCA)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("%s holds no PEM certificate", w.brokerCA)
	}
	verify, err := brokerVerifier(w.brokerCRL, func(m string) { fmt.Fprintf(stderr, "%s: warning: %s\n", cmd, m) })
	if err != nil {
		return nil, err
	}
	cfg := workload.Config{Broker: w.broker, BrokerCA: pool, CertFile: w.cert, KeyFile: w.key,
		VerifyBroker: verify, Deadline: w.deadline, Warn: func(format string, args ...any) {
			fmt.Fprintf(stderr, cmd+": "+format+"\n", args...)
		}, Say: func(format string, args ...any) {
			fmt.Fprintf(stderr, cmd+": "+format+"\n", args...)
		}}
	if w.touchKey != "" {
		// No PIN is given: a token's comes from the reference's pin-source.
		tk, err := clientkey.Open(w.touchKey, nil)
		if err != nil {
			return nil, fmt.Errorf("--touch-key: %w", err)
		}
		if tk.State() == hwkey.Locked {
			tk.Close()
			return nil, errors.New("--touch-key needs a PIN and a workload has no terminal to ask for it: add " +
				"pin-source=file:///path to the reference")
		}
		cfg.TouchKey = tk
	}
	return workload.New(cfg)
}

// mintedCount is the items that carry a token: a denied device is an answer,
// not a mint.
func mintedCount(items []api.MintItem) int {
	n := 0
	for _, it := range items {
		if it.Verdict == "permit" && it.Login != "" {
			n++
		}
	}
	return n
}

func workloadToken(args []string, stdout, stderr io.Writer) int {
	const cmd = "port49 workload token"
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var wf workloadFlags
	wf.register(fs)
	devicesFile := fs.String("devices-file", "", "a file of device names, one a line (# comments and blank lines skipped)")
	enable := fs.Bool("enable", false, "mint an enable token beside each login one")
	ttl := fs.Duration("ttl", 0, "ask for this lifetime; the broker clamps it to the subject's token_ttl")
	purpose := fs.String("purpose", "", "said in the mint record, e.g. \"oxidized nightly backup\"")
	format := fs.String("format", "tsv", "tsv (device, address, platform, username, login[, enable], expires_at) or json")
	out := fs.String("out", "", "write the tokens here (0600, replaced whole) instead of stdout")
	scope := fs.String("scope", "", "mint every device this scope selects that the workload holds a grant on, "+
		"in place of DEVICE... and --devices-file (decision 42)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	devices := fs.Args()
	if *devicesFile != "" {
		more, err := readDevices(*devicesFile)
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", cmd, err)
			return 2
		}
		devices = append(devices, more...)
	}
	if (len(devices) == 0) == (*scope == "") || (*format != "tsv" && *format != "json") {
		fmt.Fprint(stderr, usage)
		return 2
	}
	c, err := wf.client(stderr, cmd)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %s\n", cmd, safe(err.Error()))
		var ce *workload.CertError
		if errors.As(err, &ce) {
			return exitFinal // nothing can mint until the certificate is renewed
		}
		return 2
	}
	resp, err := c.Mint(context.Background(), workload.MintOptions{Devices: devices, Scope: *scope, Enable: *enable,
		TTL: *ttl, Purpose: *purpose})
	code := mintOutcome(stderr, cmd, *scope, devices, resp, err)
	switch {
	case err == nil && *scope != "" && len(resp.Results) == 0:
		// One message for an undeclared scope and an ungranted one: the
		// broker never tells them apart (decision 42 ruling 2).
		fmt.Fprintf(stderr, "%s: scope %s: no device it selects is one you hold a grant on, or no scope has that name\n",
			cmd, safe(*scope))
		return exitFinal
	}
	var permitted []api.MintItem
	for _, it := range resp.Results {
		if it.Verdict != "permit" || it.Login == "" {
			// The item's own words, never its token (there is none on a deny).
			// "<device>: <verdict> <reason>: <detail>", leaving out what is
			// empty: the broker's fault item has an error and a detail, no verdict.
			reason := it.Reason
			if it.Error != "" {
				reason = it.Error
			}
			var words []string
			for _, s := range []string{it.Verdict, reason} {
				if s != "" {
					words = append(words, safe(s))
				}
			}
			line := safe(it.Device)
			if len(words) > 0 {
				line += ": " + strings.Join(words, " ")
			}
			if it.Detail != "" {
				line += ": " + safe(it.Detail)
			}
			fmt.Fprintf(stderr, "%s: %s\n", cmd, line)
			code = max(code, 1)
			continue
		}
		if *format == "tsv" && hasControl(it, *enable) {
			// One device's line would corrupt the file: leave that device out.
			fmt.Fprintf(stderr, "%s: %s: left out, a field holds a control character, which TSV cannot carry\n", cmd,
				safe(it.Device))
			code = max(code, 1)
			continue
		}
		permitted = append(permitted, it)
	}
	if len(permitted) == 0 {
		// Nothing to write: the last output stays as it was. Temporary, or
		// final until someone acts.
		if code == exitTemporary {
			return exitTemporary
		}
		return exitFinal
	}
	body, err := render(*format, resp, permitted, *enable)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %s\n", cmd, safe(err.Error()))
		return exitTemporary
	}
	// Tokens were minted but not written: a run again writes them, and the
	// last output stands (decision 40 ruling 10).
	if *out == "" {
		if _, err := stdout.Write(body); err != nil {
			fmt.Fprintf(stderr, "%s: cannot write the tokens to stdout: %v; run again\n", cmd, err)
			return exitTemporary
		}
		return code
	}
	if err := writePrivate(*out, body); err != nil {
		fmt.Fprintf(stderr, "%s: cannot write %s: %v; run again\n", cmd, *out, err)
		return exitTemporary
	}
	return code
}

// hasControl is a TSV line for it that would hold a control character: a tab
// or newline would split it, and the rest would reach a terminal.
func hasControl(it api.MintItem, enable bool) bool {
	cols := []string{it.Device, it.Address, it.Platform, it.Username, it.Login, it.ExpiresAt}
	if enable {
		cols = append(cols, it.Enable)
	}
	for _, c := range cols {
		if strings.ContainsFunc(c, func(r rune) bool { return r < 0x20 || r == 0x7f || unicode.IsControl(r) }) {
			return true
		}
	}
	return false
}

// render is the permitted items as format says: TSV with no header, one line
// each, or the broker's answer as JSON with only the permitted results.
func render(format string, resp api.MintResponse, permitted []api.MintItem, enable bool) ([]byte, error) {
	if format == "json" {
		resp.Results = permitted
		return json.Marshal(resp)
	}
	var b strings.Builder
	for _, it := range permitted {
		cols := []string{it.Device, it.Address, it.Platform, it.Username, it.Login}
		if enable {
			cols = append(cols, it.Enable)
		}
		cols = append(cols, it.ExpiresAt)
		b.WriteString(strings.Join(cols, "\t") + "\n")
	}
	return []byte(b.String()), nil
}

// writePrivate writes data to path 0600, through a temporary file in the same
// directory renamed over it, so a reader never sees half a file and the
// tokens are never readable by others, whatever the umask.
func writePrivate(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // after the rename there is nothing at name
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	// Best effort: make the rename durable. Some platforms cannot sync a directory.
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// readDevices is a file's device names, one a line, blank lines and # comments skipped.
func readDevices(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out, sc.Err()
}

func workloadIdentity(args []string, stdout, stderr io.Writer) int {
	const cmd = "port49 workload identity"
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var wf workloadFlags
	wf.register(fs)
	asJSON := fs.Bool("json", false, "print the broker's answer as JSON")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return 2
	}
	c, err := wf.client(stderr, cmd)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %s\n", cmd, safe(err.Error()))
		var ce *workload.CertError
		switch {
		case errors.Is(err, errWorkloadUsage):
			return 2 // as workload token (pre-flight M-6)
		case errors.As(err, &ce):
			return exitFinal
		}
		return 2 // as workload token: the flags or the files named are wrong
	}
	id, err := c.Identity(context.Background())
	if err != nil {
		fmt.Fprintf(stderr, "%s: %s\n", cmd, safe(err.Error()))
		var ae *workload.APIError
		var re *workload.RedirectError
		var tle *workload.TLSError
		var de *workload.DecodeError
		switch {
		case errors.Is(err, workload.ErrTemporary):
			return exitTemporary
		case errors.As(err, &ae), errors.As(err, &re), errors.As(err, &tle), errors.As(err, &de):
			return exitFinal
		}
		return 1
	}
	if *asJSON {
		// JSON escapes control characters itself.
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(id)
		return 0
	}
	printIdentity(stdout, safeIdentity(id))
	return 0
}

// safeIdentity is id with every string the broker sent made printable, the
// slices copied so id is untouched.
func safeIdentity(id api.Identity) api.Identity {
	each := func(in []string) []string {
		if in == nil {
			return nil
		}
		out := make([]string, len(in))
		for i, s := range in {
			out[i] = safe(s)
		}
		return out
	}
	id.Principal, id.Method, id.Fingerprint = safe(id.Principal), safe(id.Method), safe(id.Fingerprint)
	id.Subject, id.Username = safe(id.Subject), safe(id.Username)
	id.VerifiedAt, id.Source = safe(id.VerifiedAt), safe(id.Source)
	id.AuthTime, id.ConnectionEndsAt = safe(id.AuthTime), safe(id.ConnectionEndsAt)
	id.Subjects, id.GroupDNs, id.Groups, id.API = each(id.Subjects), each(id.GroupDNs), each(id.Groups), each(id.API)
	grants := make([]api.IdentityGrant, len(id.Grants))
	for i, g := range id.Grants {
		grants[i] = api.IdentityGrant{Scope: safe(g.Scope), Roles: each(g.Roles), MaxPrivilege: safe(g.MaxPrivilege),
			Expires: safe(g.Expires)}
	}
	id.Grants = grants
	if id.OIDC != nil {
		o := *id.OIDC
		o.Issuer, o.Sub, o.Sid, o.ACR, o.AMR = safe(o.Issuer), safe(o.Sub), safe(o.Sid), safe(o.ACR), each(o.AMR)
		id.OIDC = &o
	}
	return id
}
