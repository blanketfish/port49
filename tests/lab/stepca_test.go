//go:build lab

package lab

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// stepCA is the lab's workload CA (L48). dir is its state on the host
// (tests/lab/logs/workload/step); the workload's files are dir/w/w.pem and
// dir/w/w-key.pem, written by step inside the container as /home/step/w/....
// The key is never read on the host except to copy it, byte for byte, to
// hostW for bin/port49 to read (workloadFiles); nothing here prints it.
type stepCA struct {
	t       *testing.T
	dir     string
	compose string   // the compose file, absolute
	hostW   string   // the host copy of the workload's files (workloadFiles)
	secrets []string // values no output or note may hold: the provisioner password
	renewer *exec.Cmd
}

const (
	// stepCAImage is workload/compose.yaml's image, pinned by digest; a unit
	// test holds the two equal. step-ca says "Smallstep CA/0.30.2".
	stepCAImage   = "smallstep/step-ca:0.30.2@sha256:a2b17872915c193259b75a5474c398326f41bd199f0842093e52cf4182bc8270"
	stepCACompose = "tests/lab/workload/compose.yaml"
	l48ID         = "spiffe://port49.lab/host/oxidized-01"

	stepCAURL  = "https://localhost:9000" // inside the container
	stepCARoot = "/home/step/certs/root_ca.crt"
	// stepCAPassword is the harness's generated password file, mounted
	// read-only (workload/compose.yaml); it is the CA key's and the
	// provisioner's password both.
	stepCAPassword = "/run/secrets/lab_password"
	stepCAProv     = "lab"
	stepCAHost     = "https://127.0.0.1:19000" // the published port
	stepCAWCert    = "/home/step/w/w.pem"
	stepCAWKey     = "/home/step/w/w-key.pem"
	caJSONPath     = "/home/step/config/ca.json"
	// stepCACRLIDP is the name step-ca's CRL gives its own distribution point:
	// https://<the first of DOCKER_STEPCA_INIT_DNS_NAMES>/1.0/crl (L48).
	stepCACRLIDP = "https://step-ca.port49.lab/1.0/crl"
	// exampleCRLName is the CRL name examples/oxidized/step-ca-workload.tpl
	// holds for an operator to replace.
	exampleCRLName = "https://ca.corp.example.com/1.0/crl"
)

// privateKeyShape is the armor line of any PEM private key.
var privateKeyShape = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)

// stepLeak says whether a step command's output may not be kept: it holds key
// material, a compact JWS (a provisioner token), or a registered secret. It
// says what kind, never which.
func stepLeak(out string, secrets []string) error {
	if privateKeyShape.MatchString(out) {
		return errors.New("it holds a private key")
	}
	return leakIn(out, secrets)
}

// scrubStepLog is a container log without its password lines, or an error when
// a secret or key material is still in what is left: the image prints the CA's
// administrative password at its first start.
func scrubStepLog(raw string, secrets []string) (string, error) {
	var kept []string
	for _, ln := range strings.Split(raw, "\n") {
		if !strings.Contains(strings.ToLower(ln), "password") {
			kept = append(kept, ln)
		}
	}
	// step-ca's request log can hold a compact-JWS-shaped string (a one-time
	// token): those are redacted, not a reason to lose the log. A registered
	// secret, or key material, that is left still refuses it.
	out := jwsShape.ReplaceAllString(strings.Join(kept, "\n"), "<jws redacted>")
	if err := stepLeak(out, secrets); err != nil {
		return "", err
	}
	return out, nil
}

// withholdLeakyLog leaves the log at path as it is when it is clean, and
// replaces it with a line saying it was withheld when it holds key material, a
// compact JWS or a registered secret. A missing file is not an error.
func withholdLeakyLog(path string, secrets []string) error {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if lerr := stepLeak(string(raw), secrets); lerr != nil {
		return os.WriteFile(path, []byte("(log withheld: "+lerr.Error()+")\n"), 0o644)
	}
	return nil
}

// workloadNote is a results note in spec §15 rule 3's form, not yet checked
// for leaks (leakIn runs on it before it is written).
func workloadNote(row, platform, claim, observation, evidencePath, run, version string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s — %s\n\n", row, platform)
	fmt.Fprintf(&b, "- **Date measured:** %s\n", time.Now().UTC().Format("2006-01-02"))
	fmt.Fprintf(&b, "- **Run:** %s\n", run)
	fmt.Fprintf(&b, "- **Platform:** %s\n", platform)
	fmt.Fprintf(&b, "- **Image version:** %s\n", version)
	fmt.Fprintf(&b, "- **Capture:** `%s`\n", evidencePath)
	fmt.Fprintf(&b, "- **Credentials:** none here or in the evidence: tokens, keys and the provisioner password are "+
		"never written; certificates are public.\n")
	fmt.Fprintf(&b, "\n## Claim\n\n%s\n\n## Observation\n\n%s\n", claim, observation)
	return scrubHome(b.String())
}

// caJSONWithCRL is raw (step-ca's ca.json) with its crl block set to
// {"enabled": true, "generateOnRevoke": true}; every other key is kept, with
// its numbers as written.
func caJSONWithCRL(raw []byte) ([]byte, error) {
	m, err := decodeCAJSON(raw)
	if err != nil {
		return nil, err
	}
	m["crl"] = map[string]any{"enabled": true, "generateOnRevoke": true}
	return encodeCAJSON(m)
}

// provisionerOptionsX509 is the x509 options block of the provisioner named
// provisioner in m (ca.json decoded), made when it is missing.
func provisionerOptionsX509(m map[string]any, provisioner string) (map[string]any, error) {
	auth, _ := m["authority"].(map[string]any)
	provs, _ := auth["provisioners"].([]any)
	for _, p := range provs {
		pm, ok := p.(map[string]any)
		if !ok || pm["name"] != provisioner {
			continue
		}
		opts, ok := pm["options"].(map[string]any)
		if !ok {
			opts = map[string]any{}
			pm["options"] = opts
		}
		x509o, ok := opts["x509"].(map[string]any)
		if !ok {
			x509o = map[string]any{}
			opts["x509"] = x509o
		}
		return x509o, nil
	}
	return nil, fmt.Errorf("ca.json has no provisioner named %q", provisioner)
}

// caJSONProvisionerAllowURI is raw with the provisioner's options.x509.allow
// set to the one URI id; every other key, and its other options, are kept.
// step-ca 0.30.2 does not read it from ca.json (run set 3): cell 6 measures that.
func caJSONProvisionerAllowURI(raw []byte, provisioner, id string) ([]byte, error) {
	m, err := decodeCAJSON(raw)
	if err != nil {
		return nil, err
	}
	x509o, err := provisionerOptionsX509(m, provisioner)
	if err != nil {
		return nil, err
	}
	x509o["allow"] = map[string]any{"uri": []any{id}}
	return encodeCAJSON(m)
}

// caJSONAuthorityAllowURI is raw with the authority's x509 name policy
// allowing the URI id as written. step-ca's URI constraint is a host, and it
// refuses to start on one with a scheme (run set 3): cell 6 measures that.
func caJSONAuthorityAllowURI(raw []byte, id string) ([]byte, error) {
	m, err := decodeCAJSON(raw)
	if err != nil {
		return nil, err
	}
	auth, ok := m["authority"].(map[string]any)
	if !ok {
		return nil, errors.New("ca.json has no authority block")
	}
	auth["policy"] = map[string]any{"x509": map[string]any{"allow": map[string]any{"uri": []any{id}}}}
	return encodeCAJSON(m)
}

// caJSONProvisionerTemplate is raw with the provisioner's x509 template set
// to tpl; a templateFile and an allow list are dropped, so the template is
// the one in force.
func caJSONProvisionerTemplate(raw []byte, provisioner, tpl string) ([]byte, error) {
	m, err := decodeCAJSON(raw)
	if err != nil {
		return nil, err
	}
	x509o, err := provisionerOptionsX509(m, provisioner)
	if err != nil {
		return nil, err
	}
	delete(x509o, "templateFile")
	delete(x509o, "allow")
	x509o["template"] = tpl
	return encodeCAJSON(m)
}

// pinnedTemplate is an x509 template fixing the one URI id (as its only SAN
// and its subject) and clientAuth, whatever a request asks for (cell 6).
func pinnedTemplate(id string) string {
	tpl, _ := json.Marshal(map[string]any{"subject": map[string]any{"commonName": id}, "uris": []string{id},
		"keyUsage": []string{"digitalSignature"}, "extKeyUsage": []string{"clientAuth"}})
	return string(tpl)
}

// exampleWorkloadTemplate is examples/oxidized/step-ca-workload.tpl with its
// CRL name (exampleCRLName, there once) replaced by crlName (cell 5).
func exampleWorkloadTemplate(repo, crlName string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(repo, "examples", "oxidized", "step-ca-workload.tpl"))
	if err != nil {
		return "", err
	}
	if n := strings.Count(string(raw), exampleCRLName); n != 1 {
		return "", fmt.Errorf("examples/oxidized/step-ca-workload.tpl names %s %d times, want once", exampleCRLName, n)
	}
	return strings.Replace(string(raw), exampleCRLName, crlName, 1), nil
}

// idpNames are the fullName URIs of rl's issuing distribution point, or nil.
func idpNames(rl *x509.RevocationList) []string {
	for _, ext := range rl.Extensions {
		if !ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 28}) {
			continue
		}
		var idp struct {
			DistributionPoint asn1.RawValue `asn1:"optional,tag:0"`
		}
		if _, err := asn1.Unmarshal(ext.Value, &idp); err != nil || len(idp.DistributionPoint.Bytes) == 0 {
			return nil
		}
		var full asn1.RawValue
		if _, err := asn1.Unmarshal(idp.DistributionPoint.Bytes, &full); err != nil || full.Tag != 0 {
			return nil
		}
		var out []string
		for rest := full.Bytes; len(rest) > 0; {
			var gn asn1.RawValue
			var err error
			if rest, err = asn1.Unmarshal(rest, &gn); err != nil {
				return nil
			}
			if gn.Class == asn1.ClassContextSpecific && gn.Tag == 6 {
				out = append(out, string(gn.Bytes))
			}
		}
		return out
	}
	return nil
}

// stepStartRefusal is the line of step-ca's log saying why it would not start
// on its ca.json's name policy, without the compose prefix, or "".
func stepStartRefusal(log string) string {
	for _, ln := range strings.Split(log, "\n") {
		if _, rest, ok := strings.Cut(ln, "cannot parse "); ok {
			return "cannot parse " + strings.TrimSpace(rest)
		}
	}
	return ""
}

func decodeCAJSON(raw []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("ca.json is not a JSON object: %w", err)
	}
	return m, nil
}

func encodeCAJSON(m map[string]any) ([]byte, error) {
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// renewFraction is how far through its lifetime a certificate was when it was
// renewed: 0 at notBefore, 1 at notAfter. A certificate with no lifetime is 0.
func renewFraction(notBefore, notAfter, renewedAt time.Time) float64 {
	life := notAfter.Sub(notBefore)
	if life <= 0 {
		return 0
	}
	return float64(renewedAt.Sub(notBefore)) / float64(life)
}

// dc is `docker compose -f <step-ca's file> args...`.
func (s *stepCA) dc(args ...string) *exec.Cmd {
	return dockerCmd(append([]string{"compose", "-f", s.compose}, args...)...)
}

// startStepCA brings step-ca up fresh (its state directory emptied), waits
// for /health, and takes it down with t.Cleanup. A fault here is the test's
// t.Fatal: the run is INVALID, never a measured "no".
func startStepCA(t *testing.T) *stepCA {
	t.Helper()
	repo, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	logs := filepath.Join(repo, "tests", "lab", "logs", "workload")
	hostDir, err := stepCAHostDir()
	if err != nil {
		t.Fatal(err)
	}
	s := &stepCA{t: t, dir: filepath.Join(logs, "step"), hostW: hostDir,
		compose: filepath.Join(repo, stepCACompose)}
	if err := os.RemoveAll(s.hostW); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// The run's password: one value for the CA key and the provisioner
	// (DOCKER_STEPCA_INIT_PASSWORD_FILE), in a 0600 file this process writes
	// and never reads back. It is registered as a secret before anything runs.
	pw := randomSecret(t)
	s.secrets = append(s.secrets, pw)
	pwDir := filepath.Join(logs, "pw")
	if err := os.RemoveAll(pwDir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(pwDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pwDir, "password"), []byte(pw), 0o600); err != nil {
		t.Fatal(err)
	}
	// step-ca's files are owned by its uid, so a run starts from an empty
	// directory emptied, chmod'd and chowned by a root container, as the 7h
	// harness does for Keycloak: no sudo, and no assumption that the host
	// user is step's. The password file is chowned the same way, so step can
	// read it.
	uid, err := dockerCmd("run", "--rm", "--entrypoint", "id", stepCAImage, "-u", "step").Output()
	if err != nil {
		t.Fatalf("step-ca's uid (does the image pull?): %v", err)
	}
	owner := strings.TrimSpace(string(uid))
	if o, err := dockerCmd("run", "--rm", "--user", "root", "--entrypoint", "sh", "-v", s.dir+":/d", "-v", pwDir+":/p",
		stepCAImage, "-c", "rm -rf /d/* /d/.[!.]* && chmod 755 /d && chown "+owner+":"+owner+" /d /p/password").CombinedOutput(); err != nil {
		t.Fatalf("preparing step-ca's state directory: %v\n%s", err, tailOf(string(o), 500))
	}
	t.Cleanup(func() {
		if s.renewer != nil {
			_ = s.renewer.Process.Kill()
			time.Sleep(500 * time.Millisecond) // let the log's writer finish
			if err := withholdLeakyLog(filepath.Join(logs, "renew-daemon.log"), s.secrets); err != nil {
				t.Errorf("renew-daemon.log: %v", err)
			}
		}
		if raw, err := s.dc("logs", "--no-color", "step-ca").CombinedOutput(); err == nil {
			// The image's first start prints the CA's administrative password:
			// the log is kept without its password lines, and not at all if a
			// secret is still in it.
			if kept, err := scrubStepLog(string(raw), s.secrets); err != nil {
				t.Errorf("step-ca.log is not written: %v", err)
			} else {
				_ = os.WriteFile(filepath.Join(logs, "step-ca.log"), []byte(kept), 0o644)
			}
		}
		_ = os.RemoveAll(pwDir)
		if o, err := s.dc("down", "-v", "--remove-orphans", "-t", "5").CombinedOutput(); err != nil {
			t.Errorf("docker compose down (step-ca): %v\n%s", err, tailOf(string(o), 1000))
		}
		// The entrypoint leaves a copy of the password under step/secrets,
		// possibly world-readable and owned by step's uid: remove it through a
		// root container, as the directory was prepared.
		if o, err := dockerCmd("run", "--rm", "--user", "root", "--entrypoint", "sh", "-v", s.dir+":/d", stepCAImage, "-c",
			"rm -rf /d/secrets").CombinedOutput(); err != nil {
			t.Errorf("removing step-ca's secrets directory: %v\n%s", err, tailOf(string(o), 500))
		}
	})
	if o, err := s.dc("up", "-d").CombinedOutput(); err != nil {
		t.Fatalf("docker compose up (step-ca): %v\n%s", err, tailOf(string(o), 2000))
	}
	if err := s.waitHealth(3 * time.Minute); err != nil {
		t.Fatalf("step-ca never answered /health: %v", err)
	}
	return s
}

// client trusts the CA's root and reaches it as localhost, a name its
// certificate carries, at the published port.
func (s *stepCA) client() (*http.Client, error) {
	raw, err := os.ReadFile(s.root())
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, errors.New("root_ca.crt holds no certificate")
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12}}}, nil
}

func (s *stepCA) waitHealth(within time.Duration) error {
	deadline := time.Now().Add(within)
	var last error
	for {
		cl, err := s.client()
		if err == nil {
			var resp *http.Response
			if resp, err = cl.Get(stepCAHost + "/health"); err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					return nil
				}
				err = fmt.Errorf("/health answered %d", resp.StatusCode)
			}
		}
		last = err
		if time.Now().After(deadline) {
			return last
		}
		time.Sleep(2 * time.Second)
	}
}

// step runs `step args...` in the container with the CA URL and root, and
// returns its combined output. An output that holds key material, a token or
// the provisioner password is not returned: the text says it was withheld and
// the error is the leak.
func (s *stepCA) step(args ...string) (string, error) {
	full := append([]string{"exec", "-T", "step-ca", "step"}, args...)
	full = append(full, "--ca-url", stepCAURL, "--root", stepCARoot)
	b, err := s.dc(full...).CombinedOutput()
	out := string(b)
	if lerr := stepLeak(out, s.secrets); lerr != nil {
		out = "(output withheld: " + lerr.Error() + ")"
		if err == nil {
			err = lerr
		}
	}
	return out, err
}

// read is a file of the container's, as text. It is for files that are not
// printed: a caller never writes the result to a log.
func (s *stepCA) read(path string) (string, error) {
	b, err := s.dc("exec", "-T", "step-ca", "cat", path).Output()
	return string(b), err
}

// write replaces a file of the container's with body.
func (s *stepCA) write(path, body string) error {
	cmd := s.dc("exec", "-T", "step-ca", "sh", "-c", "cat > "+path)
	cmd.Stdin = strings.NewReader(body)
	if o, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("writing %s: %v: %s", path, err, tailOf(string(o), 300))
	}
	return nil
}

// leaf is the workload's current certificate, from the container.
func (s *stepCA) leaf() (*x509.Certificate, error) {
	raw, err := s.read(stepCAWCert)
	if err != nil {
		return nil, fmt.Errorf("reading the workload certificate: %w", err)
	}
	block, _ := pem.Decode([]byte(raw))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("w/w.pem holds no certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

// issue asks for a certificate for id, valid for life, into w/.
func (s *stepCA) issue(id string, life time.Duration) (*x509.Certificate, error) {
	if o, err := s.dc("exec", "-T", "step-ca", "mkdir", "-p", "/home/step/w").CombinedOutput(); err != nil {
		return nil, fmt.Errorf("mkdir w: %v: %s", err, tailOf(string(o), 300))
	}
	if out, err := s.step("ca", "certificate", id, stepCAWCert, stepCAWKey, "--san", id, "--provisioner", stepCAProv,
		"--provisioner-password-file", stepCAPassword, "--not-after", life.String(), "--force"); err != nil {
		return nil, fmt.Errorf("step ca certificate: %v: %s", err, tailOf(out, 500))
	}
	return s.leaf()
}

// renew is `step ca renew --force` of w/.
func (s *stepCA) renew() (*x509.Certificate, error) {
	if out, err := s.step("ca", "renew", stepCAWCert, stepCAWKey, "--force"); err != nil {
		return nil, fmt.Errorf("step ca renew: %v: %s", err, tailOf(out, 500))
	}
	return s.leaf()
}

// renewDaemonScript is the shell line that runs `step ca renew --daemon` on
// w/ in the container, its pid written for the stop. The files come before
// every flag: step stops reading flags at the first positional when a flag
// precedes it, and the daemon then exits at once on "too many positional
// arguments" (run set 3).
func renewDaemonScript() string {
	return "echo $$ > /tmp/renew.pid; exec step ca renew " + stepCAWCert + " " + stepCAWKey + " --daemon --ca-url " +
		stepCAURL + " --root " + stepCARoot
}

// renewDaemon starts `step ca renew --daemon` on w/ in the background and
// returns a func that stops it, in the container as well as here, and one
// that says whether it has exited on its own.
func (s *stepCA) renewDaemon() (stop func(), exited func() bool, err error) {
	cmd := s.dc("exec", "-T", "step-ca", "sh", "-c", renewDaemonScript())
	logPath := filepath.Join(filepath.Dir(s.dir), "renew-daemon.log")
	logf, err := os.Create(logPath)
	if err != nil {
		return nil, nil, err
	}
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		logf.Close()
		return nil, nil, err
	}
	s.renewer = cmd
	done := make(chan struct{})
	go func() { cmd.Wait(); logf.Close(); close(done) }()
	exited = func() bool {
		select {
		case <-done:
			return true
		default:
			return false
		}
	}
	return func() {
		_ = s.dc("exec", "-T", "step-ca", "sh", "-c", "kill $(cat /tmp/renew.pid)").Run()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
		}
		s.renewer = nil
		if err := withholdLeakyLog(logPath, s.secrets); err != nil {
			s.t.Errorf("renew-daemon.log: %v", err)
		}
	}, exited, nil
}

// revoke is `step ca revoke --cert w/w.pem --key w/w-key.pem`.
func (s *stepCA) revoke() error {
	if out, err := s.step("ca", "revoke", "--cert", stepCAWCert, "--key", stepCAWKey); err != nil {
		return fmt.Errorf("step ca revoke: %v: %s", err, tailOf(out, 500))
	}
	return nil
}

// editCAJSON rewrites ca.json through edit and restarts the container.
func (s *stepCA) editCAJSON(edit func([]byte) ([]byte, error)) error {
	raw, err := s.read(caJSONPath)
	if err != nil {
		return fmt.Errorf("reading ca.json: %w", err)
	}
	out, err := edit([]byte(raw))
	if err != nil {
		return err
	}
	if err := s.write(caJSONPath, string(out)); err != nil {
		return err
	}
	if o, err := s.dc("restart", "step-ca").CombinedOutput(); err != nil {
		return fmt.Errorf("restarting step-ca: %v: %s", err, tailOf(string(o), 300))
	}
	return s.waitHealth(2 * time.Minute)
}

// enableCRL adds {"crl": {"enabled": true, "generateOnRevoke": true}} to
// ca.json and restarts the container (the file is edited through the
// container, whose user owns it).
func (s *stepCA) enableCRL() error { return s.editCAJSON(caJSONWithCRL) }

// running says whether the step-ca container is up.
func (s *stepCA) running() bool {
	out, err := s.dc("ps", "--status", "running", "-q", "step-ca").Output()
	return err == nil && strings.TrimSpace(string(out)) != ""
}

// tryCAJSON writes body as ca.json, restarts the container, and waits up to
// 90s for it to answer /health or to stop. It returns whether it started and,
// when it did not, the refusal from its log (scrubbed as the cleanup's is).
func (s *stepCA) tryCAJSON(body string) (started bool, refusal string, err error) {
	if err := s.write(caJSONPath, body); err != nil {
		return false, "", err
	}
	since := time.Now().UTC().Format(time.RFC3339Nano)
	if o, err := s.dc("restart", "step-ca").CombinedOutput(); err != nil {
		return false, "", fmt.Errorf("restarting step-ca: %v: %s", err, tailOf(string(o), 300))
	}
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if s.waitHealth(0) == nil {
			return true, "", nil
		}
		if !s.running() {
			raw, _ := s.dc("logs", "--no-color", "--since", since, "step-ca").CombinedOutput()
			kept, lerr := scrubStepLog(string(raw), s.secrets)
			if lerr != nil {
				return false, "(log withheld: " + lerr.Error() + ")", nil
			}
			return false, stepStartRefusal(kept), nil
		}
		time.Sleep(2 * time.Second)
	}
	return false, "", errors.New("step-ca neither answered /health nor stopped within 90s")
}

// restoreCAJSON puts body back as ca.json in the stopped container (compose
// cp; exec needs it running), starts it and waits for /health.
func (s *stepCA) restoreCAJSON(body string) error {
	tmp := filepath.Join(filepath.Dir(s.dir), "ca.json.restore")
	if err := os.WriteFile(tmp, []byte(body), 0o644); err != nil {
		return err
	}
	defer os.Remove(tmp)
	if o, err := s.dc("cp", tmp, "step-ca:"+caJSONPath).CombinedOutput(); err != nil {
		return fmt.Errorf("copying ca.json back: %v: %s", err, tailOf(string(o), 300))
	}
	return s.startCA()
}

// crl fetches https://127.0.0.1:19000/1.0/crl (trusting the CA's root) and
// parses it with x509.ParseRevocationList; the raw bytes are returned too, for
// evidence. step-ca serves it DER or PEM-armored; both are read.
func (s *stepCA) crl() (*x509.RevocationList, []byte, error) {
	cl, err := s.client()
	if err != nil {
		return nil, nil, err
	}
	resp, err := cl.Get(stepCAHost + "/1.0/crl")
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, raw, fmt.Errorf("/1.0/crl answered %d", resp.StatusCode)
	}
	der := raw
	if block, _ := pem.Decode(raw); block != nil {
		der = block.Bytes
	}
	rl, err := x509.ParseRevocationList(der)
	return rl, raw, err
}

// root is certs/root_ca.crt on the host side of the volume: what the local
// broker's CRL fetch trusts, through SSL_CERT_FILE (pre-flight I-3).
func (s *stepCA) root() string { return filepath.Join(s.dir, "certs", "root_ca.crt") }

// stopCA and startCA stop and start the container, for the outage cells.
func (s *stepCA) stopCA() error {
	if o, err := s.dc("stop", "-t", "5", "step-ca").CombinedOutput(); err != nil {
		return fmt.Errorf("stopping step-ca: %v: %s", err, tailOf(string(o), 300))
	}
	return nil
}

func (s *stepCA) startCA() error {
	if o, err := s.dc("start", "step-ca").CombinedOutput(); err != nil {
		return fmt.Errorf("starting step-ca: %v: %s", err, tailOf(string(o), 300))
	}
	return s.waitHealth(2 * time.Minute)
}

// intermediate is certs/intermediate_ca.crt, the workload anchor (L48 measures
// that a CRL covers it there). It is the setup's: a CA without one is INVALID.
func (s *stepCA) intermediate() *x509.Certificate {
	s.t.Helper()
	raw, err := os.ReadFile(filepath.Join(s.dir, "certs", "intermediate_ca.crt"))
	if err != nil {
		s.t.Fatalf("step-ca's intermediate certificate: %v", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		s.t.Fatal("certs/intermediate_ca.crt holds no PEM block")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		s.t.Fatalf("certs/intermediate_ca.crt: %v", err)
	}
	return c
}

// workloadFiles copies the workload's certificate and key to the host (0600,
// byte for byte, never printed) for bin/port49 to read, and returns their
// paths. Call it again after a renewal.
func (s *stepCA) workloadFiles() (certFile, keyFile string, err error) {
	if err := os.MkdirAll(s.hostW, 0o700); err != nil {
		return "", "", err
	}
	for _, f := range []struct{ src, dst string }{{stepCAWCert, "w.pem"}, {stepCAWKey, "w-key.pem"}} {
		raw, err := s.dc("exec", "-T", "step-ca", "cat", f.src).Output()
		if err != nil {
			return "", "", fmt.Errorf("copying %s out of the container: %w", filepath.Base(f.src), err)
		}
		if err := os.WriteFile(filepath.Join(s.hostW, f.dst), raw, 0o600); err != nil {
			return "", "", err
		}
	}
	return filepath.Join(s.hostW, "w.pem"), filepath.Join(s.hostW, "w-key.pem"), nil
}

// stepCAHostDir is where the workload's certificate and key are copied for bin/port49: a private
// directory outside the tree, because the 12c file fence refuses a file under a group-writable ancestor
// (a lab host's ~/git is one).
func stepCAHostDir() (string, error) { return labPrivateSub("l48-host-w") }

// workloadHarnessFault is why a `port49 workload` step never reached the broker (a usage or
// configuration refusal, the file fence's among them), or "" when the exit is the product's answer. Exit
// 2 is the CLI's usage and config code; the step-ca renew refusal at 77 is a measurement.
func workloadHarnessFault(exit int, stderr string) string {
	switch {
	case strings.Contains(stderr, " is mode "):
		return "the file fence refused the workload's files"
	case exit == 2:
		return "exit 2 is a usage or configuration error"
	case exit == 64 || strings.Contains(stderr, "flag provided but not defined"):
		return "a usage error"
	case exit < 0:
		return "the command did not run"
	}
	return ""
}

// scrubHome replaces the operator's home directory with $HOME: a note is committed, and the tree names
// no personal path (tests/ci TestNoPersonalPathInTheTree).
func scrubHome(s string) string {
	if home, err := os.UserHomeDir(); err == nil && len(home) > 1 {
		return strings.ReplaceAll(s, home, "$HOME")
	}
	return s
}
