//go:build lab

package lab

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
)

// localBroker is bin/port49d run with a broker and the workload verifier,
// memory store, one inventory device (leaf1 at 127.0.0.1) and no device
// behind it: L48 measures what the broker does with step-ca's certificates,
// and a mint touches no device.
type localBroker struct {
	addr, stderrPath, stdoutPath, pki, dir string
	cmd                                    *exec.Cmd
	repo                                   string
	stop                                   func() // stops the process; safe to call more than once
	// piv and admin are the on-call's software key hierarchy and agent, for
	// the tests that revoke (startLabAdmin); nil until one does.
	piv   *testpki.PIV
	admin *labAdmin
}

const (
	// l48Subject is the username the lab policy gives l48ID.
	l48Subject = "svc-oxidized"
	// l48Device is the one inventory device a mint names.
	l48Device = "leaf1"
	// l48CandidateCap is the local broker's token.candidate_cap, over every
	// unredeemed mint of cells 1 to 5 (a unit test holds the arithmetic);
	// l48DefaultCandidateCap is port49's default, which cell 4's polls pass.
	l48CandidateCap        = 64
	l48DefaultCandidateCap = 8
)

// localBrokerFiles are the three files a local broker runs on, by absolute
// path under dir: port49d.yaml, policy.yaml and inventory.yaml. pki holds the
// broker's server certificate and the humans' anchor (testpki.WriteLab);
// anchorFile is the workload verifier's trust anchor (step-ca's intermediate,
// or a testpki workload CA); crlURL is "" for certificate_status disabled.
// token.candidate_cap is l48CandidateCap: L48's cells mint without redeeming,
// and the default would refuse them as candidate_cap_reached.
func localBrokerFiles(dir, pki, anchorFile, crlURL, crlIssuer string) (cfg, policy, inventory string) {
	status := "    disabled: true\n"
	if crlURL != "" {
		status = fmt.Sprintf("    refresh_interval: 1m\n    crls:\n      - {name: step_ca, url: %s, issuer_file: %s}\n",
			crlURL, crlIssuer)
	}
	cfg = fmt.Sprintf(`listen: "127.0.0.1:0"
metrics_listen: "127.0.0.1:0"
inventory_file: %s
encryption:
  current: {id: lab1, secret_ref: env:PORT49_LAB_ENC_KEY}
accounting: {spool_path: %s}
token: {candidate_cap: %d}
broker:
  listen: "127.0.0.1:0"
  tls_cert_file: %s
  tls_key_file: %s
  identity:
    humans:
      - {type: x509, trust_anchor_file: %s}
    machines:
      - {type: x509, trust_anchor_file: %s, spiffe_trust_domains: [port49.lab]}
  policy_file: %s
  revocations_file: %s
  policy_watch_interval: 1s
  certificate_status:
%s`, filepath.Join(dir, "inventory.yaml"), filepath.Join(dir, "acct.jsonl"), l48CandidateCap,
		filepath.Join(pki, testpki.LabServerCert), filepath.Join(pki, testpki.LabServerKey),
		filepath.Join(pki, testpki.LabCA), anchorFile, filepath.Join(dir, "policy.yaml"),
		filepath.Join(dir, "revocations.json"), status)
	policy = fmt.Sprintf(`scopes:
  - {name: all_devices, match: {}}
roles:
  - {name: network_admin, privilege: admin, permit: ["**"]}
subjects:
  - {name: svc_oxidized, identity: ["%s"], username: %s, token_ttl: 900s}
grants:
  - {subject: svc_oxidized, scope: all_devices, roles: [network_admin], max_privilege: admin}
key_groups:
  - {match: {cidr: 127.0.0.0/8}, key_ref: lab_key}
keys:
  lab_key:
    current: {version: 1, secret_ref: env:PORT49_KEY_LAB}
`, l48ID, l48Subject)
	inventory = fmt.Sprintf("devices:\n  - {name: %s, platform: arista_eos, addresses: [127.0.0.1]}\n", l48Device)
	return cfg, policy, inventory
}

var brokerListening = regexp.MustCompile(`port49d: broker listening on (\S+)`)

// startLocalBroker writes port49d.yaml into dir with broker.identity's
// humans anchor from testpki.WriteLab and machines anchor anchorFile,
// spiffe_trust_domains [port49.lab], and certificate_status from crlURL and
// crlIssuer ("" for disabled: true, refresh_interval 1m otherwise); a policy
// granting l48ID svc-oxidized on leaf1; and starts bin/port49d on it,
// waiting for "broker listening on". crlRoot, when set, is given to the
// process as SSL_CERT_FILE: step-ca serves its CRL over https under its own
// private root, and certstatus fetches with the system roots (pre-flight
// I-3). t.Cleanup stops it. A fault here is t.Fatal: INVALID, never a "no".
func startLocalBroker(t *testing.T, dir, anchorFile, crlURL, crlIssuer, crlRoot string) *localBroker {
	t.Helper()
	b, refusal := launchLocalBroker(t, dir, anchorFile, crlURL, crlIssuer, crlRoot)
	if b == nil {
		t.Fatalf("port49d refused to start over its CRL source: %s", refusal)
	}
	return b
}

// startRefusal is the line of a port49d start's stderr that says it refused
// the certificate_status CRL source (its issuer is not under an anchor, or is
// not a CA), or "" for any other output. Such a refusal is a fact about the
// CRL's issuer, so a measurement; any other exit is a harness fault.
func startRefusal(said string) string {
	for _, ln := range strings.Split(said, "\n") {
		if crlSourceRefusal.MatchString(ln) {
			return strings.TrimSpace(ln)
		}
	}
	return ""
}

var crlSourceRefusal = regexp.MustCompile(`broker\.certificate_status\.crls\[\d+\]`)

// prepareLocalBroker empties dir and writes what a local broker starts on:
// the PKI and the three files (localBrokerFiles). It returns the PKI's
// directory. The daemon's first-install step is initRevocations.
func prepareLocalBroker(dir, anchorFile, crlURL, crlIssuer string) (string, error) {
	if err := os.RemoveAll(dir); err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	pki := filepath.Join(dir, "pki")
	if err := testpki.WriteLab(pki, sliceEmail, time.Now()); err != nil {
		return "", err
	}
	cfg, policy, inventory := localBrokerFiles(dir, pki, anchorFile, crlURL, crlIssuer)
	for name, body := range map[string]string{"port49d.yaml": cfg, "policy.yaml": policy, "inventory.yaml": inventory} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			return "", err
		}
	}
	return pki, nil
}

// initRevocations is the daemon's first-install step, `port49d init-revocations
// --config cfg`: port49d never creates broker.revocations_file itself.
func initRevocations(bin, cfg string) error {
	if out, err := exec.Command(bin, "init-revocations", "--config", cfg).CombinedOutput(); err != nil {
		return fmt.Errorf("port49d init-revocations: %v: %s", err, tailOf(string(out), 500))
	}
	return nil
}

// localBrokerEnv is the daemon's environment: the lab keys its config names,
// and SSL_CERT_FILE when the CRL fetch must trust a private root.
func localBrokerEnv(crlRoot string) []string {
	key, encKey := os.Getenv("PORT49_LAB_KEY"), os.Getenv("PORT49_LAB_ENC_KEY")
	if key == "" {
		key = labKeyDefault
	}
	if encKey == "" {
		encKey = labEncKeyDefault
	}
	env := append(os.Environ(), "PORT49_LAB_KEY="+key, "PORT49_KEY_LAB="+key, "PORT49_KEY_RUN="+key, "PORT49_LAB_ENC_KEY="+encKey)
	if crlRoot != "" {
		env = append(env, "SSL_CERT_FILE="+crlRoot)
	}
	return env
}

// launchLocalBroker is startLocalBroker, except that a start port49d refuses
// over the CRL source returns (nil, the refusal line). Every other fault is
// t.Fatal.
func launchLocalBroker(t *testing.T, dir, anchorFile, crlURL, crlIssuer, crlRoot string) (*localBroker, string) {
	t.Helper()
	repo, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	for _, bin := range []string{"port49d", "port49"} {
		if _, err := os.Stat(filepath.Join(repo, "bin", bin)); err != nil {
			t.Fatalf("bin/%s is missing: run `make build` first", bin)
		}
	}
	pki, err := prepareLocalBroker(dir, anchorFile, crlURL, crlIssuer)
	if err != nil {
		t.Fatal(err)
	}
	return startBrokerProcess(t, repo, dir, pki, crlRoot)
}

// startBrokerProcess runs bin/port49d on the port49d.yaml in dir (already
// written, its revocations file already initialised by initRevocations) and
// waits for "broker listening on". Its stdout, the decision log, is dir's
// port49d.out. A start port49d refuses over the CRL source returns (nil, the
// refusal line); every other fault is t.Fatal.
func startBrokerProcess(t *testing.T, repo, dir, pki, crlRoot string) (*localBroker, string) {
	t.Helper()
	if err := initRevocations(filepath.Join(repo, "bin", "port49d"), filepath.Join(dir, "port49d.yaml")); err != nil {
		t.Fatal(err)
	}
	b := &localBroker{repo: repo, pki: pki, stderrPath: filepath.Join(dir, "port49d.err"), stdoutPath: filepath.Join(dir, "port49d.out"), dir: dir}
	errf, err := os.Create(b.stderrPath)
	if err != nil {
		t.Fatal(err)
	}
	outf, err := os.Create(b.stdoutPath)
	if err != nil {
		t.Fatal(err)
	}
	b.cmd = exec.Command(filepath.Join(repo, "bin", "port49d"), "-config", filepath.Join(dir, "port49d.yaml"))
	b.cmd.Dir = repo
	b.cmd.Stderr = errf
	b.cmd.Stdout = outf
	b.cmd.Env = localBrokerEnv(crlRoot)
	if err := b.cmd.Start(); err != nil {
		errf.Close()
		outf.Close()
		t.Fatalf("start port49d: %v", err)
	}
	done := make(chan struct{})
	go func() { b.cmd.Wait(); errf.Close(); outf.Close(); close(done) }()
	b.stop = func() {
		_ = b.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = b.cmd.Process.Kill()
			<-done
		}
	}
	t.Cleanup(b.stop)
	deadline := time.Now().Add(30 * time.Second)
	for {
		if m := brokerListening.FindStringSubmatch(b.said()); m != nil {
			b.addr = m[1]
			return b, ""
		}
		select {
		case <-done:
			if line := startRefusal(b.said()); line != "" {
				return nil, line
			}
			t.Fatalf("port49d exited during startup; its stderr:\n%s", tailOf(b.said(), 2000))
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("port49d never said it was listening; its stderr:\n%s", tailOf(b.said(), 2000))
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// workloadToken runs bin/port49 workload token against b with certFile and
// keyFile for leaf1, and returns its exit code, stdout and stderr (stdout
// holds a token: it is never written to a note, only its presence).
func (b *localBroker) workloadToken(certFile, keyFile string) (int, string, string) {
	return b.workload("token", certFile, keyFile, l48Device)
}

// workloadIdentity is `port49 workload identity` against b (stdout is the
// principal the broker resolved, which a note may quote).
func (b *localBroker) workloadIdentity(certFile, keyFile string) (int, string, string) {
	return b.workload("identity", certFile, keyFile)
}

// workload runs `port49 workload <sub>` against b with certFile and keyFile,
// then extra, and returns its exit code, stdout and stderr.
func (b *localBroker) workload(sub, certFile, keyFile string, extra ...string) (int, string, string) {
	cmd := exec.Command(filepath.Join(b.repo, "bin", "port49"), append([]string{"workload", sub, "--broker", "https://" + b.addr,
		"--broker-ca", filepath.Join(b.pki, testpki.LabCA), "--cert", certFile, "--key", keyFile}, extra...)...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, out.String(), errb.String()
	case errors.As(err, &ee):
		return ee.ExitCode(), out.String(), errb.String()
	}
	return -1, out.String(), errb.String() + strings.TrimSpace(err.Error())
}

// said is everything the broker has written to stderr so far.
func (b *localBroker) said() string {
	raw, _ := os.ReadFile(b.stderrPath)
	return string(raw)
}
