//go:build lab

package l62

import (
	"bufio"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The L62 stand-up harness's pure parts: the files it writes, the decision to
// reuse the state a previous run left, and the filter on the broker's log.
// Nothing here starts a container or opens a TPM; up_test.go does the first
// and nothing in this package does the second.

const (
	// project is the compose project. Its containers, network and volumes are
	// named for it, so no other lab's stack is touched.
	project = "port49labl62"
	// subnet is the stack's network. 172.30.49.0/24 is port49lab's.
	subnet = "172.30.62.0/24"

	brokerPort    = "8449"
	keycloakPort  = "18443"
	keycloakHost  = "keycloak.port49.lab"
	keycloakRealm = "port49-lab"

	// brokerImage and setupImage are this harness's own tags, so a build here
	// never retags port49:dev under another lab's stack.
	brokerImage = "port49-l62:dev"
	setupImage  = "port49-l62-setup:dev"

	// minRemaining is how long the kept PKI must still be valid for a run to
	// reuse it. The lab PKI lasts 24h (testpki.WriteLab), so a session started
	// less than this before it ends would lose its certificates mid-way.
	minRemaining = 6 * time.Hour
)

// keycloakIssuer is the realm's issuer, as the broker and the CLI name it.
const keycloakIssuer = "https://" + keycloakHost + ":" + keycloakPort + "/realms/" + keycloakRealm

// composeOverlay is the last compose file: the broker published on
// 127.0.0.1:8449 alone (no metrics port, which another lab's broker may hold),
// and this harness's image tags. Compose v2.24.4+ for !override.
const composeOverlay = `# written by the L62 harness (tests/lab/l62); regenerated at every run
services:
  port49-broker:
    image: ` + brokerImage + `
    ports: !override
      - "127.0.0.1:` + brokerPort + `:8443"
  setup:
    image: ` + setupImage + `
  etcd-init:
    image: ` + setupImage + `
`

// policyYAML is the broker's policy: alice, by the verified email Keycloak's
// realm gives her. The broker issues a certificate to anyone the policy names;
// a device is never involved.
const policyYAML = `# written by the L62 harness (tests/lab/l62)
scopes: [{name: all_devices, match: {}}]
roles: [{name: network_admin, privilege: admin, permit: ["**"]}]
subjects:
  - {name: oidc_alice, identity: ["user:alice@corp.example.com"], username: alice, token_ttl: 300s}
grants:
  - {subject: oidc_alice, scope: all_devices, roles: [network_admin], max_privilege: admin}
key_groups: [{match: {cidr: 172.30.49.0/24}, key_ref: k}]
keys:
  k:
    current: {version: 1, secret_ref: file:/run/port49/keys/tacacs_v1}
`

// rewriteBrokerConfig turns deploy/compose's port49-broker.yaml (certificate
// clients alone) into the L62 broker: the realm as a human provider, and
// certificate issuance, its CA made by init-issuer. The x509 anchor the
// original named stays, as L56's does.
func rewriteBrokerConfig(base string) (string, error) {
	lines := strings.Split(base, "\n")
	at := -1
	for i, l := range lines {
		if strings.HasPrefix(l, "  identity:") {
			return "", errors.New("port49-broker.yaml already has a broker.identity block")
		}
		if strings.HasPrefix(l, "  client_ca_file:") {
			if at >= 0 {
				return "", errors.New("port49-broker.yaml has two client_ca_file lines")
			}
			at = i
		}
	}
	if at < 0 {
		return "", errors.New("port49-broker.yaml has no broker.client_ca_file line to replace")
	}
	anchor := strings.TrimSpace(strings.TrimPrefix(lines[at], "  client_ca_file:"))
	block := []string{
		"  identity:",
		"    issuance: {certificate_lifetime: 24h}",
		"    humans:",
		"      - {type: x509, trust_anchor_file: " + anchor + "}",
		"      - type: oidc",
		"        issuer: " + keycloakIssuer,
		"        client_id: port49-cli",
		"        principal_claim: email",
		"        scopes: [openid, email]",
		"        principal_domains: [corp.example.com]",
		"        ca_file: /etc/port49-oidc/idp-ca.pem",
	}
	out := append(append(append([]string{}, lines[:at]...), block...), lines[at+1:]...)
	return strings.Join(out, "\n"), nil
}

// stateDir is where the harness keeps its PKI, config and logs: override when
// set (tests), else port49-l62 under the user's cache directory.
func stateDir(override, cache string) string {
	if override != "" {
		return override
	}
	return filepath.Join(cache, "port49-l62")
}

// stateFiles are the files a kept state must hold, relative to its directory.
// Without every one of them compose cannot start the stack, so a state
// missing one is made again.
var stateFiles = []string{
	"config/port49d.yaml", "config/port49-broker.yaml", "config/policy.yaml", "config/inventory.yaml",
	"local/port49d.env", "local/port49-broker.env",
	"local/broker/broker.pem", "local/broker/broker-key.pem", "local/broker/broker-ca.pem",
	"local/etcd/ca.pem", "local/etcd/etcd-1.pem", "local/etcd/etcd-1-key.pem",
	"local/etcd/port49-broker.pem", "local/etcd/port49-broker-key.pem",
	"local/oidc/pki/keycloak.pem", "local/oidc/pki/keycloak-key.pem", "local/oidc/pki/broker-ca.pem",
	"local/oidc/idp-ca.pem", "local/oidc/admin.env",
}

// stateCerts are the certificates whose end limits the kept state's life.
var stateCerts = []string{
	"local/broker/broker.pem", "local/etcd/etcd-1.pem", "local/oidc/pki/keycloak.pem", "local/oidc/idp-ca.pem",
}

// stateInfo is what a state directory holds, as readState finds it.
type stateInfo struct {
	Missing  []string  // stateFiles that are not there
	NotAfter time.Time // the earliest end among stateCerts; zero when none could be read
	CertErr  error     // the first stateCerts file that did not parse
}

// readState reads dir, which need not exist.
func readState(dir string) stateInfo {
	var s stateInfo
	for _, f := range stateFiles {
		fi, err := os.Stat(filepath.Join(dir, f))
		if err != nil || !fi.Mode().IsRegular() {
			s.Missing = append(s.Missing, f)
		}
	}
	for _, f := range stateCerts {
		raw, err := os.ReadFile(filepath.Join(dir, f))
		if errors.Is(err, fs.ErrNotExist) {
			continue // already in Missing
		}
		cert, perr := parseCert(raw, err)
		if perr != nil {
			if s.CertErr == nil {
				s.CertErr = fmt.Errorf("%s: %w", f, perr)
			}
			continue
		}
		if s.NotAfter.IsZero() || cert.NotAfter.Before(s.NotAfter) {
			s.NotAfter = cert.NotAfter
		}
	}
	return s
}

// parseCert is the first certificate in raw, or readErr / a parse error.
func parseCert(raw []byte, readErr error) (*x509.Certificate, error) {
	if readErr != nil {
		return nil, readErr
	}
	blk, _ := pem.Decode(raw)
	if blk == nil {
		return nil, errors.New("no PEM block")
	}
	return x509.ParseCertificate(blk.Bytes)
}

// reuseDecision is whether a run keeps the state a previous one left, and the
// sentence that says why, which the harness prints either way. Reuse keeps the
// PKI, the broker's issuing CA (in the compose volume) and so every
// certificate issued before; making it again starts over, volumes included.
func reuseDecision(s stateInfo, now time.Time, fresh bool) (bool, string) {
	switch {
	case fresh:
		return false, "PORT49_L62_FRESH=1: starting over"
	case len(s.Missing) == len(stateFiles):
		return false, "no state yet: making it"
	case len(s.Missing) > 0:
		return false, "the kept state is incomplete (no " + s.Missing[0] + "): making it again"
	case s.CertErr != nil:
		return false, "the kept state has an unreadable certificate (" + s.CertErr.Error() + "): making it again"
	case s.NotAfter.Sub(now) < minRemaining:
		return false, fmt.Sprintf("the kept PKI ends %s, under %s from now: making it again",
			s.NotAfter.UTC().Format(time.RFC3339), minRemaining)
	}
	return true, fmt.Sprintf("reusing the kept state; its PKI is valid until %s", s.NotAfter.UTC().Format(time.RFC3339))
}

// withheldMarkers are the substrings, matched without regard to case, of a
// broker log line the harness will not copy to broker.log. The runbook's own
// filter, and the sign-in parameters of an authorization address.
var withheldMarkers = []string{"password", "token", "secret", "eyj", "code=", "state=", "code_challenge"}

// withheld is whether line carries one of withheldMarkers.
func withheld(line string) bool {
	l := strings.ToLower(line)
	for _, m := range withheldMarkers {
		if strings.Contains(l, m) {
			return true
		}
	}
	return false
}

// copyFiltered writes each line of r that is not withheld to w, and says how
// many it kept and withheld.
func copyFiltered(r io.Reader, w io.Writer) (kept, dropped int, err error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		if withheld(sc.Text()) {
			dropped++
			continue
		}
		if _, err := io.WriteString(w, sc.Text()+"\n"); err != nil {
			return kept, dropped, err
		}
		kept++
	}
	return kept, dropped, sc.Err()
}

// holdUntil waits for a line on in, or for stop to close, and says which. An
// input that ends without a line (a background run, /dev/null) is not an
// Enter: the stack stays up until stop.
func holdUntil(in io.Reader, stop <-chan struct{}) string {
	line := make(chan bool, 1)
	go func() {
		_, err := bufio.NewReader(in).ReadString('\n')
		line <- err == nil
	}()
	select {
	case ok := <-line:
		if ok {
			return "enter"
		}
		<-stop
		return "stop after end of input"
	case <-stop:
		return "stop"
	}
}

// ensureDir makes dir with mode 0700 and tightens one that was left looser.
func ensureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.Chmod(dir, 0o700)
}
