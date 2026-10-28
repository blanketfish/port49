//go:build lab

package lab

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
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

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/hwkey/hwfake"
	"github.com/rhwendt/port49/internal/pivattest"
	"github.com/rhwendt/port49/internal/testpki"
)

// The admin operations go over the broker API with a security key press (spec
// §5.1.6), and the lab has no key to press. A labAdmin is one operator's agent
// running in the test process, holding a software touch key on a throwaway
// attestation hierarchy (testpki.NewPIV) that the broker under test trusts
// (adminTouchRoots). `port49 revoke` is then run as the operator runs it, at
// that agent's socket, so the report it prints is the one the lab notes quote.
// Nothing here touches a real YubiKey or TPM, and nothing is secret: every key
// is generated for the run.

// adminRolesFile is the PEM roots file the lab brokers read.
const adminRolesFile = "admin-attestation-roots.pem"

// adminTouchRoots writes a fresh test attestation root into dir and returns
// the hierarchy and the roots file's path.
func adminTouchRoots(t *testing.T, dir string) (*testpki.PIV, string) {
	t.Helper()
	piv, err := testpki.NewPIV(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, adminRolesFile)
	if err := os.WriteFile(p, piv.Anchors(), 0o600); err != nil {
		t.Fatal(err)
	}
	return piv, p
}

var clientCALine = regexp.MustCompile(`(?m)^  client_ca_file: (.+)$`)

// withAdminTouch moves a broker config's client_ca_file shorthand to
// broker.identity.humans and adds the attestation roots a touch is verified
// against: the two forms cannot be set together. The config must hold exactly
// one client_ca_file line.
func withAdminTouch(brokerYAML, rootsFile string) (string, error) {
	if n := len(clientCALine.FindAllString(brokerYAML, -1)); n != 1 {
		return "", fmt.Errorf("the broker config has %d client_ca_file lines, want exactly 1, so the admin touch roots "+
			"cannot be added beside it", n)
	}
	return clientCALine.ReplaceAllString(brokerYAML, "  identity:\n    humans:\n      - {type: x509, trust_anchor_file: $1}\n"+
		"    per_login_mfa:\n      hardware_key_touch: {attestation_roots_file: "+rootsFile+"}"), nil
}

// labAdmin is an operator's agent with a software touch key.
type labAdmin struct {
	sock string
	env  []string
}

// startLabAdmin logs the operator in at brokerURL with certFile and keyFile
// (PEM files; the key must be ECDSA, as the lab's are) and serves their agent
// on a private socket until the test ends. caFile is the broker's CA. piv is
// the hierarchy the broker's attestation roots came from (adminTouchRoots).
func startLabAdmin(t *testing.T, piv *testpki.PIV, brokerURL, caFile, certFile, keyFile string) *labAdmin {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("the operator's certificate: %v", err)
	}
	sessionKey, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("the operator's key in %s is not ECDSA", filepath.Base(keyFile))
	}
	touchKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	session := hwfake.New(sessionKey, "/lab/software.so", "LAB-TOKEN")
	touch := hwfake.New(touchKey, "/lab/software.so", "LAB-TOKEN")
	sessionAtt, err := piv.Slot(&sessionKey.PublicKey, pivattest.TouchNever)
	if err != nil {
		t.Fatal(err)
	}
	touchAtt, err := piv.Slot(&touchKey.PublicKey, pivattest.TouchAlways)
	if err != nil {
		t.Fatal(err)
	}
	touch.SetCertificates(sessionAtt, piv.Device, touchAtt)
	cert.PrivateKey = session
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatalf("%s holds no certificate", filepath.Base(caFile))
	}
	a := agent.New(agent.Config{BrokerURL: brokerURL, BrokerCA: pool, BrokerCAPEM: caPEM, Cert: cert, TouchKey: touch,
		Log: io.Discard})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := a.Connect(ctx); err != nil {
		t.Fatalf("the operator's agent could not log in at %s: %v", brokerURL, err)
	}
	// A short path: a Unix socket's has a length limit.
	dir, err := os.MkdirTemp("", "p49adm")
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "agent.sock")
	ln, err := agent.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: a.Handler()}
	go srv.Serve(ln)
	t.Cleanup(func() {
		srv.Close()
		os.RemoveAll(dir)
	})
	return &labAdmin{sock: sock, env: append(os.Environ(), "PORT49_TEST_AGENT_SOCKET="+sock)}
}

// run is `port49 revoke args…` as this operator runs it: its output and exit
// code. A revocation of a principal asks first, so --yes goes with it.
func (a *labAdmin) run(args ...string) (string, int) {
	full := append([]string{"revoke"}, args...)
	if hasArg(args, "--principal") && !hasArg(args, "--lift") && !hasArg(args, "--list") {
		full = append(full, "--yes")
	}
	return a.runCmd(full...)
}

// runCmd is `port49 args…` as this operator runs it: its output and exit code.
func (a *labAdmin) runCmd(full ...string) (string, int) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(root, "bin", "port49"), full...)
	// From the repository root, so a --cert path relative to it is what the
	// note quotes, not this machine's checkout.
	cmd.Dir = root
	cmd.Env = a.env
	out, err := cmd.CombinedOutput()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		code = -1
	}
	return strings.TrimSpace(string(out)), code
}

// cli is run with the answer reduced to whether the command exited 0, as
// revokeCLI answered.
func (a *labAdmin) cli(args ...string) (string, bool) {
	out, code := a.run(args...)
	return out, code == 0
}

func hasArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}
