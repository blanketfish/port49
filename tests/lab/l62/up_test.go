//go:build lab

package l62

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
)

// TestL62Up stands up what the L62 session needs and holds it: the lab
// Keycloak (tests/lab/oidc's realm) and port49-broker issuing certificates,
// as compose project port49labl62, with no device and no TPM. It never runs
// port49 and never opens /dev/tpm*; the session's operator does both
// (tests/lab/runbooks/L62-ser8.md, "Blocking prerequisite P0").
//
//	PORT49_L62_UP=1 go test -tags lab ./tests/lab/l62/ -run '^TestL62Up$' -count=1 -v -timeout 10h
//
// PORT49_L62_FRESH=1 starts over. PORT49_L62_DIR names the state directory
// (default: port49-l62 under the user's cache directory).
func TestL62Up(t *testing.T) {
	if os.Getenv("PORT49_L62_UP") != "1" {
		t.Skip("PORT49_L62_UP=1 brings the L62 stack up and holds it")
	}
	root := repoRoot(t)
	cache, err := os.UserCacheDir()
	if err != nil {
		t.Fatalf("no cache directory: %v", err)
	}
	s := &stack{t: t, root: root, dir: stateDir(os.Getenv("PORT49_L62_DIR"), cache)}
	if err := ensureDir(s.dir); err != nil {
		t.Fatal(err)
	}

	// Another lab's Keycloak or broker on our ports would answer for us.
	if !s.running() {
		for _, port := range []string{brokerPort, keycloakPort} {
			if listening("127.0.0.1:" + port) {
				t.Fatalf("127.0.0.1:%s is already in use and it is not project %s: another lab is running; "+
					"`docker ps` names it", port, project)
			}
		}
	}

	reuse, why := reuseDecision(readState(s.dir), time.Now(), os.Getenv("PORT49_L62_FRESH") == "1")
	fmt.Println("L62 state:", why)
	// Registered before anything starts, so a failure half way still stops
	// what did. No -v: the volumes, and so the issuing CA, are kept.
	t.Cleanup(func() {
		s.stopLogs()
		if out, err := s.projectDown(false); err != nil {
			t.Errorf("docker compose down: %v\n%s", err, out)
		}
	})
	if !reuse {
		// Before the files are rewritten: the old volumes hold the old PKI.
		if out, err := s.projectDown(true); err != nil {
			t.Fatalf("docker compose down -v: %v\n%s", err, out)
		}
		s.write()
		_ = os.Remove(filepath.Join(s.dir, "broker.log"))
	}
	s.writeOverlay()

	started := time.Now()
	if out, err := s.compose("up", "-d", "--build", "port49-broker", "keycloak"); err != nil {
		t.Fatalf("docker compose up: %v\n%s\ncompose.log (tail):\n%s", err, out, s.tail(30))
	}
	brokerCA := filepath.Join(s.dir, "local", "broker", "broker-ca.pem")
	idpCA := filepath.Join(s.dir, "local", "oidc", "idp-ca.pem")
	brokerHTTP, kcHTTP := tlsClient(t, brokerCA, "127.0.0.1"), tlsClient(t, idpCA, keycloakHost)

	s.waitFor("Keycloak's realm", 4*time.Minute, func() error {
		return answers(kcHTTP, "https://127.0.0.1:"+keycloakPort+"/realms/"+keycloakRealm+"/.well-known/openid-configuration")
	})
	s.waitFor("the broker", 3*time.Minute, func() error {
		_, err := issuance(brokerHTTP)
		return err
	})

	// init-issuer writes the issuing CA once and says "already there" after,
	// so it runs at every start. A new CA ends every certificate issued by the
	// old one, which the operator must hear.
	out, err := s.compose("run", "--rm", "--no-deps", "-T", "port49-broker", "init-issuer")
	if err != nil {
		t.Fatalf("port49-broker init-issuer: %v\n%s", err, out)
	}
	ca := "reused (already there)"
	if strings.Contains(out, "created the issuing CA") {
		ca = "NEW: certificates issued before are no longer valid"
		if out, err := s.compose("restart", "port49-broker"); err != nil {
			t.Fatalf("restarting the broker: %v\n%s", err, out)
		}
	}
	s.waitFor("the broker issuing", 3*time.Minute, func() error {
		avail, err := issuance(brokerHTTP)
		if err == nil && !avail {
			err = fmt.Errorf("/v1/config says issuance is not available")
		}
		return err
	})

	// From the start of this run, so the missing-CA start is in it too.
	s.followBrokerLog(started)
	for src, dst := range map[string]string{brokerCA: "broker-ca.pem", idpCA: "oidc-ca.pem"} {
		raw, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(s.dir, dst), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	fmt.Println("L62 UP")
	fmt.Printf("  broker   https://127.0.0.1:%s (certificates of 24h; sign in at %s)\n", brokerPort, keycloakIssuer)
	fmt.Printf("  keycloak https://%s:%s (127.0.0.1:%s; needs %s -> 127.0.0.1 in /etc/hosts)\n",
		keycloakHost, keycloakPort, keycloakPort, keycloakHost)
	fmt.Printf("  issuing CA: %s\n", ca)
	fmt.Printf("  files    %s: broker-ca.pem, oidc-ca.pem, broker.log\n", s.dir)
	fmt.Println("  Enter stops the stack and keeps its volumes (so does Ctrl-C).")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	fmt.Println("L62 stopping:", holdUntil(enterInput(), ctx.Done()))
}

// enterInput is where Enter is read: the controlling terminal when there is
// one, since `go test ./pkg/` gives the test binary /dev/null for stdin, and
// stdin otherwise (a background run then waits for a signal).
func enterInput() io.Reader {
	if tty, err := os.Open("/dev/tty"); err == nil {
		return tty
	}
	return os.Stdin
}

// stack is the compose project, its directory and the broker log follower.
type stack struct {
	t    *testing.T
	root string
	dir  string // the state directory

	cancelLogs context.CancelFunc
	logsDone   chan struct{}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	d, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d
		}
		p := filepath.Dir(d)
		if p == d {
			t.Fatal("no go.mod above the test's directory")
		}
		d = p
	}
}

// write makes the state: the lab PKI and env files compose reads, Keycloak's
// certificate, the admin password and the four config files.
func (s *stack) write() {
	s.t.Helper()
	for _, d := range []string{"local", "config"} {
		if err := os.RemoveAll(filepath.Join(s.dir, d)); err != nil {
			s.t.Fatal(err)
		}
		if err := ensureDir(filepath.Join(s.dir, d)); err != nil {
			s.t.Fatal(err)
		}
	}
	local := filepath.Join(s.dir, "local")
	now := time.Now()
	// The email names a client certificate nothing here uses.
	if err := testpki.WriteCompose(local, "l62@port49.test", now); err != nil {
		s.t.Fatal(err)
	}
	brokerCA, err := os.ReadFile(filepath.Join(local, "broker", testpki.LabCA))
	if err != nil {
		s.t.Fatal(err)
	}
	if err := writeOIDCPKI(filepath.Join(local, "oidc"), brokerCA, now); err != nil {
		s.t.Fatal(err)
	}
	deploy := filepath.Join(s.root, "deploy", "compose", "config")
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(deploy, name))
		if err != nil {
			s.t.Fatal(err)
		}
		return string(b)
	}
	broker, err := rewriteBrokerConfig(read("port49-broker.yaml"))
	if err != nil {
		s.t.Fatal(err)
	}
	for name, body := range map[string]string{"port49d.yaml": read("port49d.yaml"), "inventory.yaml": read("inventory.yaml"),
		"port49-broker.yaml": broker, "policy.yaml": policyYAML} {
		if err := os.WriteFile(filepath.Join(s.dir, "config", name), []byte(body), 0o600); err != nil {
			s.t.Fatal(err)
		}
	}
}

// writeOIDCPKI writes what tests/lab/compose/oidc.yaml mounts under dir: a CA
// for the broker's ca_file (idp-ca.pem), Keycloak's certificate and key from
// it, the broker's CA as Keycloak's truststore, and the admin password
// (admin.env, 0600, never printed). Keycloak reads its key as uid 1000, so
// pki/ is world-readable; the state directory is 0700 and the CA is a week's.
func writeOIDCPKI(dir string, brokerCA []byte, now time.Time) error {
	pki := filepath.Join(dir, "pki")
	if err := os.MkdirAll(pki, 0o755); err != nil {
		return err
	}
	ca, err := testpki.NewCA("port49 lab oidc l62 CA", now.Add(-time.Hour), now.Add(7*24*time.Hour))
	if err != nil {
		return err
	}
	leaf, err := ca.Issue(testpki.Leaf{CommonName: keycloakHost, DNSNames: []string{keycloakHost},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(7 * 24 * time.Hour)})
	if err != nil {
		return err
	}
	cert, key, err := testpki.PEMs(leaf)
	if err != nil {
		return err
	}
	pass := make([]byte, 18)
	if _, err := rand.Read(pass); err != nil {
		return err
	}
	for _, f := range []struct {
		path string
		body []byte
		mode os.FileMode
	}{
		{filepath.Join(pki, "keycloak.pem"), cert, 0o644},
		{filepath.Join(pki, "keycloak-key.pem"), key, 0o644},
		{filepath.Join(pki, "broker-ca.pem"), brokerCA, 0o644},
		{filepath.Join(dir, "idp-ca.pem"), ca.PEM(), 0o644},
		{filepath.Join(dir, "admin.env"), []byte(fmt.Sprintf("KC_BOOTSTRAP_ADMIN_PASSWORD=%x\n", pass)), 0o600},
	} {
		if err := os.WriteFile(f.path, f.body, f.mode); err != nil {
			return err
		}
		if err := os.Chmod(f.path, f.mode); err != nil {
			return err
		}
	}
	return nil
}

func (s *stack) writeOverlay() {
	s.t.Helper()
	if err := os.WriteFile(filepath.Join(s.dir, "l62-overlay.yaml"), []byte(composeOverlay), 0o644); err != nil {
		s.t.Fatal(err)
	}
}

// compose runs docker compose on the project's files and records the command
// and its output in compose.log. The output holds no secret: the env files
// are read by compose, not echoed.
func (s *stack) compose(args ...string) (string, error) {
	full := []string{"compose", "-p", project,
		"-f", filepath.Join(s.root, "deploy", "compose", "compose.yaml"),
		"-f", filepath.Join(s.root, "tests", "lab", "compose", "oidc.yaml"),
		"-f", filepath.Join(s.dir, "l62-overlay.yaml")}
	cmd := exec.Command("docker", append(full, args...)...)
	cmd.Dir = s.root
	cmd.Env = append(os.Environ(),
		"PORT49_COMPOSE_LOCAL="+filepath.Join(s.dir, "local"),
		"PORT49_COMPOSE_CONFIG="+filepath.Join(s.dir, "config"),
		"PORT49_COMPOSE_SUBNET="+subnet)
	return s.run(cmd, "docker compose "+strings.Join(args, " "))
}

// projectDown is `docker compose -p port49labl62 down` on the project's
// labels alone: it needs no files, which a first run or a state being made
// again does not have.
func (s *stack) projectDown(volumes bool) (string, error) {
	args := []string{"compose", "-p", project, "down", "--remove-orphans"}
	if volumes {
		args = append(args, "-v")
	}
	return s.run(exec.Command("docker", args...), "docker "+strings.Join(args, " "))
}

func (s *stack) run(cmd *exec.Cmd, what string) (string, error) {
	out, err := cmd.CombinedOutput()
	if f, ferr := os.OpenFile(filepath.Join(s.dir, "compose.log"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644); ferr == nil {
		fmt.Fprintf(f, "%s $ %s\n%s\n(exit: %v)\n", time.Now().UTC().Format(time.RFC3339), what, out, err)
		f.Close()
	}
	return strings.TrimSpace(string(out)), err
}

func (s *stack) tail(n int) string {
	raw, _ := os.ReadFile(filepath.Join(s.dir, "compose.log"))
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// running is whether the project already has a container up.
func (s *stack) running() bool {
	out, err := exec.Command("docker", "ps", "-q", "--filter", "label=com.docker.compose.project="+project).Output()
	return err == nil && strings.TrimSpace(string(out)) != ""
}

func (s *stack) waitFor(what string, limit time.Duration, check func() error) {
	s.t.Helper()
	deadline := time.Now().Add(limit)
	for {
		err := check()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			s.t.Fatalf("%s did not answer within %s: %v\ncompose.log (tail):\n%s", what, limit, err, s.tail(30))
		}
		time.Sleep(time.Second)
	}
}

// followBrokerLog copies the broker container's log, minus the lines
// withheld names, to broker.log, from since on. `docker logs -f` ends when
// the container does, so it runs again until stopLogs; a restart can repeat
// the line or two at its edge.
func (s *stack) followBrokerLog(since time.Time) {
	path := filepath.Join(s.dir, "broker.log")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		s.t.Fatal(err)
	}
	// O_CREATE keeps the mode of a file that was already there.
	_ = os.Chmod(path, 0o644)
	fmt.Fprintf(f, "## %s harness started; lines with %s are withheld\n", time.Now().UTC().Format(time.RFC3339),
		strings.Join(withheldMarkers, ", "))
	ctx, cancel := context.WithCancel(context.Background())
	s.cancelLogs, s.logsDone = cancel, make(chan struct{})
	go func() {
		defer close(s.logsDone)
		defer f.Close()
		dropped := 0
		defer func() { fmt.Fprintf(f, "## %d lines withheld\n", dropped) }()
		for ctx.Err() == nil {
			cmd := exec.CommandContext(ctx, "docker", "logs", "-f", "--since", since.UTC().Format(time.RFC3339Nano),
				project+"-port49-broker-1")
			pr, pw := io.Pipe()
			cmd.Stdout, cmd.Stderr = pw, pw
			if err := cmd.Start(); err != nil {
				return
			}
			go func() { _ = cmd.Wait(); pw.Close() }()
			_, d, _ := copyFiltered(pr, f)
			dropped += d
			since = time.Now()
			select {
			case <-ctx.Done():
			case <-time.After(time.Second):
			}
		}
	}()
}

func (s *stack) stopLogs() {
	if s.cancelLogs != nil {
		s.cancelLogs()
		<-s.logsDone
	}
}

// listening is whether something accepts connections on addr.
func listening(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// tlsClient trusts the CA in caFile and checks the server's certificate for
// serverName, whatever address it is dialed at.
func tlsClient(t *testing.T, caFile, serverName string) *http.Client {
	t.Helper()
	raw, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		t.Fatalf("%s holds no certificate", caFile)
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: serverName, MinVersion: tls.VersionTLS13}}}
}

// answers is nil when GET url is 200.
func answers(c *http.Client, url string) error {
	resp, err := c.Get(url)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s", resp.Status)
	}
	return nil
}

// issuance is GET /v1/config's word on whether the broker can issue now.
func issuance(c *http.Client) (available bool, err error) {
	resp, err := c.Get("https://127.0.0.1:" + brokerPort + "/v1/config")
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("/v1/config answered %s", resp.Status)
	}
	return issuanceAvailable(body)
}

// issuanceAvailable reads /v1/config's issuance block: absent means the
// broker does not issue; "available" absent means it does.
func issuanceAvailable(body []byte) (bool, error) {
	var cfg struct {
		Issuance *struct {
			Available *bool `json:"available"`
		} `json:"issuance"`
	}
	if err := json.Unmarshal(body, &cfg); err != nil {
		return false, fmt.Errorf("/v1/config is not JSON: %w", err)
	}
	if cfg.Issuance == nil {
		return false, nil
	}
	return cfg.Issuance.Available == nil || *cfg.Issuance.Available, nil
}
