// L86 cell (c)'s identity provider: the lab's Keycloak (tests/lab/oidc/compose.yaml,
// compose project port49laboidc, the realm tests/lab/oidc/keycloak/realm.json), brought
// up and taken down by the cell itself with the same files and the same project the
// lab's own L45/L46/L55 tests use (tests/lab/oidc_test.go startKeycloak: that function
// is in the lab package behind -tags lab and is not importable, so the same steps are
// here), and the in-process broker made to verify its ID tokens and issue the
// certificate for the key `port49 login --oidc` puts on the token
// (issued_key_store: pkcs11).
//
// Nothing here reads realm.json or a password: Ryan types the lab user's password
// into Keycloak's own form in a browser.

package l60

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/issuer"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/testpki"
)

const (
	kcHost         = "keycloak.port49.lab"
	kcPort         = "18443"
	kcRealm        = "port49-lab"
	kcClientID     = "port49-cli"
	kcRedirectPort = 18749 // the realm's port49-cli redirect: http://127.0.0.1:18749/callback
	kcProject      = "port49laboidc"
	// kcImage is tests/lab/oidc/compose.yaml's image, pinned by digest; a unit
	// test holds the two equal, as the lab's own does.
	kcImage = "quay.io/keycloak/keycloak:26.4@sha256:9409c59bdfb65dbffa20b11e6f18b8abb9281d480c7ca402f51ed3d5977e6007"

	// The lab user cell (c) signs in as: the realm's alice, whose verified email the
	// broker's human verifier takes as the principal (tests/lab/oidc_e2e_test.go).
	l86OIDCUser   = "alice"
	l86OIDCDomain = "corp.example.com"
	l86OIDCEmail  = l86OIDCUser + "@" + l86OIDCDomain
)

// kcIssuer is the realm's issuer, as the broker and the CLI name it.
func kcIssuer() string { return "https://" + kcHost + ":" + kcPort + "/realms/" + kcRealm }

// kcDial reaches keycloak.port49.lab at the published port on loopback, so the
// broker (in this process) needs no hosts entry. The CLI, a child process, does:
// l86HostsOK checks it.
func kcDial(ctx context.Context, network, addr string) (net.Conn, error) {
	if host, _, _ := net.SplitHostPort(addr); host == kcHost {
		addr = "127.0.0.1:" + kcPort
	}
	return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
}

// kcHTTP reaches Keycloak by its issuer's name through kcDial, trusts ca, and
// follows no redirect.
func kcHTTP(ca *testpki.CA) *http.Client {
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.Pool(), MinVersion: tls.VersionTLS12}, DialContext: kcDial}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// l86HostsOK is whether the addresses keycloak.port49.lab resolves to include
// loopback, which the CLI and the browser need (the lab's L62 runbook, A6).
func l86HostsOK(addrs []string) bool {
	for _, a := range addrs {
		if a == "127.0.0.1" {
			return true
		}
	}
	return false
}

// l86Keycloak is the lab's Keycloak, up.
type l86Keycloak struct {
	h      *lab
	ca     *testpki.CA
	caFile string // the lab CA's PEM: the CLI's --oidc-ca
	http   *http.Client
}

// shQuote is a word for sg's shell.
func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// l86Docker is `docker args...` under `sg docker`, as the lab's dockerCmd runs it,
// for a shell that is not in the docker group.
func l86Docker(args ...string) *exec.Cmd {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = shQuote(a)
	}
	return exec.Command("sg", "docker", "-c", "docker "+strings.Join(q, " "))
}

// kcDown is `docker compose down -v` on the lab's project; a variable so a unit test can
// count the calls without Docker.
var kcDown = func(root string) error {
	d := kcCompose(root, "down", "-v")
	d.Dir = root
	if o, err := d.CombinedOutput(); err != nil {
		return fmt.Errorf("%v\n%s", err, tailText(string(o), 500))
	}
	return nil
}

// l86RegisterDown makes Keycloak come down when the cell ends and when it is killed.
func (h *lab) l86RegisterDown(root string) {
	h.t.Cleanup(func() {
		if err := kcDown(root); err != nil {
			h.t.Errorf("docker compose down -v (project %s) failed: %v\nrun it yourself: see tests/lab/L86-runbook.md, \"If a cell was killed\"",
				kcProject, err)
		}
	})
	h.mu.Lock()
	h.onKill = append(h.onKill, func() {
		if err := kcDown(root); err != nil {
			h.say("  docker compose down -v (project %s) failed: %v\n  run it yourself: tests/lab/L86-runbook.md, \"If a cell was killed\"", kcProject, err)
		}
	})
	h.mu.Unlock()
}

// kcUpDeadline bounds `docker compose up`: a first pull on a slow link must not eat the
// cell's whole -test.timeout. Keycloak's own discovery wait is separate.
const kcUpDeadline = 8 * time.Minute

// kcComposeCtx is kcCompose that is killed, with the `sg` shell's whole process group,
// when ctx ends.
func kcComposeCtx(ctx context.Context, root string, args ...string) *exec.Cmd {
	q := make([]string, 0, len(args)+5)
	for _, a := range append([]string{"compose", "-p", kcProject, "-f", filepath.Join(root, "tests", "lab", "oidc", "compose.yaml")}, args...) {
		q = append(q, shQuote(a))
	}
	cmd := exec.CommandContext(ctx, "sg", "docker", "-c", "docker "+strings.Join(q, " "))
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	return cmd
}

// kcCompose is `docker compose` on tests/lab/oidc/compose.yaml, project port49laboidc.
func kcCompose(root string, args ...string) *exec.Cmd {
	return l86Docker(append([]string{"compose", "-p", kcProject, "-f", filepath.Join(root, "tests", "lab", "oidc", "compose.yaml")}, args...)...)
}

// listening is whether something answers on addr.
func listening(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// l86StartKeycloak writes the lab PKI under tests/lab/logs/oidc (git-ignored, the
// directory compose.yaml mounts), brings project port49laboidc up on 127.0.0.1:18443,
// waits for the realm's discovery, and takes the project down (with its volumes) when
// the cell ends. The admin password is generated per run and goes only into a 0600
// file compose reads; it is never printed and nothing here reads realm.json.
func (h *lab) l86StartKeycloak() *l86Keycloak {
	h.t.Helper()
	root := repoRoot(h.t)
	if listening("127.0.0.1:" + kcPort) {
		h.t.Fatalf("INVALID: 127.0.0.1:%s is already in use: another lab's Keycloak is up (`docker ps` names it); stop it first", kcPort)
	}
	out := filepath.Join(root, "tests", "lab", "logs", "oidc")
	pki := filepath.Join(out, "pki")
	// A run starts from an empty directory: Keycloak's key below is chowned to its uid,
	// and a file owned by another uid could not be rewritten.
	if err := os.RemoveAll(pki); err != nil {
		h.t.Fatal(err)
	}
	if err := os.MkdirAll(pki, 0o755); err != nil {
		h.t.Fatal(err)
	}
	now := time.Now()
	ca, err := testpki.NewCA("port49 lab oidc CA", now.Add(-time.Hour), now.Add(48*time.Hour))
	if err != nil {
		h.t.Fatal(err)
	}
	leaf, err := ca.Issue(testpki.Leaf{CommonName: kcHost, DNSNames: []string{kcHost}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(48 * time.Hour)})
	if err != nil {
		h.t.Fatal(err)
	}
	cert, key, err := testpki.PEMs(leaf)
	if err != nil {
		h.t.Fatal(err)
	}
	pass := make([]byte, 18)
	if _, err := rand.Read(pass); err != nil {
		h.t.Fatal(err)
	}
	for _, f := range []struct {
		path string
		body []byte
		mode os.FileMode
	}{
		{filepath.Join(pki, "keycloak.pem"), cert, 0o644},
		{filepath.Join(pki, "keycloak-key.pem"), key, 0o600},
		{filepath.Join(pki, "lab-ca.pem"), ca.PEM(), 0o644},
		{filepath.Join(out, "admin.env"), []byte("KC_BOOTSTRAP_ADMIN_PASSWORD=" + hex.EncodeToString(pass) + "\n"), 0o600},
	} {
		if err := os.WriteFile(f.path, f.body, f.mode); err != nil {
			h.t.Fatal(err)
		}
		if err := os.Chmod(f.path, f.mode); err != nil {
			h.t.Fatal(err)
		}
	}
	// Keycloak reads its key as uid 1000 in the container, not as this user.
	if o, err := l86Docker("run", "--rm", "--user", "root", "--entrypoint", "chown", "-v", pki+":/pki", kcImage,
		"1000:0", "/pki/keycloak-key.pem").CombinedOutput(); err != nil {
		h.t.Fatalf("INVALID: the chown of Keycloak's key: %v\n%s", err, tailText(string(o), 500))
	}
	k := &l86Keycloak{h: h, ca: ca, caFile: filepath.Join(pki, "lab-ca.pem"), http: kcHTTP(ca)}
	ctx, cancel := context.WithTimeout(context.Background(), kcUpDeadline)
	defer cancel()
	cmd := kcComposeCtx(ctx, root, "up", "-d")
	cmd.Dir = root
	h.say("  starting the lab's Keycloak (docker compose -p %s; the first run pulls the image and imports the realm: minutes)", kcProject)
	h.l86RegisterDown(root)
	if o, err := cmd.CombinedOutput(); err != nil {
		why := ""
		if ctx.Err() != nil {
			why = fmt.Sprintf(" (the %s deadline: pre-pull the image yourself, runbook step 6)", kcUpDeadline)
		}
		h.t.Fatalf("INVALID: docker compose up: %v%s\n%s", err, why, tailText(string(o), 1500))
	}
	k.waitDiscovery(3 * time.Minute)
	h.obs("keycloak", "up: "+kcIssuer()+" (the lab's compose project "+kcProject+", image pinned by digest)")
	return k
}

// tailText is the last n bytes of s.
func tailText(s string, n int) string {
	if len(s) > n {
		return "..." + s[len(s)-n:]
	}
	return s
}

// waitDiscovery waits for the realm's discovery document: the realm import takes up to
// 90s at first start, and a container that is "up" may not have it yet.
func (k *l86Keycloak) waitDiscovery(within time.Duration) {
	k.h.t.Helper()
	deadline := time.Now().Add(within)
	for {
		resp, err := k.http.Get(kcIssuer() + "/.well-known/openid-configuration")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
			err = fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		if time.Now().After(deadline) {
			k.h.t.Fatalf("INVALID: Keycloak's realm %s never answered discovery within %v: %v", kcRealm, within, err)
		}
		time.Sleep(2 * time.Second)
	}
}

// l86WireOIDC makes br an OIDC-only broker that issues, as port49-broker is with
// `broker.identity: humans: [{type: oidc, ...}]` and `issuance: {}`: a human verifier
// for the realm's port49-cli client (principal from the email claim, in corp.example.com,
// asking the email scope), the keys ks holds, and an issuing CA held in memory. The
// CA anchors the one thing the broker's TLS takes a client certificate for, so the broker
// has no x509 human anchor of its own; it reports true for that (startBrokerWire).
func l86WireOIDC(t *testing.T, br *broker.Broker, now func() time.Time, ks *oidc.KeySet) bool {
	t.Helper()
	ca, err := issuer.Ephemeral(now())
	if err != nil {
		t.Fatalf("the issuing CA: %v", err)
	}
	algs, err := oidc.ParseAlgs(nil)
	if err != nil {
		t.Fatal(err)
	}
	v := oidc.VerifierConfig{Domain: oidc.Humans, Issuer: kcIssuer(), ClientID: kcClientID, PrincipalClaim: oidc.ClaimEmail,
		PrincipalDomains: []string{l86OIDCDomain}, Scopes: []string{"openid", "email"}, Algorithms: algs}
	br.Identity = &oidc.Set{Verifiers: []*oidc.Verifier{{VerifierConfig: v, Keys: ks}}, Timing: oidc.DefaultTiming, Now: now,
		M: br.Metrics}
	br.Issuer = ca
	return true
}

// startOIDCBroker serves the broker of cell (c): under the admin policy with the OIDC
// subject, Yubico's roots for the touch proof, and the realm's verifier and an issuing CA
// (l86WireOIDC). Its decision log is decisions-c.jsonl in the lab directory.
func (k *l86Keycloak) startOIDCBroker(pivRoots []byte) *labBroker {
	h := k.h
	h.t.Helper()
	return h.startLabBrokerWire(nil, pivRoots, l86OIDCPolicy, func(br *broker.Broker, now func() time.Time) bool {
		ks := oidc.NewKeySet(oidc.KeySetConfig{Issuer: kcIssuer(), Client: k.http, Refresh: oidc.DefaultTiming.JWKSRefresh,
			MaxAge: oidc.DefaultTiming.JWKSMaxAge, Now: now, M: br.Metrics})
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := ks.Fetch(ctx); err != nil {
			h.t.Fatalf("INVALID: the broker could not fetch Keycloak's keys: %v", err)
		}
		return l86WireOIDC(h.t, br, now, ks)
	})
}

// l86OIDCPolicy is the admin policy with the OIDC lab user as its one subject.
func l86OIDCPolicy(touch bool) string {
	return strings.ReplaceAll(l86Policy(touch), "user:"+labEmail, "user:"+l86OIDCEmail)
}

// l86Config is the user config `port49 login --oidc` reads in the cell's own HOME:
// the issued key a token's, named by issued_key, and the touch key on the same token.
// The two CA files go on the login's command line (--broker-ca, --oidc-ca), as every
// other cell's broker CA does: a throwaway directory's file is not one the config's
// ownership walk takes.
type l86Config struct {
	broker, touchKey, issuedKey string
	redirectPort                int
}

// text is config.yaml's text: snake_case keys as userconfig.File reads them.
func (c l86Config) text() string {
	return "broker: " + strconv.Quote(c.broker) + "\n" +
		"method: oidc\n" +
		"oidc_redirect_port: " + strconv.Itoa(c.redirectPort) + "\n" +
		"touch_key: " + strconv.Quote(c.touchKey) + "\n" +
		"issued_key_store: pkcs11\n" +
		"issued_key: " + strconv.Quote(c.issuedKey) + "\n"
}

// writeConfig writes ~/.port49/config.yaml under home, the directory 0700 and the
// file 0600 as the CLI's ownership walk wants them.
func (c l86Config) writeConfig(home string) error {
	dir := filepath.Join(home, ".port49")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(c.text()), 0o600)
}

// l86LoginWords drops the authorization address from a login's stderr before it is
// recorded: the address is Ryan's to open, and carries a state, a nonce and a
// code_challenge the note has no use for.
func l86LoginWords(stderr string) string {
	var keep []string
	for _, l := range strings.Split(stderr, "\n") {
		if strings.Contains(l, "https://") || strings.Contains(l, "http://") {
			l = "<address>"
		}
		keep = append(keep, l)
	}
	return strings.Join(keep, "\n")
}
