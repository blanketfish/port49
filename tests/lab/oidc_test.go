//go:build lab

package lab

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/tests/lab/labcreds"
)

const (
	kcHost     = "keycloak.port49.lab"
	kcPort     = "18443"
	kcRealm    = "port49-lab"
	kcClient   = "port49-cli"
	kcRedirect = "http://127.0.0.1:18749/callback"
	rcvHost    = "host.port49.lab"
	rcvPort    = "18750"
	// kcServiceAccountID is realm.json's fixed id for port49-svc's service
	// account: its client-credentials tokens' sub (Ruling 21).
	kcServiceAccountID = "5f3c2d1e-0000-4000-8000-000000000049"
	// kcImage is compose.yaml's image, pinned by digest; a unit test holds
	// the two equal.
	kcImage = "quay.io/keycloak/keycloak:26.4@sha256:9409c59bdfb65dbffa20b11e6f18b8abb9281d480c7ca402f51ed3d5977e6007"
)

// jwsShape is a compact JWS: three base64url parts. Nothing the lab writes
// may hold one, since its signature would be in it.
var jwsShape = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`)

type keycloak struct {
	URL    string // the issuer
	HTTP   *http.Client
	CAFile string
	out    string // the run's output root
	dir    string // tests/lab/oidc
	pki    string // tests/lab/logs/oidc/pki
	admin  string // the admin password, generated per run, never printed
	ca     *testpki.CA

	mu      sync.Mutex
	secrets []string // every value no note, evidence line or message may hold
}

// labSecrets are realm.json's published values: not secret, but nothing the
// lab writes has a reason to carry them either.
var labSecrets = []string{"lab-only-alice-password", "lab-only-svc-secret"}

// know registers values the run must never write out: the admin password, and
// each code, verifier, state, token and cookie value the flow handles. A value
// under 8 bytes is skipped, since it would match ordinary text.
func (k *keycloak) know(vals ...string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, v := range vals {
		if len(v) >= 8 && !slices.Contains(k.secrets, v) {
			k.secrets = append(k.secrets, v)
		}
	}
}

func (k *keycloak) known() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]string(nil), k.secrets...)
}

// errCause is err without the request URL a *url.Error carries: a query string
// holds a state, a challenge or a session code. Its Op and its cause remain.
func errCause(err error) string {
	if err == nil {
		return ""
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Op + ": " + ue.Err.Error()
	}
	return err.Error()
}

// leakIn says whether text holds a compact JWS or any of secrets, and what
// kind, never which.
func leakIn(text string, secrets []string) error {
	if jwsShape.MatchString(text) {
		return fmt.Errorf("it holds a compact JWS")
	}
	for _, v := range secrets {
		if v != "" && strings.Contains(text, v) {
			return fmt.Errorf("it holds a value the run registered as secret")
		}
	}
	return nil
}

// startKeycloak writes the PKI and the admin password, brings Keycloak up
// and waits for the realm's discovery document: the realm import takes up
// to 90s at first start, and a container that is "up" may not have it yet.
func startKeycloak(t *testing.T) *keycloak {
	t.Helper()
	repo, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	out, err := directoryOut() // PORT49_LAB_DIRECTORY_OUT, else the repository
	if err != nil {
		t.Fatal(err)
	}
	k := &keycloak{out: out, dir: filepath.Join(repo, "tests", "lab", "oidc"),
		pki: filepath.Join(repo, "tests", "lab", "logs", "oidc", "pki"), URL: "https://" + kcHost + ":" + kcPort + "/realms/" + kcRealm}
	// A run starts from an empty directory: the key below is chowned to
	// Keycloak's uid, and a file owned by another uid could not be rewritten.
	if err := os.RemoveAll(k.pki); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(k.pki, 0o755); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if k.ca, err = testpki.NewCA("port49 lab oidc CA", now.Add(-time.Hour), now.Add(48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	for name, leaf := range map[string]testpki.Leaf{
		"keycloak": {CommonName: kcHost, DNSNames: []string{kcHost}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour)},
		"receiver": {CommonName: rcvHost, DNSNames: []string{rcvHost, "port49-broker"}, NotBefore: now.Add(-time.Hour),
			NotAfter: now.Add(48 * time.Hour)},
	} {
		c, err := k.ca.Issue(leaf)
		if err != nil {
			t.Fatal(err)
		}
		cert, key, err := testpki.PEMs(c)
		if err != nil {
			t.Fatal(err)
		}
		// Keys are 0600; Keycloak's own is chowned to its uid below. The
		// certificates are public.
		writeLab(t, filepath.Join(k.pki, name+".pem"), cert, 0o644)
		writeLab(t, filepath.Join(k.pki, name+"-key.pem"), key, 0o600)
	}
	k.CAFile = filepath.Join(k.pki, "lab-ca.pem")
	writeLab(t, k.CAFile, k.ca.PEM(), 0o644)
	// Keycloak reads its key as uid 1000 in the container, not as this user.
	if o, err := dockerCmd("run", "--rm", "--user", "root", "--entrypoint", "chown", "-v", k.pki+":/pki", kcImage,
		"1000:0", "/pki/keycloak-key.pem").CombinedOutput(); err != nil {
		t.Fatalf("chown of Keycloak's key: %v\n%s", err, tailOf(string(o), 500))
	}
	k.admin = randomSecret(t)
	k.know(append([]string{k.admin}, labSecrets...)...)
	writeLab(t, filepath.Join(filepath.Dir(k.pki), "admin.env"), []byte("KC_BOOTSTRAP_ADMIN_PASSWORD="+k.admin+"\n"), 0o600)

	k.HTTP = keycloakClient(k.ca)

	if o, err := k.compose("up", "-d").CombinedOutput(); err != nil {
		t.Fatalf("docker compose up: %v\n%s", err, tailOf(string(o), 2000))
	}
	t.Cleanup(func() {
		logs, _ := k.compose("logs", "--no-color", "keycloak").CombinedOutput()
		_ = os.WriteFile(filepath.Join(filepath.Dir(k.pki), "keycloak.log"), logs, 0o644)
		_, _ = k.compose("down", "-v").CombinedOutput()
	})
	waitDiscovery(t, k, 3*time.Minute)
	return k
}

// kcDial reaches keycloak.port49.lab at the published port on loopback.
func kcDial(ctx context.Context, network, addr string) (net.Conn, error) {
	if host, _, _ := net.SplitHostPort(addr); host == kcHost {
		addr = "127.0.0.1:" + kcPort
	}
	return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
}

// keycloakClient reaches Keycloak by its issuer's name through kcDial,
// trusts ca, and follows no redirect: the flow reads each one.
func keycloakClient(ca *testpki.CA) *http.Client {
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.Pool(), MinVersion: tls.VersionTLS12},
		DialContext: kcDial}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// waitDiscovery waits for the realm's discovery document: the realm import
// takes up to 90s at first start, and a container that is "up" may not
// have it yet.
func waitDiscovery(t *testing.T, k *keycloak, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		resp, err := k.HTTP.Get(k.URL + "/.well-known/openid-configuration")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("Keycloak's realm %s never answered discovery: %v", kcRealm, err)
		}
		time.Sleep(2 * time.Second)
	}
}

// adminFromEnv reads the admin password from the admin.env a run wrote.
func (k *keycloak) adminFromEnv(t *testing.T, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	k.admin = strings.TrimSpace(strings.TrimPrefix(string(b), "KC_BOOTSTRAP_ADMIN_PASSWORD="))
}

func (k *keycloak) compose(args ...string) *exec.Cmd {
	return dockerCmd(append([]string{"compose", "-p", "port49laboidc", "-f", filepath.Join(k.dir, "compose.yaml")}, args...)...)
}

// Version is what the running image says it is.
func (k *keycloak) Version() string {
	out, _ := k.compose("exec", "-T", "keycloak", "/opt/keycloak/bin/kc.sh", "--version").CombinedOutput()
	return oneLineMax(strings.TrimSpace(string(out)), 200) + "; image " + imageID(kcImage)
}

// Admin is a master-realm admin token, from the password this run made.
func (k *keycloak) Admin(t *testing.T) string {
	t.Helper()
	form := url.Values{"grant_type": {"password"}, "client_id": {"admin-cli"}, "username": {"admin"},
		"password": {k.admin}}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	k.postForm(t, "https://"+kcHost+":"+kcPort+"/realms/master/protocol/openid-connect/token", form, &tok)
	return tok.AccessToken
}

// adminDo is one admin REST call; out, when not nil, is the JSON answer.
func (k *keycloak) adminDo(t *testing.T, method, path string, body any, out any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, "https://"+kcHost+":"+kcPort+"/admin/realms/"+kcRealm+path, rd)
	req.Header.Set("Authorization", "Bearer "+k.Admin(t))
	req.Header.Set("Content-Type", "application/json")
	resp, err := k.HTTP.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %s", method, path, errCause(err))
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		t.Fatalf("%s %s: %s %s", method, path, resp.Status, oneLineMax(string(raw), 300))
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
	}
}

// SetLogoutURL points port49-cli's back-channel logout at u.
func (k *keycloak) SetLogoutURL(t *testing.T, u string) {
	t.Helper()
	var clients []map[string]any
	k.adminDo(t, "GET", "/clients?clientId="+kcClient, nil, &clients)
	if len(clients) != 1 {
		t.Fatalf("%d clients named %s", len(clients), kcClient)
	}
	c := clients[0]
	attrs, _ := c["attributes"].(map[string]any)
	attrs["backchannel.logout.url"] = u
	k.adminDo(t, "PUT", "/clients/"+c["id"].(string), c, nil)
	// Read it back: a PUT that did not take would send every logout to
	// receiver.invalid, and read as a measured "Keycloak sends nothing".
	clients = nil
	k.adminDo(t, "GET", "/clients?clientId="+kcClient, nil, &clients)
	if got, _ := clients[0]["attributes"].(map[string]any)["backchannel.logout.url"].(string); len(clients) != 1 || got != u {
		t.Fatalf("INVALID: %s's backchannel.logout.url did not take the receiver's URL; no note is written", kcClient)
	}
}

func (k *keycloak) UserID(t *testing.T, username string) string {
	t.Helper()
	var users []map[string]any
	k.adminDo(t, "GET", "/users?exact=true&username="+url.QueryEscape(username), nil, &users)
	if len(users) != 1 {
		t.Fatalf("%d users named %s", len(users), username)
	}
	return users[0]["id"].(string)
}

// LogoutUser is an administrator signing a user out of every session.
func (k *keycloak) LogoutUser(t *testing.T, id string) {
	k.adminDo(t, "POST", "/users/"+id+"/logout", nil, nil)
}

// DeleteSession is an administrator ending one session.
func (k *keycloak) DeleteSession(t *testing.T, sid string) {
	k.adminDo(t, "DELETE", "/sessions/"+sid, nil, nil)
}

func (k *keycloak) postForm(t *testing.T, u string, form url.Values, out any) {
	t.Helper()
	resp, err := k.HTTP.PostForm(u, form)
	if err != nil {
		t.Fatalf("POST %s: %s", strings.SplitN(u, "?", 2)[0], errCause(err))
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("POST %s: %s %s", u, resp.Status, oneLineMax(string(raw), 300))
	}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("POST %s: %v", u, err)
	}
}

// claimsOf decodes a JWS's header and claims without verifying it: the lab
// inspects what the provider sent, and verifies nothing.
func claimsOf(jwt string) (map[string]any, map[string]any) {
	parts := strings.Split(jwt, ".")
	dec := func(s string) map[string]any {
		b, _ := base64.RawURLEncoding.DecodeString(s)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		return m
	}
	if len(parts) != 3 {
		return nil, nil
	}
	return dec(parts[0]), dec(parts[1])
}

// received is one request the receiver took, the logout token decoded
// (header and claims, never the signature).
type received struct {
	At          time.Time
	ContentType string
	Header      map[string]any
	Claims      map[string]any
	Answered    int
}

// receiver is an HTTPS endpoint Keycloak posts logout tokens to, answering
// each with the status Answer set (200 until set).
type receiver struct {
	URL    string
	srv    *http.Server
	mu     sync.Mutex
	status int
	got    []received
}

func startReceiver(t *testing.T, k *keycloak) *receiver {
	t.Helper()
	c, err := k.ca.Issue(testpki.Leaf{CommonName: rcvHost, DNSNames: []string{rcvHost}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	r := &receiver{URL: "https://" + rcvHost + ":" + rcvPort + "/v1/logout", status: 200}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/logout", func(w http.ResponseWriter, req *http.Request) {
		_ = req.ParseForm()
		h, cl := claimsOf(req.PostForm.Get("logout_token"))
		r.mu.Lock()
		status := r.status
		r.got = append(r.got, received{At: time.Now(), ContentType: req.Header.Get("Content-Type"), Header: h,
			Claims: cl, Answered: status})
		r.mu.Unlock()
		w.WriteHeader(status)
	})
	ln, err := net.Listen("tcp", "0.0.0.0:"+rcvPort)
	if err != nil {
		t.Fatal(err)
	}
	r.srv = &http.Server{Handler: mux, TLSConfig: &tls.Config{Certificates: []tls.Certificate{c}}}
	go func() { _ = r.srv.ServeTLS(ln, "", "") }()
	t.Cleanup(r.Stop)
	return r
}

func (r *receiver) Answer(status int) { r.mu.Lock(); r.status = status; r.mu.Unlock() }
func (r *receiver) Stop()             { _ = r.srv.Close() }
func (r *receiver) Got() []received {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]received(nil), r.got...)
}

// checkLogoutToken says why a request the receiver took is not a logout
// token from this realm for port49-cli. The receiver listens on every
// interface and records any POST, so a stray one must stop the run, never
// become a row.
func checkLogoutToken(issuer string, g received) error {
	if g.Claims == nil {
		return fmt.Errorf("a request with no decodable logout_token")
	}
	if g.Claims["iss"] != issuer {
		return fmt.Errorf("a logout token whose iss is not the realm's")
	}
	named := false
	switch aud := g.Claims["aud"].(type) {
	case string:
		named = aud == kcClient
	case []any:
		named = slices.Contains(aud, any(kcClient))
	}
	if !named {
		return fmt.Errorf("a logout token whose aud does not name %s", kcClient)
	}
	return nil
}

// waitGot waits until the receiver holds more than n requests, or within.
func (r *receiver) waitGot(n int, within time.Duration) []received {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if g := r.Got(); len(g) > n {
			return g
		}
		time.Sleep(250 * time.Millisecond)
	}
	return r.Got()
}

// writeOIDCResult writes tests/lab/results/<row>-keycloak.md in spec §15
// rule 3's form, through labcreds.RedactNote.
func writeOIDCResult(t *testing.T, k *keycloak, row, claim, observation, evidencePath string) {
	t.Helper()
	dir := filepath.Join(k.out, "tests", "lab", "results")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	note := oidcNote(row, claim, observation, evidencePath, runLine(), k.Version())
	if err := oidcNoteLeak(note, k.known()); err != nil {
		t.Fatalf("the %s note: %v", row, err)
	}
	path := filepath.Join(dir, row+"-keycloak.md")
	if err := os.WriteFile(path, []byte(labcreds.RedactNote(note)), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s", path)
}

// oidcEvidence opens tests/lab/evidence/<name>.json and returns a line
// writer; a line is decoded JWS parts and what the step was, never a
// signature or a raw token.
func oidcEvidence(t *testing.T, k *keycloak, name string) (func(step string, v any), string) {
	t.Helper()
	dir := filepath.Join(k.out, "tests", "lab", "evidence")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name+".json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	var mu sync.Mutex
	return func(step string, v any) {
		mu.Lock()
		defer mu.Unlock()
		b, err := oidcEvidenceLine(step, v, k.known())
		if err != nil {
			t.Errorf("evidence step %q: %v", step, err)
			return
		}
		_, _ = f.Write(b)
	}, filepath.Join("tests", "lab", "evidence", name+".json")
}

// oidcEvidenceLine is one evidence line, newline included. It refuses a value
// that holds a compact JWS: evidence is decoded headers and claims, never a
// token or its signature.
func oidcEvidenceLine(step string, v any, secrets []string) ([]byte, error) {
	b, err := json.Marshal(map[string]any{"step": step, "value": v})
	if err != nil {
		return nil, err
	}
	if err := leakIn(string(b), secrets); err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// oidcNote is a results note in spec §15 rule 3's form, not yet redacted.
func oidcNote(row, claim, observation, evidencePath, run, version string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s — keycloak\n\n", row)
	fmt.Fprintf(&b, "- **Date measured:** %s\n", time.Now().UTC().Format("2006-01-02"))
	fmt.Fprintf(&b, "- **Run:** %s\n", run) // the commit and the test run, as 7g's notes carry (pre-flight M-23)
	fmt.Fprintf(&b, "- **Platform:** Keycloak, as a container on `tests/lab/oidc/compose.yaml` (no network device)\n")
	fmt.Fprintf(&b, "- **Image version:** %s\n", version)
	fmt.Fprintf(&b, "- **Capture:** `%s`: one JSON line per request or token, with the JWS header and claims decoded "+
		"and the signature dropped (the wire is TLS, so a pcap would be encrypted).\n", evidencePath)
	fmt.Fprintf(&b, "- **Credentials:** none here or in the evidence: the admin password is generated per run and never "+
		"printed; the lab user's password and the service secret are the realm file's published lab values.\n")
	fmt.Fprintf(&b, "\n## Claim\n\n%s\n\n## Observation\n\n%s\n", claim, observation)
	return b.String()
}

// oidcNoteLeak says why a note must not be written: it holds a compact JWS or
// a value the run registered as secret (the admin password, a code, a token).
func oidcNoteLeak(note string, secrets []string) error { return leakIn(note, secrets) }

func writeLab(t *testing.T, path string, body []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, body, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func randomSecret(t *testing.T) string {
	t.Helper()
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
