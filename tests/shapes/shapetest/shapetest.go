// Package shapetest is what every deployment shape's smoke shares (plan 12b,
// Task 6): the compose smoke here, the systemd smoke (Task 9) and the kind
// smoke (Task 11). It is a plain package with no build tag and is imported
// only by tagged tests, so `go test ./...` never needs Docker, systemd or a
// cluster. Nothing in it prints a key, a token or a challenge: a failure names
// the reference or the field.
package shapetest

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/tacacs/wire"
	"github.com/rhwendt/port49/internal/testpki"
	"gopkg.in/yaml.v3"
)

// Device is the smallest TACACS+ client that logs in and asks for
// authorization, one exchange per connection, as port49d's own tests'
// tacacsClient (internal/port49d/run_test.go), which a smoke cannot import.
type Device struct {
	T    *testing.T
	Addr string
	Key  []byte
}

func (d Device) exchange(typ wire.Type, body []byte) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", d.Addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	h := wire.Header{MajorVersion: 0xc, Type: typ, SeqNo: 1, SessionID: 0x5eed, Length: uint32(len(body))}
	if _, err := conn.Write(append(h.Encode(), wire.Obfuscate(h, d.Key, body)...)); err != nil {
		return nil, err
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	hb := make([]byte, wire.HeaderLen)
	if _, err := io.ReadFull(conn, hb); err != nil {
		return nil, err
	}
	rh, _ := wire.DecodeHeader(hb)
	rb := make([]byte, rh.Length)
	if _, err := io.ReadFull(conn, rb); err != nil {
		return nil, err
	}
	return wire.Obfuscate(rh, d.Key, rb), nil
}

// TryLogin is a PAP login: the reply's status, or the error of a connection
// that was not answered (port49d resets a source it does not admit, and
// closes on a body it cannot open under the key).
func (d Device) TryLogin(user, password string) (uint8, error) {
	b, err := d.exchange(wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, PrivLvl: 1,
		AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte(user), Port: []byte("ssh"),
		RemAddr: []byte("198.51.100.4"), Data: []byte(password)}.Encode())
	if err != nil {
		return 0, err
	}
	r, err := wire.DecodeAuthenReply(b)
	if err != nil {
		return 0, err
	}
	return r.Status, nil
}

// Login is TryLogin that fails the test on a connection that was not
// answered.
func (d Device) Login(user, password string) uint8 {
	d.T.Helper()
	st, err := d.TryLogin(user, password)
	if err != nil {
		d.T.Fatalf("login: %v (a reset is port49d not admitting the source it saw: the inventory names "+
			"the stack's gateway; read port49d's log)", err)
	}
	return st
}

// Permits asks for user's session (no words) or a command at 15.
func (d Device) Permits(user string, words ...string) bool {
	d.T.Helper()
	priv := uint8(15)
	args := [][]byte{[]byte("service=shell")}
	if len(words) == 0 {
		args, priv = append(args, []byte("cmd=")), 1
	} else {
		args = append(args, []byte("cmd="+words[0]))
		for _, w := range words[1:] {
			args = append(args, []byte("cmd-arg="+w))
		}
		args = append(args, []byte("cmd-arg=<cr>"))
	}
	b, err := d.exchange(wire.TypeAuthor, wire.AuthorRequest{AuthenMethod: wire.AuthenMethodTACACSPlus,
		PrivLvl: priv, AuthenType: wire.AuthenTypeASCII, Service: wire.AuthenServiceLogin, User: []byte(user),
		Port: []byte("vty1"), Args: args}.Encode())
	if err != nil {
		d.T.Fatalf("authorize: %v", err)
	}
	r, err := wire.DecodeAuthorResponse(b)
	if err != nil {
		d.T.Fatal(err)
	}
	return r.Status == wire.AuthorStatusPassAdd || r.Status == wire.AuthorStatusPassRepl
}

// brokerClient is an HTTPS client for the broker at brokerDir's lab CA, with
// the client certificate files cert and key in brokerDir.
func brokerClient(t *testing.T, brokerDir, cert, key string) *http.Client {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(filepath.Join(brokerDir, cert), filepath.Join(brokerDir, key))
	if err != nil {
		t.Fatalf("the client certificate %s: %v", cert, err)
	}
	caPEM, err := os.ReadFile(filepath.Join(brokerDir, testpki.LabCA))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		Certificates: []tls.Certificate{pair}, RootCAs: roots, MinVersion: tls.VersionTLS13}}}
}

// mintRaw asks the broker at addr for a token on device with the client
// certificate files cert and key, and returns the status and body. A 503 is
// tried again for up to 60s, as port49 workload retries it: a first start's
// broker holds every mint until its takeover judges the bundle (decision 36,
// the start gate). The body may hold a token: callers never print it.
func mintRaw(t *testing.T, brokerDir, cert, key, addr, device string) (int, []byte) {
	t.Helper()
	c := brokerClient(t, brokerDir, cert, key)
	for deadline := time.Now().Add(60 * time.Second); ; time.Sleep(time.Second) {
		resp, err := c.Post("https://"+addr+"/v1/tokens", "application/json",
			bytes.NewReader([]byte(`{"devices":["`+device+`"]}`)))
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusServiceUnavailable || time.Now().After(deadline) {
			return resp.StatusCode, body
		}
		t.Logf("mint: 503, the broker's start gate; trying again")
	}
}

// mintItem is mintRaw's one device answer. The item's String withholds its
// tokens.
func mintItem(t *testing.T, brokerDir, cert, key, addr, device string) api.MintItem {
	t.Helper()
	status, body := mintRaw(t, brokerDir, cert, key, addr, device)
	var out api.MintResponse
	if err := json.Unmarshal(body, &out); err != nil || len(out.Results) != 1 {
		var e api.Error
		json.Unmarshal(body, &e)
		t.Fatalf("mint: status %d, error %q, %d result(s)", status, e.Error, len(out.Results))
	}
	return out.Results[0]
}

// Mint asks the broker at addr for a token on device with the trial's own
// client certificate (testpki.LabClientCert) and returns it. It is never
// printed.
func Mint(t *testing.T, brokerDir, brokerAddr, device string) string {
	t.Helper()
	it := mintItem(t, brokerDir, testpki.LabClientCert, testpki.LabClientKey, brokerAddr, device)
	if it.Login == "" {
		// MintItem.String withholds tokens (internal/broker/api/api.go), so %v
		// names the refusal and prints no credential.
		t.Fatalf("mint: %v", it)
	}
	return it.Login
}

// mintAs is mintItem with principal's own client certificate
// (testpki.LabClientFiles of its email).
func mintAs(t *testing.T, brokerDir, principal, brokerAddr, device string) api.MintItem {
	t.Helper()
	cert, key := testpki.LabClientFiles(strings.TrimPrefix(principal, "user:"))
	return mintItem(t, brokerDir, cert, key, brokerAddr, device)
}

// Ready waits up to 3 minutes for /readyz at metricsAddr to answer 200.
func Ready(t *testing.T, metricsAddr string) {
	t.Helper()
	var err error
	for deadline := time.Now().Add(3 * time.Minute); ; time.Sleep(time.Second) {
		var resp *http.Response
		resp, err = http.Get("http://" + metricsAddr + "/readyz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
			err = fmt.Errorf("status %d", resp.StatusCode)
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s/readyz not 200 in 3m (%v)", metricsAddr, err)
		}
	}
}

// WaitFor polls ok every second until it is true, or fails naming what within
// the time.
func WaitFor(t *testing.T, what string, within time.Duration, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(within); ; time.Sleep(time.Second) {
		if ok() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not happen within %v", what, within)
		}
	}
}

var floorLine = regexp.MustCompile(`etcd .*, at or above the floor`)

// FloorLine fails unless one line of log is port49d's etcd floor line (spec
// §13 decision 54 ruling 14: `etcd ..., at or above the floor`) and names
// every URL of members: each smoke configures every member, never a Service
// or a VIP.
func FloorLine(t *testing.T, log string, members []string) {
	t.Helper()
	for _, line := range strings.Split(log, "\n") {
		if !floorLine.MatchString(line) {
			continue
		}
		all := true
		for _, m := range members {
			all = all && strings.Contains(line, m)
		}
		if all {
			return
		}
	}
	t.Fatalf("no line of port49d's log says `etcd ..., at or above the floor` and names every member (%s)",
		strings.Join(members, ", "))
}

// Gauge reads the one unlabelled metric name at metricsAddr.
func Gauge(t *testing.T, metricsAddr, name string) float64 {
	t.Helper()
	resp, err := http.Get("http://" + metricsAddr + "/metrics")
	if err != nil {
		t.Fatalf("metrics at %s: %v", metricsAddr, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	v, err := gaugeIn(string(body), name)
	if err != nil {
		t.Fatalf("metrics at %s: %v", metricsAddr, err)
	}
	return v
}

// gaugeIn is the value of the unlabelled sample name in an exposition.
func gaugeIn(exposition, name string) (float64, error) {
	for _, line := range strings.Split(exposition, "\n") {
		if v, ok := strings.CutPrefix(line, name+" "); ok {
			return strconv.ParseFloat(strings.TrimSpace(v), 64)
		}
	}
	return 0, fmt.Errorf("no unlabelled sample %s", name)
}

// RootsName is the file AdminSetup writes into the broker's PKI directory.
const RootsName = "attestation-roots.pem"

// AdminSetup writes a testpki.NewPIV root into dir as RootsName, the file
// broker.identity.per_login_mfa.hardware_key_touch.attestation_roots_file
// names, and returns its path with the policy subject that grants the
// operator (testpki.ComposeOperator, whose client certificate dir holds,
// cut by the broker's own lab CA) api: [revoke_others]. A smoke renders both
// into its broker config and policy (AdminBroker, AdminPolicy), so the admin
// cell answers 401 admin_touch_required, not 503 admin_touch_unavailable or 403.
func AdminSetup(t *testing.T, dir string) (rootsFile string, policySubject string) {
	t.Helper()
	cert, key := testpki.LabClientFiles(testpki.ComposeOperator)
	for _, f := range []string{cert, key} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatalf("AdminSetup: the operator's client certificate files are not in %s: %v", dir, err)
		}
	}
	piv, err := testpki.NewPIV(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rootsFile = filepath.Join(dir, RootsName)
	if err := os.WriteFile(rootsFile, piv.Anchors(), 0o644); err != nil {
		t.Fatal(err)
	}
	return rootsFile, `  - {name: operator, identity: ["user:` + testpki.ComposeOperator + `"], username: operator, token_ttl: 15m, api: [revoke_others, lift_revocations]}`
}

var clientCALine = regexp.MustCompile(`(?m)^  client_ca_file: (.+)$`)

// AdminBroker moves a broker config's client_ca_file shorthand into
// broker.identity.humans and adds the attestation roots at rootsInContainer,
// the two forms being refused together. The config holds exactly one
// client_ca_file line.
func AdminBroker(t *testing.T, brokerYAML, rootsInContainer string) string {
	t.Helper()
	if n := len(clientCALine.FindAllString(brokerYAML, -1)); n != 1 {
		t.Fatalf("the broker config has %d client_ca_file lines, want exactly 1", n)
	}
	return clientCALine.ReplaceAllString(brokerYAML, "  identity:\n    humans:\n      - {type: x509, trust_anchor_file: $1}\n"+
		"    per_login_mfa:\n      hardware_key_touch: {attestation_roots_file: "+rootsInContainer+"}")
}

// AdminPolicy adds subject (AdminSetup's) to the end of policyYAML's subjects
// list, which the config must hold as the block before `grants:`.
func AdminPolicy(t *testing.T, policyYAML, subject string) string {
	t.Helper()
	if strings.Count(policyYAML, "\ngrants:") != 1 {
		t.Fatal("the policy has no single `grants:` line to put the operator's subject before")
	}
	return strings.Replace(policyYAML, "\ngrants:", "\n"+subject+"\ngrants:", 1)
}

// WithGrantedSubject adds a subject named name with the given identity, and a grant of role over scope
// to it, to a policy that holds its subjects as the block before `grants:`: the admin cells revoke and
// mint as a principal the shipped policy does not name. The compose smoke's policy already holds both.
func WithGrantedSubject(policyYAML, name, identity, scope, role string) (string, error) {
	if strings.Count(policyYAML, "\ngrants:\n") != 1 {
		return "", fmt.Errorf("shapetest: the policy has no single `grants:` line to add %s before", name)
	}
	subject := `  - {name: ` + name + `, identity: ["` + identity + `"], username: ` + name + `, token_ttl: 15m}`
	grant := `  - {subject: ` + name + `, scope: ` + scope + `, roles: [` + role + `]}`
	return strings.Replace(policyYAML, "\ngrants:\n", "\n"+subject+"\ngrants:\n"+grant+"\n", 1), nil
}

// AdminNeedsTouch: the operator's POST /v1/tokens/revoke naming principal is
// answered 401 admin_touch_required with a challenge (the revocation is not
// made: nothing was signed), and a mint by principal still succeeds after.
func AdminNeedsTouch(t *testing.T, brokerDir, brokerAddr, principal string) {
	t.Helper()
	cert, key := testpki.LabClientFiles(testpki.ComposeOperator)
	c := brokerClient(t, brokerDir, cert, key)
	var resp *http.Response
	var err error
	for deadline := time.Now().Add(60 * time.Second); ; time.Sleep(time.Second) {
		resp, err = c.Post("https://"+brokerAddr+"/v1/tokens/revoke", "application/json",
			bytes.NewReader([]byte(`{"principal":"`+principal+`"}`)))
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusServiceUnavailable || time.Now().After(deadline) {
			break
		}
		resp.Body.Close()
	}
	defer resp.Body.Close()
	var e api.Error
	if err := json.NewDecoder(resp.Body).Decode(&e); err != nil {
		t.Fatalf("revoke: status %d, the body does not decode", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusUnauthorized || e.Error != "admin_touch_required" || e.Admin == nil || e.Admin.Challenge == "" {
		t.Fatalf("revoke with no touch: status %d, error %q, challenge present %v; want 401 admin_touch_required with a challenge",
			resp.StatusCode, e.Error, e.Admin != nil && e.Admin.Challenge != "")
	}
	if it := mintAs(t, brokerDir, principal, brokerAddr, "smoke1"); it.Login == "" {
		t.Fatalf("a mint by %s after the unproved revoke: %v", principal, it)
	}
}

// OfflineRevoked: a mint by principal is refused 401 credential_revoked.
func OfflineRevoked(t *testing.T, brokerDir, brokerAddr, principal string) {
	t.Helper()
	cert, key := testpki.LabClientFiles(strings.TrimPrefix(principal, "user:"))
	status, body := mintRaw(t, brokerDir, cert, key, brokerAddr, "smoke1")
	var e api.Error
	json.Unmarshal(body, &e)
	if status != http.StatusUnauthorized || e.Error != "credential_revoked" {
		t.Fatalf("a mint by %s after the offline revoke: status %d, error %q; want 401 credential_revoked",
			principal, status, e.Error)
	}
}

// OfflineLifted: a mint by principal is issued again after the revocation was
// lifted.
func OfflineLifted(t *testing.T, brokerDir, brokerAddr, principal string) {
	t.Helper()
	if it := mintAs(t, brokerDir, principal, brokerAddr, "smoke1"); it.Login == "" {
		t.Fatalf("a mint by %s after the lift: verdict %q, reason %q; want a token", principal, it.Verdict, it.Reason)
	}
}

// Rotator is what RotateCell needs of a shape: where its key files and
// policy live and how to write them as the shape's own users would.
type Rotator interface {
	KeyDir() string                            // the directory a policy's file: key reference names
	BasePolicy() []byte                        // the policy now running, version 1 current
	WritePolicy(policyYAML []byte) error       // replace it where every process reads it, by rename
	WriteKey(name string, secret []byte) error // a new file named name in KeyDir, never an overwrite
	StartedAt() string                         // port49d's start time, for "no restart"
}

// WithAcceptV2 is policyYAML with key set k's version 2 added to accept,
// naming the file KeyDir/tacacs_v2 (the key set's schema is current, accept,
// retired). Comments are not kept.
func WithAcceptV2(policyYAML []byte, keyDir string) ([]byte, error) {
	var doc map[string]any
	if err := yaml.Unmarshal(policyYAML, &doc); err != nil {
		return nil, err
	}
	keys, _ := doc["keys"].(map[string]any)
	k, _ := keys["k"].(map[string]any)
	if k == nil {
		return nil, fmt.Errorf("the policy has no keys.k")
	}
	k["accept"] = []any{map[string]any{"version": 2, "secret_ref": "file:" + filepath.Join(keyDir, "tacacs_v2")}}
	return yaml.Marshal(doc)
}

// v1Back is how long RotateCell waits for the version 1 login after the version 2
// miss: the strike's backoff (limits.malformed_backoff_max, 5 s) and the policy's
// watch interval, with margin.
const v1Back = 15 * time.Second

// RotateCell adds a device key version with no restart (spec §13 decision 54
// ruling 2). In order: the policy names version 2 while its file is absent,
// where a v2-keyed login fails and a v1 login passes; then the file is
// written; then within, a v2 login passes; and port49d was not restarted and
// has seen no key file change. mint gives a fresh token for each login.
func RotateCell(t *testing.T, d Device, user string, mint func() string, metricsAddr string, within time.Duration, r Rotator) {
	t.Helper()
	started := r.StartedAt()
	next, err := WithAcceptV2(r.BasePolicy(), r.KeyDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := r.WritePolicy(next); err != nil {
		t.Fatalf("writing the policy with version 2 named: %v", err)
	}
	v2, err := testpki.RandomSecret(32)
	if err != nil {
		t.Fatal(err)
	}
	dv2 := Device{T: t, Addr: d.Addr, Key: []byte(v2)}
	// The policy is read at its watch interval; version 2's file is not
	// there, so the key set cannot open a v2-keyed body and the login fails
	// whether or not the policy has been read yet.
	// A key miss is a strike: the source's next connections are refused at
	// Accept for a backoff of at most limits.malformed_backoff_max (5s), and
	// a refused connection redeems nothing, so each phase mints once and
	// tries the same token until the answer is what the phase expects.
	tok := mint()
	if st, err := dv2.TryLogin(user, tok); err == nil && st == wire.AuthenStatusPass {
		t.Fatal("a login keyed with version 2 passed before its file existed")
	}
	tok = mint()
	// The v1 login waits the backoff (5 s at most) and the watch interval, not
	// within: a version 1 login that is not back in 15 s is a failure.
	WaitFor(t, "a login keyed with version 1, after the policy names version 2 and the key miss backoff", v1Back, func() bool {
		st, err := d.TryLogin(user, tok)
		return err == nil && st == wire.AuthenStatusPass
	})
	if err := r.WriteKey("tacacs_v2", []byte(v2)); err != nil {
		t.Fatalf("writing the version 2 key file: %v", err)
	}
	tok = mint()
	WaitFor(t, "a login keyed with version 2", within, func() bool {
		st, err := dv2.TryLogin(user, tok)
		return err == nil && st == wire.AuthenStatusPass
	})
	if got := r.StartedAt(); got != started {
		t.Fatalf("port49d restarted during the key rotation: started %s, then %s", started, got)
	}
	if g := Gauge(t, metricsAddr, "port49_key_secret_files_changed"); g != 0 {
		t.Fatalf("port49_key_secret_files_changed is %v after the rotation, want 0: a new version is a new file", g)
	}
}

// Filtered is text as tests/qual/secret-filter.sh leaves it, for a failure message that must say what
// a command printed without a chance of printing a secret. root is the repository root. Each line goes
// through the filter alone: one it drops becomes "<line withheld: N bytes>", so the message never
// shows less than the output had lines (the length of a withheld line is shown, which is acceptable),
// and only the last 400 lines are filtered. If the filter cannot run, it says so and prints nothing of text.
func Filtered(root, text string) string {
	var out []string
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if len(lines) > 400 {
		lines = lines[len(lines)-400:]
	}
	for _, ln := range lines {
		cmd := exec.Command("bash", filepath.Join(root, "tests", "qual", "secret-filter.sh"))
		cmd.Stdin = strings.NewReader(ln + "\n")
		b, err := cmd.Output()
		switch {
		case err != nil:
			return "(output withheld: the secret filter did not run)"
		case strings.TrimSpace(string(b)) == "" && strings.TrimSpace(ln) != "":
			out = append(out, fmt.Sprintf("<line withheld: %d bytes>", len(ln)))
		default:
			out = append(out, strings.TrimRight(string(b), "\n"))
		}
	}
	return strings.Join(out, "\n") + "\n"
}
