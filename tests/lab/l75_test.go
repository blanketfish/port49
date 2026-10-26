//go:build lab

package lab

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/oidc/oidctest"
	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/internal/totp"
)

const l75Claim = "spec §15 L75, cell by cell (decision 51: unlocks, TOTP fail-closed, membership's pin, " +
	"back-channel logouts across brokers; decision 47 ruling 5)."

// l75Device is the one device L75's brokers mint for.
const l75Device = "l75-device"

// l75Opts is one host broker's config.
type l75Opts struct {
	i                int
	dir              string // the run's directory
	x                *labDir
	pki              *regionPKI
	session          string   // its session member, host:port
	directory        []string // the directory's endpoints as it reaches them; nil: the members'
	usersCA          string   // the client CA file: carol's and bob's certificates
	issuer, issuerCA string   // (g)'s provider
	provider         bool     // (g): the oidc verifier in place of directory_password
}

// l75BrokerYAML is port49-broker.yaml for one host broker: L74's shape with
// L67's directory, an identity per l75Opts.provider, and stores whose
// directory is L74's (through o.directory when set). It names every secret by
// environment variable and holds none.
func l75BrokerYAML(o l75Opts) string {
	state := filepath.Join(o.dir, fmt.Sprintf("b%d-state", o.i))
	os.Mkdir(state, 0o700)
	human := `      - type: directory_password
        principal_domains: [corp.example.com]
        second_factor: totp
`
	if o.provider {
		human = fmt.Sprintf(`      - type: oidc
        issuer: %s
        client_id: port49-cli
        principal_claim: email
        principal_domains: [corp.example.com]
        ca_file: %s
`, o.issuer, o.issuerCA)
	}
	// A broker with an issuer takes a person's ID token only at
	// /v1/certificate, never as a mint bearer (decision 43, ruling 13); (g)
	// mints with the ID token, as decision 39 has it for a broker with none.
	issuance := "    issuance: {}\n"
	if o.provider {
		issuance = ""
	}
	stores := regionStoresYAML(o.pki, "broker", o.session)
	if o.directory != nil {
		var members []string
		for i := 1; i <= 3; i++ {
			members = append(members, "https://"+regionIP(i)+":2379")
		}
		var via []string
		for _, ep := range o.directory {
			via = append(via, "https://"+ep)
		}
		stores = strings.Replace(stores, strings.Join(members, ", "), strings.Join(via, ", "), 1)
	}
	return fmt.Sprintf(`metrics_listen: "127.0.0.1:0"
inventory_file: %[1]s/l75-inventory.yaml
key_refs: [k]
encryption:
  current: {id: l74, secret_ref: env:L74_ENC_KEY}
admin_socket: %[1]s/b%[2]d.sock
broker:
  listen: "127.0.0.1:0"
  tls_cert_file: %[3]s
  tls_key_file: %[4]s
  policy_file: %[1]s/l75-policy.yaml
  state_dir: %[5]s
  policy_watch_interval: 5s
  certificate_status: {disabled: true}
  identity:
    humans:
      - {type: x509, trust_anchor_file: %[6]s}
%[7]s%[16]s  directory:
    servers:
      - {uri: "ldaps://%[8]s", priority: 100, site: lab}
    site: lab
    ca_file: %[9]s
    bind:
      mechanism: simple
      bind_dn: "%[10]s"
      password_secret_ref: env:LAB_DIRECTORY_BIND_PASSWORD
    base_dn: "%[11]s"
    groups_base_dn: "%[12]s"
    user_filter: "%[13]s"
    group_filter: "%[14]s"
    principal_attribute: mail
    username_attribute: %[15]s
    certificate_mapping:
      kind: san_email
      allow_weak: true
      issuers: ["CN=L75 users CA"]
    nested_groups: direct
    grace: 4h
`, o.dir, o.i, filepath.Join(o.pki.lab, testpki.LabServerCert), filepath.Join(o.pki.lab, testpki.LabServerKey), state,
		o.usersCA, human, l67HostPort(o.x.uri), o.x.d.pki.caFile, o.x.bindDN, o.x.baseDN, o.x.groupsBaseDN,
		o.x.userFilter, o.x.groupFilter, o.x.usernameAttr, issuance) + stores
}

func l75Policy() string {
	return `scopes:
  - {name: all, match: {}}
roles:
  - {name: admin, privilege: admin, permit: ["**"]}
subjects:
  - {name: carol, identity: ["user:carol@corp.example.com"], token_ttl: 900s}
  - {name: bob, identity: ["user:bob@corp.example.com"], token_ttl: 900s}
grants:
  - {subject: carol, scope: all, roles: [admin]}
  - {subject: bob, scope: all, roles: [admin]}
key_groups:
  - {match: {cidr: 127.0.0.0/8}, key_ref: k}
`
}

// The judges of the cells that have a negative to show: each requires the
// positive control beside it, so a cell cannot agree for want of a working
// path. They are pure, so the unit tests can drive them.

// (a) the first sign-in passed, the same code at broker 2 was refused, and
// broker 2 takes a fresh code (it was able to say yes).
func l75JudgeA(first, replay, control int) bool {
	return first == http.StatusOK && replay == http.StatusUnauthorized && control == http.StatusOK
}

// (c) broker 2 locked (after lockedAt wrong codes), a valid code was refused
// 429 while locked, the unlock exited 0, and the next valid sign-in passed.
func l75JudgeC(lockedAt, whileLocked, unlockExit, after int) bool {
	return lockedAt > 0 && whileLocked == http.StatusTooManyRequests && unlockExit == 0 && after == http.StatusOK
}

// (d) with no unlock between, each broker took its own count: threshold
// failures, then the refusal on the next try (n = threshold+1). A count shared
// across brokers would refuse the second and third at once (n = 1).
func l75JudgeD(counts []int, threshold int) bool {
	if len(counts) == 0 {
		return false
	}
	for _, n := range counts {
		if n != threshold+1 {
			return false
		}
	}
	return true
}

// (e) the cut took (store status exit 3), the sign-in answered 503
// store_unavailable, unlock and reset were refused with the store's own words
// ("did not answer"), and the heal took.
func l75JudgeE(statusExit, signIn int, signInErr string, unlockExit int, unlockOut string, resetExit int, resetOut string,
	healed bool) bool {
	const said = "did not answer"
	return statusExit == 3 && signIn == http.StatusServiceUnavailable && signInErr == "store_unavailable" &&
		unlockExit != 0 && strings.Contains(unlockOut, said) && resetExit != 0 && strings.Contains(resetOut, said) && healed
}

// (g) the mint before the logout passed, the logout was accepted, the runner
// line naming it was said, and the mint was then refused as credential_revoked.
func l75JudgeG(before, logout int, why string, runnerLine bool) bool {
	return before == http.StatusOK && logout == http.StatusOK && why == "credential_revoked" && runnerLine
}

// l75RacedPair is whether two sign-ins with one code really raced: one won and
// the other was refused for the code. A 429 is a locked-out broker, not a race.
func l75RacedPair(a, b int) bool {
	return (a == http.StatusOK && b == http.StatusUnauthorized) || (a == http.StatusUnauthorized && b == http.StatusOK)
}

// l75SameStep is whether two instants fall in one TOTP step.
func l75SameStep(a, b time.Time) bool {
	step := int64(totp.Period / time.Second)
	return a.Unix()/step == b.Unix()/step
}

// l75Broker is one host broker: its session member, its process, and for
// b3 the proxies that are its way to the directory.
type l75Broker struct {
	o       l75Opts
	cfg     string
	sess    *regionEtcd
	proc    *regionProc
	proxies []*etcdtest.Proxy
	// api and metrics are the addresses the broker said when its mints opened,
	// kept because proc.said() starts again at every mark.
	api, metrics string
}

// l75Listening is port49-broker's line once its API serves.
var l75Listening = regexp.MustCompile(`port49-broker: listening on (127\.0\.0\.1:\d+)`)

// l75Metrics is the line that names the broker's metrics address.
var l75Metrics = regexp.MustCompile(`metrics on (127\.0\.0\.1:\d+)`)

// l75Addrs are the API and metrics addresses the last of a log's lines name,
// "" for one it does not.
func l75Addrs(log string) (api, metrics string) {
	if m := l75Listening.FindAllStringSubmatch(log, -1); m != nil {
		api = m[len(m)-1][1]
	}
	if m := l75Metrics.FindAllStringSubmatch(log, -1); m != nil {
		metrics = m[len(m)-1][1]
	}
	return api, metrics
}

// addr is the API address the broker said at its last start(). It is not
// read from proc.said(), which restarts at every mark.
func (b *l75Broker) addr() string { return b.api }

func (b *l75Broker) sock() string { return filepath.Join(b.o.dir, fmt.Sprintf("b%d.sock", b.o.i)) }

// hang cuts b3 from the directory (or heals it) and answers whether the
// broker's own `port49 store status` then says so (exit 3 cut, exit 0 healed)
// within the bound: the cut is judged by what the broker reports, not by the
// proxy's say-so.
func (b *l75Broker) hang(w *regionWorld, on bool) bool {
	for _, p := range b.proxies {
		p.Hang(on)
	}
	want, bound := 0, 90*time.Second
	if on {
		want, bound = 3, 30*time.Second
	}
	for deadline := time.Now().Add(bound); ; time.Sleep(time.Second) {
		if _, code, _ := w.port49("store", "status", "--socket", b.sock()); code == want {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
	}
}

// l75TookOver waits up to d for the broker's runner to hold the keyspace and
// record its bundle as judged: the takeover is done, so a logout after it
// takes the follow path.
func l75TookOver(p *regionProc, d time.Duration) error {
	start := time.Now()
	for _, want := range []string{"runner: took keyspace", "runner: recorded bundle"} {
		if _, err := p.wait(want, d-time.Since(start)); err != nil {
			return fmt.Errorf("%s: its takeover did not finish, a port49 finding if the keyspace was free: %w", p.name, err)
		}
	}
	return nil
}

// l75RunnerLines are the lines (g) accepts of a runner that reached a logout:
// the follow path's only. After the takeover wait the logout arrives to a
// running runner, so the takeover's "standing logout(s) reached here" would
// mean the follow path was not what was measured.
var l75RunnerLines = []struct{ say, via string }{
	{"a logout made elsewhere", "followed (a logout made elsewhere)"},
}

// l75RunnerLine waits up to d for the broker's runner to say it reached the
// logout by the follow path, and returns how long it took and the line named.
func l75RunnerLine(p *regionProc, d time.Duration) (time.Duration, string, error) {
	start := time.Now()
	for {
		said := p.said()
		for _, l := range l75RunnerLines {
			if strings.Contains(said, l.say) {
				return time.Since(start), l.via, nil
			}
		}
		if time.Since(start) > d {
			return d, "", fmt.Errorf("%s did not say it reached the logout within %v", p.name, d)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// l75NotAnswering waits up to d for the broker to say its directory store does
// not answer (since the last mark, so mark before the cut): the mint path, a
// forget and a logout follow that check (Freshness.Reachable, set by
// keepFresh up to a check and a call timeout after the cut), not store status,
// which pings live and says "cut" before it.
func l75NotAnswering(p *regionProc, d time.Duration) error {
	if _, err := p.wait("directory store: not answering", d); err != nil {
		return fmt.Errorf("%s: the broker never said its directory store stopped answering after the cut: %w", p.name, err)
	}
	return nil
}

// l75AnsweringAgain waits up to d for the broker to say its directory store
// answers again (since the last mark): mints follow that check, not store
// status, which pings live.
func l75AnsweringAgain(p *regionProc, d time.Duration) error {
	if _, err := p.wait("directory store: answering again", d); err != nil {
		return fmt.Errorf("%s: a port49 finding if the heal held and store status said reachable: %w", p.name, err)
	}
	return nil
}

// l75Poll calls read every `every` until done accepts what it returned, or d
// passes, and returns the last read, how long it took, and whether done
// accepted it.
func l75Poll(read func() string, done func(string) bool, d, every time.Duration) (string, time.Duration, bool) {
	start := time.Now()
	for {
		got := read()
		if done(got) {
			return got, time.Since(start), true
		}
		if time.Since(start) >= d {
			return got, time.Since(start), false
		}
		time.Sleep(every)
	}
}

// scrape is the broker's metrics page, "" when it does not answer.
func (b *l75Broker) scrape() string {
	resp, err := http.Get("http://" + b.metrics + "/metrics")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return string(raw)
}

// l75EnrollmentStoreSeen waits up to d for every broker in bs to read
// port49_directory_enrollment_store_ok 1: a broker that started before
// init-enrollments caches the store as lost and looks again every 30s
// (decision 47, D7), so (a) waits for the others rather than measuring that.
func l75EnrollmentStoreSeen(bs []*l75Broker, d time.Duration) (time.Duration, error) {
	start := time.Now()
	for _, b := range bs {
		_, _, ok := l75Poll(b.scrape, func(m string) bool {
			return metricOf(m, "port49_directory_enrollment_store_ok") == 1
		}, d, time.Second)
		if !ok {
			return time.Since(start), fmt.Errorf("%s did not read port49_directory_enrollment_store_ok 1 within %v, "+
				"past D7's 30s recheck: a port49 finding if the store was initialised", b.proc.name, d)
		}
	}
	return time.Since(start), nil
}

// l75OnePending is whether a store status says exactly one logout pending:
// "11 logouts pending" is not "1 logouts pending".
func l75OnePending(status string) bool {
	return regexp.MustCompile(`(^|[^0-9])1 logouts pending`).MatchString(status)
}

// start writes the config, starts the broker and waits until its mints are open.
func (b *l75Broker) start(w *regionWorld) {
	t := w.t
	t.Helper()
	if err := os.WriteFile(b.cfg, []byte(l75BrokerYAML(b.o)), 0o600); err != nil {
		t.Fatal(err)
	}
	b.proc.start(t)
	for deadline := time.Now().Add(120 * time.Second); !l67MintsOpen(b.proc.said()); time.Sleep(500 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("INVALID: %s's mints did not open within 120s: %s", b.proc.name, w.leakless(lastLine(b.proc.said())))
		}
	}
	b.api, b.metrics = l75Addrs(b.proc.said())
	if b.api == "" {
		t.Fatalf("INVALID: %s opened its mints but said no API address", b.proc.name)
	}
}

// l75Client is an HTTP client trusting the lab API's CA, with cert when given.
func l75Client(pki *regionPKI, cert *tls.Certificate) *http.Client {
	caPEM, err := os.ReadFile(filepath.Join(pki.lab, testpki.LabCA))
	if err != nil {
		panic(fmt.Sprintf("INVALID: the lab API's CA: %v", err)) // every mint would read as "unreachable"
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	tc := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}
	if cert != nil {
		tc.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: tc}}
}

// l75Mint is one mint at addr for l75Device, by the client's certificate or
// by bearer, and its status and error code; a token it returns is held.
func l75Mint(w *regionWorld, c *http.Client, addr, bearer string) (int, string) {
	req, err := http.NewRequest(http.MethodPost, "https://"+addr+"/v1/tokens",
		strings.NewReader(`{"devices":["`+l75Device+`"]}`))
	if err != nil {
		return 0, "request"
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, "unreachable"
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusOK {
		var out api.MintResponse
		if json.Unmarshal(raw, &out) == nil {
			for _, r := range out.Results {
				if r.Login != "" {
					w.hold(r.Login)
				}
			}
		}
		return resp.StatusCode, ""
	}
	var e api.Error
	_ = json.Unmarshal(raw, &e)
	return resp.StatusCode, e.Error
}

// l75LogoutClaims is a back-channel logout token's claims for session sid.
func l75LogoutClaims(iss, client, sid, jti string, now time.Time) map[string]any {
	return map[string]any{"iss": iss, "aud": client, "iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(),
		"jti": jti, "sid": sid, "events": map[string]any{oidc.BackchannelLogoutEvent: map[string]any{}}}
}

// l75Logout posts a logout token to addr's /v1/logout, form-encoded with
// no client certificate, as a provider does, and returns the status.
func l75Logout(c *http.Client, addr, token string) int {
	resp, err := c.Post("https://"+addr+"/v1/logout", "application/x-www-form-urlencoded",
		strings.NewReader(url.Values{"logout_token": {token}}.Encode()))
	if err != nil {
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}

func l75Random(t *testing.T) string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// l75 runs L75's cells on three host brokers sharing w's directory, writes its
// note, and answers the cells that disagree with the claim (the caller fails
// the test on them, after L74's note is also written).
func l75(t *testing.T, w *regionWorld) []string {
	pw, err := l67Password()
	if err != nil {
		t.Fatal(err)
	}
	w.hold(pw)
	sec := &l67Secrets{}
	w.leaks = append(w.leaks, sec.leaksIn)
	d := startDirectoriesWith(t, l67Prepare(pw))
	w.hold(d.password)
	// The brokers' environment: the bind password and the encryption key, in
	// the 0600 file the wrapper sources, never on an argv.
	envFile := filepath.Join(w.dir, "l75.env")
	if err := writeEnvFile(envFile, [2]string{"L74_ENC_KEY", w.encKey},
		[2]string{"LAB_DIRECTORY_BIND_PASSWORD", d.password}); err != nil {
		t.Fatalf("INVALID: writing L75's key file: %v", err)
	}

	// The client CA: carol's and bob's certificates, never written but the CA's file.
	now := time.Now()
	users, err := testpki.NewCA("L75 users CA", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	usersCA := filepath.Join(w.dir, "l75-users-ca.pem")
	if err := os.WriteFile(usersCA, users.PEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	certOf := func(name string) *tls.Certificate {
		c, err := users.Issue(testpki.Leaf{CommonName: name, Emails: []string{name + "@corp.example.com"}, Client: true,
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		return &c
	}
	carolCert, bobCert := certOf("carol"), certOf("bob")
	iss := oidctest.NewIssuer(t)
	issCA := filepath.Join(w.dir, "l75-issuer-ca.pem")
	if err := os.WriteFile(issCA, iss.CertPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"l75-policy.yaml": l75Policy(),
		"l75-inventory.yaml": "devices:\n  - {name: " + l75Device + ", platform: arista_eos, addresses: [127.0.0.1]}\n"} {
		if err := os.WriteFile(filepath.Join(w.dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cmdEnv := append(os.Environ(), "L74_ENC_KEY="+w.encKey, "LAB_DIRECTORY_BIND_PASSWORD="+d.password)

	var bs [4]*l75Broker
	for i := 1; i <= 3; i++ {
		client, peer := freeAddr(t), freeAddr(t)
		s := &regionEtcd{name: fmt.Sprintf("l75s%d", i), bin: w.etcdBin, client: client, peer: peer,
			cluster: fmt.Sprintf("l75s%d=http://%s", i, peer), data: filepath.Join(w.dir, fmt.Sprintf("l75s%d.etcd", i)),
			log: filepath.Join(w.dir, fmt.Sprintf("l75s%d.log", i)), pki: w.pki}
		s.start(t)
		o := l75Opts{i: i, dir: w.dir, x: d.openldap, pki: w.pki, session: client, usersCA: usersCA,
			issuer: iss.URL, issuerCA: issCA}
		b := &l75Broker{o: o, cfg: filepath.Join(w.dir, fmt.Sprintf("b%d.yaml", i)), sess: s}
		if i == 3 {
			for m := 1; m <= 3; m++ {
				p := etcdtest.NewProxy(t, regionIP(m)+":2379")
				b.proxies = append(b.proxies, p)
				b.o.directory = append(b.o.directory, p.Addr())
			}
			// However the run ends, the proxies forward again.
			t.Cleanup(func() {
				for _, p := range b.proxies {
					p.Hang(false)
				}
			})
		}
		b.proc = &regionProc{name: fmt.Sprintf("port49-broker l75 b%d", i), bin: w.broker, cfg: b.cfg,
			log: filepath.Join(w.dir, fmt.Sprintf("l75-b%d.log", i)), envFile: envFile}
		bs[i] = b
	}
	for i := 1; i <= 3; i++ {
		for deadline := time.Now().Add(60 * time.Second); ; time.Sleep(500 * time.Millisecond) {
			if _, err := bs[i].sess.ctl("https://"+bs[i].sess.client, "endpoint", "health"); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("INVALID: L75's session member %d did not answer within 60s", i)
			}
		}
		// Roles for the session member alone: the directory's were made by L74.
		if err := os.WriteFile(bs[i].cfg, []byte(l75BrokerYAML(bs[i].o)), 0o600); err != nil {
			t.Fatal(err)
		}
		stub := filepath.Join(w.dir, fmt.Sprintf("b%d-port49d.yaml", i))
		if err := os.WriteFile(stub, []byte(strings.Replace(w.daemonYAML(1), regionSessionClient, bs[i].sess.client, 1)),
			0o600); err != nil {
			t.Fatal(err)
		}
		sr := exec.Command(w.port49d, "store-roles", "--config", stub, "--broker-config", bs[i].cfg)
		sr.Env = append(cmdEnv, "L74_TACACS_KEY="+w.tacacsKey)
		out, err := sr.CombinedOutput()
		if err != nil {
			t.Fatalf("INVALID: port49d store-roles for L75 b%d: %v\n%s", i, err, w.leakless(string(out)))
		}
		s := bs[i].sess
		applyRoles(t, string(out), map[string]func(args ...string) (string, error){
			"session": func(args ...string) (string, error) { return s.ctl("https://"+s.client, args...) }})
		cmd := exec.Command(w.broker, "init-issuer", "--config", bs[i].cfg)
		cmd.Env = cmdEnv
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("INVALID: port49-broker init-issuer for b%d: %v: %s", i, err, w.leakless(oneLineMax(string(out), 400)))
		}
		bs[i].start(w)
		t.Cleanup(bs[i].proc.stop)
	}
	if out, code, _ := w.port49("directory", "init-enrollments", "--socket", bs[1].sock()); code != 0 {
		t.Fatalf("INVALID: init-enrollments: exit %d: %s", code, w.leakless(oneLineMax(out, 300)))
	}
	// Brokers 2 and 3 started before init-enrollments: they take the new store
	// up within 30s, and (a) must not run before they have.
	storeSeen, err := l75EnrollmentStoreSeen(bs[2:], 45*time.Second)
	if err != nil {
		t.Fatalf("INVALID: %v", err)
	}
	apiOf := func(b *l75Broker) *l67API {
		a, err := newL67API("https://"+b.addr(), filepath.Join(w.pki.lab, testpki.LabCA))
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	unlock := func(at *l75Broker) (string, int, time.Duration) {
		return w.port49("directory", "unlock", "--socket", at.sock(), "user:carol@corp.example.com")
	}
	mustUnlock := func(at *l75Broker) {
		if out, code, _ := unlock(at); code != 0 {
			t.Fatalf("INVALID: unlocking carol at b%d: exit %d: %s", at.o.i, code, w.leakless(oneLineMax(out, 300)))
		}
	}

	// Carol enrolls at b1: a sign-in with no code answers 202 and the
	// secret, and her first code confirms it (L67's flow).
	a1 := apiOf(bs[1])
	ans := a1.signIn("carol", pw, "")
	if ans.Status != http.StatusAccepted || ans.Enroll == nil {
		t.Fatalf("INVALID: enrolling carol at b1: %d %s", ans.Status, ans.Error)
	}
	secret, err := l67SecretOf(ans.Enroll.URI)
	if err != nil {
		t.Fatalf("INVALID: %v", err)
	}
	sec.addSecret(secret)
	carol := &l67Person{name: "carol", secret: secret, rec: sec}
	if conf := a1.confirm(ans.Enroll.Handle, carol.code()); conf.Status != http.StatusOK {
		t.Fatalf("INVALID: confirming carol's enrollment: %d %s", conf.Status, conf.Error)
	}
	mustUnlock(bs[1])

	var rows []regionRow
	row := func(id, claim, observed string, agrees bool) {
		rows = append(rows, regionRow{ID: id, Claim: claim, Observed: observed, Agrees: agrees})
	}

	// (a) one code at b1, then the same code at b2; then a fresh code at b2.
	w.guard()
	code := carol.code()
	r1 := a1.signIn("carol", pw, code)
	r2 := apiOf(bs[2]).signIn("carol", pw, code)
	rc := apiOf(bs[2]).signIn("carol", pw, carol.code())
	row("a", "a code signed in at broker 1 is refused at broker 2 within its step (broker 2 takes a fresh code)",
		fmt.Sprintf("broker 1: %d; broker 2, the same code: %d %s; broker 2, a fresh code: %d; brokers 2 and 3 read the "+
			"enrollment store as ok %v after init-enrollments (D7: within 30s)", r1.Status, r2.Status, r2.Error,
			rc.Status, storeSeen.Round(100*time.Millisecond)), l75JudgeA(r1.Status, r2.Status, rc.Status))

	// (b) twenty steps: one code to b1 and b2 at once. The loser of a race is
	// a failed attempt, so b1 is unlocked after every pair: each pair then runs
	// the race on a broker that is not locked out. A pair counts only as a race
	// when both requests left in one step and exactly one won.
	w.guard()
	ap1, ap2 := apiOf(bs[1]), apiOf(bs[2])
	raced := 0
	var pairs []string
	for n := 0; n < 20; n++ {
		code := carol.code()
		var s1, s2 l67Answer
		var t1, t2 time.Time
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); t1 = time.Now(); s1 = ap1.signIn("carol", pw, code) }()
		go func() { defer wg.Done(); t2 = time.Now(); s2 = ap2.signIn("carol", pw, code) }()
		wg.Wait()
		if l75RacedPair(s1.Status, s2.Status) && l75SameStep(t1, t2) {
			raced++
		}
		pairs = append(pairs, fmt.Sprintf("%d/%d", s1.Status, s2.Status))
		mustUnlock(bs[1])
	}
	row("b", "one code sent to brokers 1 and 2 at once, twenty steps: pairs with exactly one 200 (the other refused for the code); broker 1 is unlocked after each pair, so no pair runs on a locked-out broker",
		fmt.Sprintf("%d of 20: %s", raced, strings.Join(pairs, " ")), raced == 20)

	// (c) locked out at b2 by wrong codes, a valid code refused while locked,
	// unlocked at b1, judged afresh at b2.
	w.guard()
	wrongs := func(b *l75Broker) int {
		for n := 1; n <= 20; n++ {
			c, err := l67WrongCode(carol.secret, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			sec.addCode(c)
			if apiOf(b).signIn("carol", pw, c).Status == http.StatusTooManyRequests {
				return n
			}
		}
		return -1
	}
	lockedAt := wrongs(bs[2])
	whileLocked := apiOf(bs[2]).signIn("carol", pw, carol.code())
	_, ucode, _ := unlock(bs[1])
	c3 := apiOf(bs[2]).signIn("carol", pw, carol.code())
	row("c", "locked out at broker 2, unlocked at broker 1: broker 2's next sign-in is judged",
		fmt.Sprintf("broker 2 refused after %d wrong code(s); a valid code while locked: %d; unlock at broker 1 exit %d; "+
			"broker 2's next sign-in %d", lockedAt, whileLocked.Status, ucode, c3.Status),
		l75JudgeC(lockedAt, whileLocked.Status, ucode, c3.Status))

	// (d) the counts are per broker: unlocked once, then b1, b2 and b3 are each
	// locked out in turn with no unlock between. Each takes its own threshold of
	// failures; a count shared across brokers would refuse b2 and b3 at once.
	w.guard()
	mustUnlock(bs[1])
	var counts []string
	var ns []int
	sum := 0
	for i := 1; i <= 3; i++ {
		n := wrongs(bs[i])
		ns = append(ns, n)
		counts = append(counts, fmt.Sprintf("broker %d: refused at try %d", i, n))
		sum += max(n-1, 0)
	}
	row("d", "the attempt counts are per broker: failures each takes before it refuses, and the total across three",
		fmt.Sprintf("%s; %d failures in all (threshold %d each)", strings.Join(counts, ", "), sum,
			oidc.DefaultFailuresPerPrincipal), l75JudgeD(ns, oidc.DefaultFailuresPerPrincipal))
	mustUnlock(bs[1])

	// (e) b3 cut from the directory: a password sign-in, an unlock and a
	// reset are each refused, promptly. The controls: b3 takes a code and an
	// unlock before the cut, and heals after it.
	w.guard()
	if pc := apiOf(bs[3]).signIn("carol", pw, carol.code()); pc.Status != http.StatusOK {
		t.Fatalf("INVALID: b3's sign-in before its cut: %d %s", pc.Status, pc.Error)
	}
	mustUnlock(bs[3])
	// Bob signs in by certificate alone and has no second factor, so resetting
	// his is harmless (it only opens an enrollment window): the control that
	// reset-second-factor works at b3 before the cut.
	if out, code, _ := w.port49("directory", "reset-second-factor", "--socket", bs[3].sock(),
		"user:bob@corp.example.com"); code != 0 {
		t.Fatalf("INVALID: reset-second-factor of bob at b3 before its cut: exit %d: %s", code, w.leakless(oneLineMax(out, 300)))
	}
	bs[3].proc.mark()
	if !bs[3].hang(w, true) {
		t.Fatal("INVALID: b3's store status never said the directory was cut")
	}
	if err := l75NotAnswering(bs[3].proc, 30*time.Second); err != nil {
		t.Fatalf("INVALID: %v", err)
	}
	// The clock starts with the code in hand: the wait for the step is not b3's.
	code3 := carol.code()
	start := time.Now()
	e1 := apiOf(bs[3]).signIn("carol", pw, code3)
	t1 := time.Since(start)
	o2, c2, t2 := unlock(bs[3])
	o3, c3e, t3 := w.port49("directory", "reset-second-factor", "--socket", bs[3].sock(), "user:bob@corp.example.com")
	healed := bs[3].hang(w, false)
	if !healed {
		t.Fatal("INVALID: b3 did not reach the directory again within 90s of the heal")
	}
	row("e", "broker 3 cut from the directory: a password sign-in 503 store_unavailable; unlock and "+
		"reset-second-factor refused; how long each took",
		fmt.Sprintf("store status exit 3 under the cut; sign-in %d %s in %v; unlock exit %d in %v: %s; reset exit %d in %v: %s; healed %v",
			e1.Status, e1.Error, t1.Round(time.Millisecond), c2, t2.Round(time.Millisecond), firstLine(o2), c3e,
			t3.Round(time.Millisecond), firstLine(o3), healed),
		l75JudgeE(3, e1.Status, e1.Error, c2, o2, c3e, o3, healed))

	// (f) membership's pin across brokers (R13).
	w.guard()
	d1 := w.dirMembers[1]
	pinKey := "/port49/v1/mb/user:carol@corp.example.com" // esc() is url.PathEscape, which keeps : and @
	pinRev := func() int64 {
		js, err := d1.ctl(w.dirEndpoints(), "get", pinKey, "-w", "json")
		if err != nil {
			w.t.Fatalf("INVALID: reading carol's pin from the directory: %v", err)
		}
		var r struct {
			Kvs []struct {
				ModRevision int64 `json:"mod_revision"`
			} `json:"kvs"`
		}
		if json.Unmarshal([]byte(js), &r) != nil || len(r.Kvs) == 0 {
			return 0
		}
		return r.Kvs[0].ModRevision
	}
	carolC, bobC := l75Client(w.pki, carolCert), l75Client(w.pki, bobCert)
	m1, _ := l75Mint(w, carolC, bs[2].addr(), "")
	rev1 := pinRev()
	// b3 mints for carol while the directory answers: its session store holds
	// her membership with the pin as it stands (the cached pin the cut serves).
	if st, e := l75Mint(w, carolC, bs[3].addr(), ""); st != http.StatusOK {
		t.Fatalf("INVALID: carol's mint at b3 before the forget: %d %s", st, e)
	}
	_, fcode, _ := w.port49("directory", "forget", "--socket", bs[1].sock(), "user:carol@corp.example.com")
	// b2's next mint pins her again once its pins feed has delivered the forget:
	// mint until the pin's revision moves, or give up after 30s.
	m2, rev2 := 0, rev1
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(time.Second) {
		m2, _ = l75Mint(w, carolC, bs[2].addr(), "")
		if rev2 = pinRev(); rev2 > rev1 {
			break
		}
	}
	// And b3 reads the new pin the same way, before the cut.
	if st, e := l75Mint(w, carolC, bs[3].addr(), ""); st != http.StatusOK {
		t.Fatalf("INVALID: carol's mint at b3 after the re-pin: %d %s", st, e)
	}
	bs[3].proc.mark()
	if !bs[3].hang(w, true) {
		t.Fatal("INVALID: b3's store status never said the directory was cut")
	}
	// store status pings live and says "cut" up to one freshness check before
	// the copy knows: until then the forget waits out the call timeout and
	// carol's pin is served from the watch with no cached-membership line.
	if err := l75NotAnswering(bs[3].proc, 30*time.Second); err != nil {
		t.Fatalf("INVALID: %v", err)
	}
	_, f3, ft3 := w.port49("directory", "forget", "--socket", bs[3].sock(), "user:carol@corp.example.com")
	m3, _ := l75Mint(w, carolC, bs[3].addr(), "")
	cached := strings.Contains(bs[3].proc.said(), "serving user:carol@corp.example.com's cached directory membership")
	mb, mbErr := l75Mint(w, bobC, bs[3].addr(), "")
	if !bs[3].hang(w, false) {
		t.Fatal("INVALID: b3 did not reach the directory again within 90s of the heal")
	}
	// store status pings live and says "reachable" up to one freshness check
	// before mints reopen, so the control waits for the broker's own line.
	if err := l75AnsweringAgain(bs[3].proc, 30*time.Second); err != nil {
		t.Fatalf("INVALID: %v", err)
	}
	// The control for bob's refusal: after the heal he is a member b3 mints for.
	mbAfter, _ := l75Mint(w, bobC, bs[3].addr(), "")
	row("f", "membership's pin: written once in the directory; a forget at broker 1 re-pins at broker 2's next "+
		"mint; with broker 3 cut, a forget there refused, a pinned member served from the cached pin and said, "+
		"a first bind refused (and served after the heal)",
		fmt.Sprintf("mint at b2 %d, pin revision %d; forget at b1 exit %d; next mint at b2 %d, pin revision %d; cut: "+
			"forget at b3 exit %d in %v; carol's mint at b3 %d (said %v); bob's first mint at b3 %d %s; bob's mint at b3 after the heal %d",
			m1, rev1, fcode, m2, rev2, f3, ft3.Round(time.Millisecond), m3, cached, mb, mbErr, mbAfter),
		m1 == http.StatusOK && rev1 > 0 && fcode == 0 && m2 == http.StatusOK && rev2 > rev1 && f3 != 0 &&
			m3 == http.StatusOK && cached && mb != http.StatusOK && mbAfter == http.StatusOK)

	// (g) back-channel logouts across brokers (R26), with the provider identity.
	w.guard()
	for i := 1; i <= 3; i++ {
		bs[i].proc.stop()
		bs[i].o.provider = true
		bs[i].start(w)
	}
	// A restarted broker serves mints before its runner holds the keyspace; a
	// logout that arrives in that gap is reached by the takeover, with its own
	// line, not by the follow path (g) measures. Wait for each takeover.
	for i := 1; i <= 3; i++ {
		if err := l75TookOver(bs[i].proc, 60*time.Second); err != nil {
			t.Fatalf("INVALID: %v", err)
		}
	}
	plain := l75Client(w.pki, nil)
	idToken := func(sid string) string {
		tok := iss.IDToken(t, "k1", "port49-cli", "sub-carol", time.Now(),
			map[string]any{"email": "carol@corp.example.com", "email_verified": true, "sid": sid})
		w.hold(tok)
		return tok
	}
	logoutToken := func(sid string) string {
		tok := iss.TokenWith(t, "k1", map[string]any{"kid": "k1", "typ": "logout+jwt"},
			l75LogoutClaims(iss.URL, "port49-cli", sid, l75Random(t), time.Now()))
		w.hold(tok)
		return tok
	}
	refusedWithin := func(b *l75Broker, tok string, d time.Duration) (time.Duration, string) {
		start := time.Now()
		for time.Since(start) < d {
			if st, e := l75Mint(w, plain, b.addr(), tok); st == http.StatusUnauthorized {
				return time.Since(start), e
			}
			time.Sleep(200 * time.Millisecond)
		}
		return d, "not refused"
	}
	s1 := "l75-g-" + l75Random(t)
	tok1 := idToken(s1)
	g1, _ := l75Mint(w, plain, bs[2].addr(), tok1)
	bs[2].proc.mark()
	lo1 := l75Logout(plain, bs[1].addr(), logoutToken(s1))
	took, why := refusedWithin(bs[2], tok1, 30*time.Second)
	line, via, lerr := l75RunnerLine(bs[2].proc, 30*time.Second)
	row("g", "a logout received at broker 1 refuses broker 2's mint for that session",
		fmt.Sprintf("mint at b2 %d; logout at b1 %d; b2 refused after %v (%s); b2's runner line after %v (%v): %s",
			g1, lo1, took.Round(10*time.Millisecond), why, line.Round(10*time.Millisecond), lerr == nil, via),
		l75JudgeG(g1, lo1, why, lerr == nil))

	w.guard()
	s2 := "l75-g-" + l75Random(t)
	tok2 := idToken(s2)
	g2, _ := l75Mint(w, plain, bs[1].addr(), tok2)
	bs[3].proc.mark()
	if !bs[3].hang(w, true) {
		t.Fatal("INVALID: b3's store status never said the directory was cut")
	}
	if err := l75NotAnswering(bs[3].proc, 30*time.Second); err != nil {
		t.Fatalf("INVALID: %v", err)
	}
	lo3 := l75Logout(plain, bs[3].addr(), logoutToken(s2))
	r3, why3 := l75Mint(w, plain, bs[3].addr(), tok2)
	// The pending count behind store status is refreshed every 5s, so a status
	// read at once can lag the logout it just took: poll for up to 10s.
	var scode int
	status, statusAfter, _ := l75Poll(func() string {
		out, code, _ := w.port49("store", "status", "--socket", bs[3].sock())
		scode = code
		return out
	}, l75OnePending, 10*time.Second, time.Second)
	b1st, _ := l75Mint(w, plain, bs[1].addr(), tok2)
	bs[3].proc.mark()
	healedAt := time.Now()
	if !bs[3].hang(w, false) {
		t.Fatal("INVALID: b3 did not reach the directory again within 90s of the heal")
	}
	_, ferr := bs[3].proc.wait("pending back-channel logout(s) forwarded", 30*time.Second)
	_, why2 := refusedWithin(bs[1], tok2, 30*time.Second)
	fromHeal := time.Since(healedAt)
	row("g2", "with broker 3 cut, a logout there is answered 200, refused there at once and pending; broker 1 "+
		"mints for it until the heal, then refuses",
		fmt.Sprintf("mint at b1 %d; logout at b3 %d; b3's mint %d %s; status (after %v) exit %d: %s; b1's mint during the cut %d; "+
			"forwarded line %v; b1 refused %v after the heal (%s)", g2, lo3, r3, why3, statusAfter.Round(100*time.Millisecond), scode,
			strings.ReplaceAll(status, "\n", " / "), b1st, ferr == nil, fromHeal.Round(10*time.Millisecond), why2),
		g2 == http.StatusOK && lo3 == http.StatusOK && r3 == http.StatusUnauthorized &&
			l75OnePending(status) && scode == 3 && b1st == http.StatusOK && ferr == nil &&
			why2 == "credential_revoked")

	var procs []*regionProc
	for i := 1; i <= 3; i++ {
		procs = append(procs, bs[i].proc)
	}
	sortRows(rows)
	writeRegionNote(t, w, "L75", l75Claim, rows, []string{
		"the brokers run on the host, not in the namespaces: OpenLDAP's ports are published on the host's loopback alone",
		"Keycloak's own sending of a logout, and that it does not retry a 503: L45's; (g) signs its logout tokens with an in-process provider",
	}, procs)
	return disagreeingCells(rows)
}
