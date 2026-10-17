//go:build lab

package lab

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/tests/lab/labcreds"
)

// l72Env is one port49d with both listeners, its PKI and its files, all
// under one temporary directory. Every secret it makes is random, held in
// memory, and registered for the leak check.
type l72Env struct {
	t           *testing.T
	dir         string
	bin         string // port49d
	clientBin   string // tacacs-tls-client
	tcpPort     int
	tlsPort     int
	metricsPort int
	secrets     []string
	daemon      *exec.Cmd
	logPath     string // the decision log (port49d's stdout)
	stderrPath  string
	cfgPath     string
	caFile      string
	certs       map[string][2]string // name -> cert file, key file
	seedFile    string
	env         []string // port49d's secret_env values
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// newL72Env makes the PKI, the files and the config, then starts port49d.
// crl is "file" (a CRL file listing the revoked leaf) or "unreachable" (a CRL
// URL nothing listens on, and no kept list).
func newL72Env(t *testing.T, crl string) *l72Env {
	t.Helper()
	e := l72Prepare(t, crl)
	e.build()
	e.start()
	return e
}

// l72Prepare writes everything port49d reads and the config that names it,
// without building or starting anything.
func l72Prepare(t *testing.T, crl string) *l72Env {
	t.Helper()
	e := &l72Env{t: t, dir: t.TempDir(), certs: map[string][2]string{}}
	e.bin = filepath.Join(e.dir, "port49d")
	e.clientBin = filepath.Join(e.dir, "tacacs-tls-client")
	e.logPath = filepath.Join(e.dir, "decisions.jsonl")
	e.stderrPath = filepath.Join(e.dir, "port49d.log")
	now := time.Now()
	ca, err := testpki.NewCA("L72 Device CA", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	other, err := testpki.NewCA("L72 Other CA", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	e.caFile = e.write("ca.pem", ca.PEM())
	issue := func(name string, from *testpki.CA, l testpki.Leaf) {
		if l.NotAfter.IsZero() {
			l.NotBefore, l.NotAfter = now.Add(-time.Minute), now.Add(time.Hour)
		}
		c, err := from.Issue(l)
		if err != nil {
			t.Fatal(err)
		}
		cp, kp, err := testpki.PEMs(c)
		if err != nil {
			t.Fatal(err)
		}
		e.certs[name] = [2]string{e.write(name+".crt", cp), e.write(name+".key", kp)}
	}
	issue("server", ca, testpki.Leaf{DNSNames: []string{"tacacs.l72.example"}, IPs: testpki.Loopback()})
	issue("good", ca, testpki.Leaf{DNSNames: []string{"tls-dev"}, Client: true})
	issue("other_ca", other, testpki.Leaf{DNSNames: []string{"tls-dev"}, Client: true})
	issue("expired", ca, testpki.Leaf{DNSNames: []string{"tls-dev"}, Client: true,
		NotBefore: now.Add(-2 * time.Hour), NotAfter: now.Add(-time.Hour)})
	issue("other_device", ca, testpki.Leaf{DNSNames: []string{"tls-other"}, Client: true})
	revokedSerial := big.NewInt(0x72)
	issue("revoked", ca, testpki.Leaf{DNSNames: []string{"tls-dev"}, Client: true, Serial: revokedSerial})
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1),
		ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: revokedSerial, RevocationTime: now.Add(-time.Minute)}}},
		ca.Cert, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	crlFile := e.write("l72.crl", crlDER)
	inv := e.write("inventory.yaml", []byte("devices:\n"+
		"  - {name: tls-dev, platform: arista_eos, addresses: [127.0.0.1], transport: tls}\n"+
		"  - {name: tcp-dev, platform: arista_eos, addresses: [127.0.0.2]}\n"+
		"key_groups:\n  - {match: {cidr: 127.0.0.2/32}, key_ref: l72}\n"))
	e.tcpPort, e.tlsPort, e.metricsPort = freePort(t), freePort(t), freePort(t)
	keyEnv, encEnv := randomHex(t, 16), randomHex(t, 16)
	e.secrets = append(e.secrets, keyEnv, encEnv)
	e.seedFile = filepath.Join(e.dir, "seeds.jsonl")
	status := "{crls: [{name: l72, file: " + crlFile + ", issuer_file: " + e.caFile + "}]}"
	if crl == "unreachable" {
		status = fmt.Sprintf("{crls: [{name: l72, url: \"http://127.0.0.1:%d/l72.crl\", issuer_file: %s}]}",
			freePort(t), e.caFile)
	}
	cfg := fmt.Sprintf(`listen: "127.0.0.1:%d"
metrics_listen: "127.0.0.1:%d"
inventory_file: %s
keys:
  l72:
    current: {version: 1, secret_env: L72_KEY}
encryption:
  current: {id: v1, secret_env: L72_ENC}
accounting: {spool_path: %s}
limits:
  # A strike's backoff and a decline's window start at 2s, so a cell's
  # second connection is inside it, and settle's 6s is past the 5s cap.
  malformed_backoff_base: 2s
session:
  # The lab's seeded contexts are judged by no broker, so nothing stamps
  # refreshed_at (port49d-lab.yaml says the same).
  staleness_ceiling: 0s
lab:
  session_attributes: ["priv-lvl=15"]
  seed_token_file: %s
  seed_tokens: [{nas: tls-dev, username: alice}]
tls_listener:
  listen: "127.0.0.1:%d"
  cert_file: %s
  key_file: %s
  client_ca_file: %s
  server_names: [tacacs.l72.example]
  handshake_timeout: 2s
  session_ticket_lifetime: 10m
  state_dir: %s
  certificate_status: %s
`, e.tcpPort, e.metricsPort, inv, filepath.Join(e.dir, "acct.jsonl"), e.seedFile, e.tlsPort, e.certs["server"][0],
		e.certs["server"][1], e.caFile, e.mkdir("state"), status)
	e.cfgPath = e.write("port49d.yaml", []byte(cfg))
	e.env = []string{"L72_KEY=" + keyEnv, "L72_ENC=" + encEnv}
	return e
}

// build compiles port49d and the reference client from the repository root.
func (e *l72Env) build() {
	e.t.Helper()
	for out, pkg := range map[string]string{e.bin: "./cmd/port49d", e.clientBin: "./tests/lab/cmd/tacacs-tls-client"} {
		cmd := exec.Command("go", "build", "-o", out, pkg)
		cmd.Dir = root
		if b, err := cmd.CombinedOutput(); err != nil {
			e.t.Fatalf("INVALID: build %s: %v\n%s", pkg, err, b)
		}
	}
}

// start runs port49d and waits for it to announce the RFC 9887 listener and
// write its seed tokens. Both of its streams go to files: the decision log is
// read while the daemon runs.
func (e *l72Env) start() {
	t := e.t
	t.Helper()
	logf, err := os.Create(e.logPath)
	if err != nil {
		t.Fatal(err)
	}
	errf, err := os.Create(e.stderrPath)
	if err != nil {
		t.Fatal(err)
	}
	e.daemon = exec.Command(e.bin, "-config", e.cfgPath)
	e.daemon.Env = append(os.Environ(), e.env...)
	e.daemon.Stdout, e.daemon.Stderr = logf, errf
	if err := e.daemon.Start(); err != nil {
		t.Fatalf("INVALID: start port49d: %v", err)
	}
	t.Cleanup(func() { e.stop(); logf.Close(); errf.Close() })
	deadline := time.Now().Add(20 * time.Second)
	for !strings.Contains(e.stderr(), "RFC 9887 listener on") {
		if time.Now().After(deadline) {
			t.Fatalf("INVALID: port49d did not start: %s", e.stderr())
		}
		time.Sleep(100 * time.Millisecond)
	}
	seeds, err := labcreds.SeedTokens(e.seedFile)
	if err != nil {
		t.Fatalf("INVALID: seeds: %v", err)
	}
	secrets, err := labcreds.SecretsOf(seeds)
	if err != nil {
		t.Fatal(err)
	}
	e.secrets = append(e.secrets, secrets...)
	// The token goes to a 0600 file the client reads; it is never printed.
	e.write("token", []byte(secrets[0]))
}

// stop kills the daemon once; the files it wrote stay readable.
func (e *l72Env) stop() {
	if e.daemon != nil && e.daemon.Process != nil {
		e.daemon.Process.Kill()
		e.daemon.Wait()
		e.daemon = nil
	}
}

func (e *l72Env) write(name string, b []byte) string {
	p := filepath.Join(e.dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		e.t.Fatal(err)
	}
	return p
}

func (e *l72Env) mkdir(name string) string {
	p := filepath.Join(e.dir, name)
	if err := os.MkdirAll(p, 0o700); err != nil {
		e.t.Fatal(err)
	}
	return p
}

func (e *l72Env) stderr() string {
	b, _ := os.ReadFile(e.stderrPath)
	return string(b)
}

func (e *l72Env) logBytes() []byte {
	b, _ := os.ReadFile(e.logPath)
	return b
}

// client runs tacacs-tls-client against port with args, as cert (a name in
// e.certs, or "" for none).
func (e *l72Env) client(port int, cert string, args ...string) []l72Result {
	e.t.Helper()
	base := []string{"-addr", fmt.Sprintf("127.0.0.1:%d", port), "-ca", e.caFile, "-server-name", "tacacs.l72.example",
		"-token-file", filepath.Join(e.dir, "token")}
	if cert != "" {
		base = append(base, "-cert", e.certs[cert][0], "-key", e.certs[cert][1])
	}
	// base first, args last: a later -server-name in args wins.
	out, err := exec.Command(e.clientBin, append(base, args...)...).Output()
	if err != nil {
		e.t.Fatalf("INVALID: tacacs-tls-client %v: %v", args, err)
	}
	rs, err := parseL72Result(out)
	if err != nil {
		e.t.Fatal(err)
	}
	return rs
}

// openssl runs openssl s_client against the TLS listener; stdin is sleep
// seconds of nothing, so the client reads what the server sends (a
// NewSessionTicket, an alert) before it quits.
func (e *l72Env) openssl(sleep int, args ...string) string {
	e.t.Helper()
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", fmt.Sprintf("sleep %d | openssl s_client -connect 127.0.0.1:%d %s 2>&1",
		sleep, e.tlsPort, strings.Join(quoted, " ")))
	out, _ := cmd.CombinedOutput() // s_client exits non-zero on a refused handshake: the transcript is the result
	return string(out)
}

// records is the decision log so far, one line each, matching sub.
func (e *l72Env) records(sub string) []string {
	var out []string
	for _, l := range strings.Split(string(e.logBytes()), "\n") {
		if strings.Contains(l, sub) {
			out = append(out, l)
		}
	}
	return out
}

// metric is the value of one exposition line, selector included
// (`port49_connection_events_total{event="declined_refused"}`); 0 when the
// series does not exist yet.
func (e *l72Env) metric(selector string) float64 {
	e.t.Helper()
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/metrics", e.metricsPort))
	if err != nil {
		e.t.Fatalf("INVALID: metrics: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, selector+" ") {
			v, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimPrefix(l, selector)), 64)
			if err != nil {
				e.t.Fatalf("INVALID: metric %s: %v", selector, err)
			}
			return v
		}
	}
	return 0
}

func connEvent(name string) string { return `port49_connection_events_total{event="` + name + `"}` }

func TestL72ReferenceClients(t *testing.T) {
	if err := labGuardAt(l66StopSentinel, "/", l66DiskFloorMB); err != nil {
		t.Fatal(err)
	}
	// L72 brings up no platform, so initGlobal never sets root: newL72Env
	// builds from it and l72Note writes under it (as L69 does, l69_test.go:1264).
	if root == "" {
		r, err := repoRoot()
		if err != nil {
			t.Fatalf("INVALID: repo root: %v", err)
		}
		root = r
		t.Cleanup(func() { root = "" })
	}
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Fatal("INVALID: no openssl on PATH")
	}
	osslVersion, _ := exec.Command("openssl", "version").Output()
	e := newL72Env(t, "file")
	var got []l72Obs
	cell := func(id string, ok bool, format string, args ...any) {
		if err := labGuardAt(l66StopSentinel, "/", l66DiskFloorMB); err != nil {
			t.Fatal(err)
		}
		got = append(got, l72Obs{id, fmt.Sprintf(format, args...), ok})
	}
	waitRec := func(sub string) []string {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if r := e.records(sub); len(r) > 0 {
				return r
			}
			time.Sleep(50 * time.Millisecond)
		}
		return nil
	}
	settle := func() { time.Sleep(6 * time.Second) } // past the default 5s malformed_backoff_max: each cell starts unstruck

	r := e.client(e.tlsPort, "good")
	red := waitRec(`"event":"redeem"`)
	cell("a", len(r) == 1 && r[0].Status == "pass" && r[0].Flags&1 == 1 && len(red) == 1 &&
		strings.Contains(red[0], `"transport":"tls"`) && strings.Contains(red[0], `"cert_sha256"`) && !strings.Contains(red[0], `"key_ref"`),
		"client: %+v; redeem record: %s", r, strings.Join(red, " "))

	for _, c := range []struct {
		id, cert, outcome string
		args              []string
	}{
		{"b", "good", "version_refused", []string{"-max-tls12"}},
		{"c", "", "no_client_certificate", nil},
		{"d", "other_ca", "unknown_ca", nil},
		{"e", "expired", "certificate_expired", nil},
		{"f", "other_device", "identity_mismatch", nil},
		{"g", "revoked", "certificate_revoked", nil},
		{"i", "good", "sni_mismatch", []string{"-server-name", "wrong.l72.example"}},
	} {
		settle()
		r := e.client(e.tlsPort, c.cert, c.args...)
		rec := waitRec(`"tls_outcome":"` + c.outcome + `"`)
		ossl := ""
		if c.id == "b" || c.id == "c" {
			settle() // the Go client's refusal struck 127.0.0.1; openssl starts unstruck
		}
		switch c.id {
		case "b":
			ossl = e.openssl(1, "-tls1_2", "-cert", e.certs["good"][0], "-key", e.certs["good"][1], "-CAfile", e.caFile)
		case "c":
			ossl = e.openssl(1, "-tls1_3", "-CAfile", e.caFile, "-servername", "tacacs.l72.example")
		}
		e.write("openssl-"+c.id+".txt", []byte(ossl))
		cell(c.id, len(rec) > 0 && len(r) == 1 && r[0].Status == "none",
			"client: %+v; record: %s; openssl (evidence/L72-reference/openssl-%s.txt): %s", r, strings.Join(rec, " "),
			c.id, l72AlertLine(ossl))
	}
	// -server-name wrong.l72.example also fails the client's own check of
	// port49's certificate; the server's refusal at the ClientHello comes first,
	// and the record says which.

	settle()
	r = e.client(e.tlsPort, "good", "-count", "3", "-replay")
	if len(r) != 3 {
		cell("j", false, "three connections were run; the client reported %d lines: %+v", len(r), r)
	} else {
		// The second connection resumes (and is judged again: its status is the
		// login's); the first ticket offered a second time is not resumed, so the
		// third connection is a full handshake that still completes.
		cell("j", !r[0].Resumed && r[1].Resumed && !r[2].Resumed && r[2].Handshake == "ok",
			"three connections offering the first ticket: resumed %v, %v, %v; handshakes %s %s %s; statuses %s %s %s",
			r[0].Resumed, r[1].Resumed, r[2].Resumed, r[0].Handshake, r[1].Handshake, r[2].Handshake,
			r[0].Status, r[1].Status, r[2].Status)
	}

	sess := filepath.Join(e.dir, "sess.pem")
	e.write("early.bin", []byte("early data"))
	first := e.openssl(2, "-tls1_3", "-cert", e.certs["good"][0], "-key", e.certs["good"][1], "-CAfile", e.caFile,
		"-servername", "tacacs.l72.example", "-sess_out", sess)
	second := e.openssl(2, "-tls1_3", "-cert", e.certs["good"][0], "-key", e.certs["good"][1], "-CAfile", e.caFile,
		"-servername", "tacacs.l72.example", "-sess_in", sess, "-early_data", filepath.Join(e.dir, "early.bin"))
	e.write("openssl-k.txt", []byte(first+"\n----\n"+second))
	// A port49 ticket carries no max_early_data_size, so s_client has nothing to
	// send early and says so. "Early data was rejected" would mean the ticket
	// permitted it, and an abort at the ClientHello (early_data_refused) that
	// the client sent it anyway: neither is the claim, and either is recorded
	// as observed. ruling 12's "a ticket never permits early data" is
	// unmeasured until this cell closes.
	aborted := e.records(`"tls_outcome":"early_data_refused"`)
	cell("k", strings.Contains(second, "Early data was not sent") && len(aborted) == 0,
		"openssl's second run says: %s; reused: %t; early_data_refused records: %d (evidence/L72-reference/openssl-k.txt)",
		l72EarlyLine(second), strings.Contains(second, "Reused, TLSv1.3"), len(aborted))

	settle()
	r = e.client(e.tlsPort, "good", "-obfuscated")
	rec := waitRec(`"diagnosis":"obfuscated_over_tls"`)
	// The peer's certificate verified, so the ERROR and the close are no strike
	// (ruling 13): the next connection, at once, reaches its handshake.
	next := e.client(e.tlsPort, "good")
	cell("l", len(r) == 1 && r[0].Status == "error" && r[0].Flags&1 == 1 && r[0].After == "eof" && len(rec) > 0 &&
		len(next) == 1 && next[0].Handshake == "ok" && e.metric(connEvent("held_refused")) == 0,
		"client: %+v; record: %s; the next connection at once: %+v; held_refused: %v", r, strings.Join(rec, " "), next,
		e.metric(connEvent("held_refused")))

	settle()
	tcpDev := e.client(e.tlsPort, "good", "-source", "127.0.0.2")
	unknown := e.client(e.tlsPort, "good", "-source", "127.0.0.3")
	mm, un := waitRec(`"diagnosis":"transport_mismatch"`), waitRec(`"diagnosis":"unadmitted_source"`)
	// No TLS byte comes back: a TLS alert would reach the client as "remote
	// error", and anything else crypto/tls says it read is a byte too.
	silentReset := func(r []l72Result) bool {
		return len(r) == 1 && r[0].Handshake == "error" && !strings.Contains(r[0].Error, "remote error") &&
			!strings.Contains(r[0].Error, "tls:")
	}
	cell("m", silentReset(tcpDev) && silentReset(unknown) && len(mm) > 0 && len(un) > 0,
		"tcp device: %+v; unknown address: %+v; records: %s | %s", tcpDev, unknown, strings.Join(mm, " "), strings.Join(un, " "))

	settle()
	before := len(e.records(`"diagnosis":"transport_mismatch"`))
	r = e.client(e.tcpPort, "", "-plain")
	time.Sleep(time.Second)
	after := e.records(`"diagnosis":"transport_mismatch"`)
	// Declined, not struck (decision 50 ruling 4): the window the decline opened
	// is dropped at the next Accept on the TLS listener, where the device is
	// admitted, so its login is not refused there.
	next = e.client(e.tlsPort, "good")
	cell("n", len(r) == 1 && r[0].After == "reset" && len(after) == before+1 &&
		len(next) == 1 && next[0].Handshake == "ok" && e.metric(connEvent("held_refused")) == 0,
		"client: %+v; the records: %s; the TLS login at once after: %+v; held_refused: %v", r, strings.Join(after, " "), next,
		e.metric(connEvent("held_refused")))

	settle()
	r = e.client(e.tlsPort, "", "-silent")
	rec = waitRec(`"tls_outcome":"handshake_timeout"`)
	cell("o", len(r) == 1 && r[0].ClosedMS >= 1800 && r[0].ClosedMS <= 4000 && len(rec) > 0,
		"client: %+v (handshake_timeout 2s); record: %s", r, strings.Join(rec, " "))

	// (h) needs its own port49d: a CRL source that cannot be fetched and no kept list.
	e.stop()
	h := newL72Env(t, "unreachable")
	rs := h.client(h.tlsPort, "good", "-count", "2") // the second at once, inside the 2s decline window
	time.Sleep(time.Second)
	recH := h.records(`"tls_outcome":"status_unavailable"`)
	// The first completes its handshake (the status is asked only after it)
	// and is then reset with no reply. The second is reset at Accept, before
	// any TLS byte, on the window status_unavailable keeps, and makes no
	// second record (decision 50 ruling 8). That is a decline, not a strike:
	// declined_refused counts it and held_refused does not.
	declined, held := h.metric(connEvent("declined_refused")), h.metric(connEvent("held_refused"))
	// The window is the base 2s, not a strike's growing hold: a connection
	// after it reaches the handshake again, and the status fails again.
	settle()
	again := h.client(h.tlsPort, "good")
	time.Sleep(time.Second)
	recAgain := h.records(`"tls_outcome":"status_unavailable"`)
	if len(rs) != 2 || len(again) != 1 {
		cell("h", false, "the client reported %d and %d lines: %+v %+v", len(rs), len(again), rs, again)
	} else {
		cell("h", rs[0].Handshake == "ok" && rs[0].Status == "none" && rs[1].Handshake == "error" &&
			len(recH) == 1 && !strings.Contains(string(h.logBytes()), `"tls_outcome":"handshake_failed"`) &&
			declined == 1 && held == 0 && again[0].Handshake == "ok" && len(recAgain) == 2,
			"first: %+v; second (inside the decline window): %+v; records: %s; declined_refused %v, held_refused %v; "+
				"after the window: %+v, %d records in all", rs[0], rs[1], strings.Join(recH, " "), declined, held, again[0],
			len(recAgain))
	}

	l72Note(t, e, h, string(osslVersion), got)
}

// l72Obs is one cell's observation, and whether it agrees with decision 50.
type l72Obs struct {
	id, observed string
	ok           bool
}

func l72AlertLine(s string) string { return l72FirstLine(s, "alert", "(no alert line)") }
func l72EarlyLine(s string) string { return l72FirstLine(s, "Early data", "(no early data line)") }

func l72FirstLine(s, sub, none string) string {
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, sub) {
			return strings.TrimSpace(line)
		}
	}
	return none
}

// l72Note writes the evidence and the note, after checking that neither
// holds a secret, then fails the test if any cell disagreed.
func l72Note(t *testing.T, e, h *l72Env, osslVersion string, got []l72Obs) {
	t.Helper()
	files := map[string][]byte{"decisions.jsonl": e.logBytes(), "decisions-h.jsonl": h.logBytes()}
	matches, _ := filepath.Glob(filepath.Join(e.dir, "openssl-*.txt"))
	for _, m := range matches {
		b, err := os.ReadFile(m)
		if err != nil {
			t.Fatal(err)
		}
		files[filepath.Base(m)] = b
	}
	claims := map[string]string{}
	for _, c := range l72Cells {
		claims[c.id] = c.claim
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# L72 — reference clients\n\n")
	fmt.Fprintf(&b, "- **Date measured:** %s\n", time.Now().UTC().Format("2006-01-02"))
	fmt.Fprintf(&b, "- **Platform:** reference clients on the lab host, no device\n")
	fmt.Fprintf(&b, "- **Image version:** %s; Go %s (`tests/lab/cmd/tacacs-tls-client`)\n",
		strings.TrimSpace(osslVersion), runtime.Version())
	fmt.Fprintf(&b, "- **Capture:** tests/lab/evidence/L72-reference/\n")
	fmt.Fprintf(&b, "- **Run:** %s\n\n", runLine())
	fmt.Fprintf(&b, "## Claim\n\nspec §15 L72, cell by cell.\n\n## Observation\n\n")
	fmt.Fprintf(&b, "| cell | claim | observed | agrees with decision 50 |\n|---|---|---|---|\n")
	var disagree []string
	for _, o := range got {
		mark := "yes"
		if !o.ok {
			mark, disagree = "**no**", append(disagree, o.id)
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", o.id, claims[o.id],
			strings.ReplaceAll(o.observed, "|", "\\|"), mark)
	}
	note := labcreds.RedactNote(b.String())
	secrets := append(append([]string{}, e.secrets...), h.secrets...)
	for name, body := range files {
		if hits := labcreds.Contains(body, secrets); len(hits) > 0 {
			t.Fatalf("INVALID: evidence %s holds a secret; nothing written", name)
		}
	}
	if hits := labcreds.Contains([]byte(note), secrets); len(hits) > 0 {
		t.Fatal("INVALID: the note holds a secret; nothing written")
	}
	evDir := filepath.Join(root, "tests", "lab", "evidence", "L72-reference")
	if err := os.MkdirAll(evDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(evDir, name), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(root, "tests", "lab", "results", "L72-reference.md")
	if err := os.WriteFile(path, []byte(note), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s", path)
	if len(disagree) > 0 {
		t.Fatalf("cells %v disagree with decision 50: the note records what was observed", disagree)
	}
}
