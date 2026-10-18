//go:build lab

package lab

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/tests/lab/labcreds"
)

const l74Claim = "spec §15 L74, cell by cell (decision 51: the cache, fail closed, a process with no cache, the runner's reach, port49 store status)."

// regionRow is one cell's line of a note.
type regionRow struct {
	ID, Claim, Observed string
	Agrees              bool
}

// regionNote is a results note in L72's shape.
func regionNote(row, platform, version, run, claim string, rows []regionRow, notMeasured []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s — three simulated regions\n\n- **Date measured:** %s\n- **Platform:** %s\n"+
		"- **Image version:** %s\n- **Capture:** tests/lab/evidence/%s-regions/\n- **Run:** %s\n\n## Claim\n\n%s\n\n"+
		"## Observation\n\n| cell | claim | observed | agrees with decision 51 |\n|---|---|---|---|\n",
		row, time.Now().UTC().Format("2006-01-02"), platform, version, row, run, claim)
	for _, r := range rows {
		agrees := "yes"
		if !r.Agrees {
			agrees = "**no**"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", r.ID, r.Claim, strings.ReplaceAll(r.Observed, "|", "\\|"), agrees)
	}
	if len(notMeasured) > 0 {
		b.WriteString("\n**Not measured here:**\n\n- " + strings.Join(notMeasured, "\n- ") + "\n")
	}
	return b.String()
}

// regionWorld is the run: the PKI, the binaries, the members and processes
// of each region, and every secret the notes must not hold.
type regionWorld struct {
	t                 *testing.T
	dir, etcdBin      string
	port49d, broker   string // binaries
	cli               string // port49
	pki               *regionPKI
	dirMembers, sess  [4]*regionEtcd // indexed 1..3
	brokers, daemons  [4]*regionProc
	encKey, tacacsKey string
	secrets           []string
	mu                sync.Mutex
	// home is the $HOME every port49 CLI run gets: its .port49/config.yaml
	// pins issued_key_store: file (pinFileKeyStore), so no run probes the
	// machine's TPM (lab rules). guard is the STOP and disk check, run
	// before every cell.
	home  string
	guard func()
	// leaks are further checks a note and each evidence line must pass:
	// L75 adds the TOTP secrets' and codes' (l67Secrets.leaksIn).
	leaks []func(string) bool
}

func (w *regionWorld) hold(secret string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.secrets = append(w.secrets, secret)
}

func (w *regionWorld) env() []string {
	return []string{"L74_ENC_KEY=" + w.encKey, "L74_TACACS_KEY=" + w.tacacsKey}
}

func (w *regionWorld) client(i int) regionClient {
	return regionClient{addr: regionIP(i) + ":4949", key: []byte(w.tacacsKey)}
}

func (w *regionWorld) adminSock(i int, proc string) string {
	return filepath.Join(w.dir, fmt.Sprintf("r%d-%s.sock", i, proc))
}

// port49 runs the CLI and answers its output, exit code and duration.
func (w *regionWorld) port49(args ...string) (string, int, time.Duration) {
	start := time.Now()
	cmd := exec.Command(w.cli, args...)
	cmd.Env = append(os.Environ(), "HOME="+w.home)
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		code = -1
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
	}
	return strings.TrimSpace(string(out)), code, time.Since(start)
}

// mint is a token minted at region i's broker, held and registered.
func (w *regionWorld) mint(i int) string {
	w.t.Helper()
	tok, err := regionMint(w.pki, regionIP(i)+":8443")
	if err != nil {
		w.t.Fatalf("INVALID: %v", err)
	}
	w.hold(tok)
	return tok
}

// session logs alice in at region i with a fresh token and authorizes her
// session, as a device does before her first command.
func (w *regionWorld) session(i int) error {
	st, _, err := w.client(i).login("alice", w.mint(i))
	if err != nil || st != "pass" {
		return fmt.Errorf("region %d login: %s %v", i, st, err)
	}
	if st, _, err := w.client(i).command("alice"); err != nil || st != "permit" {
		return fmt.Errorf("region %d session authorization: %s %v", i, st, err)
	}
	return nil
}

// until is how long until region i's command answers want, polling every
// 100ms, or false past d.
func (w *regionWorld) until(i int, want string, d time.Duration) (time.Duration, bool) {
	start := time.Now()
	for time.Since(start) < d {
		if st, _, _ := w.client(i).command("alice", "show", "version"); st == want {
			return time.Since(start), true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return d, false
}

// startRegions builds the run (L74's shape): the binaries, the keys, the
// network, the etcd members, the roles, the brokers and the daemons, each
// removed at t's cleanup (in reverse: processes, members, network).
func startRegions(t *testing.T, etcdBin string) *regionWorld {
	t.Helper()
	dir, err := os.MkdirTemp("", "p49l74")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	w := &regionWorld{t: t, dir: dir, etcdBin: etcdBin, pki: newRegionPKI(t), home: filepath.Join(dir, "home"),
		guard: func() {}}
	if err := pinFileKeyStore(w.home); err != nil {
		t.Fatalf("INVALID: the CLI's home: %v", err)
	}
	bins := filepath.Join(dir, "bin")
	build := exec.Command("go", "build", "-o", bins+"/", "./cmd/port49d", "./cmd/port49-broker", "./cmd/port49")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("INVALID: building the binaries: %v\n%s", err, out)
	}
	w.port49d, w.broker, w.cli = filepath.Join(bins, "port49d"), filepath.Join(bins, "port49-broker"),
		filepath.Join(bins, "port49")
	// The encryption key is 32 bytes as written (32 hex characters), as the
	// lab's default is; both are this run's and held for the leak check.
	w.encKey, w.tacacsKey = randomHex(t, 16), randomHex(t, 12)
	w.hold(w.encKey)
	w.hold(w.tacacsKey)

	_ = sudoRun(regionNetDown(), true)
	if err := sudoRun(regionNetUp(), false); err != nil {
		t.Fatalf("INVALID: the network: %v", err)
	}
	t.Cleanup(func() { _ = sudoRun(regionNetDown(), true) })

	var initial []string
	for i := 1; i <= 3; i++ {
		initial = append(initial, fmt.Sprintf("d%d=http://%s:2380", i, regionIP(i)))
	}
	for i := 1; i <= 3; i++ {
		w.dirMembers[i] = &regionEtcd{ns: regionNS(i), name: fmt.Sprintf("d%d", i), bin: etcdBin,
			client: regionIP(i) + ":2379", peer: regionIP(i) + ":2380", cluster: strings.Join(initial, ","),
			data: filepath.Join(dir, fmt.Sprintf("d%d.etcd", i)), log: filepath.Join(dir, fmt.Sprintf("d%d.log", i)),
			pki: w.pki}
		w.sess[i] = &regionEtcd{ns: regionNS(i), name: "s", bin: etcdBin, client: regionSessionClient,
			peer: regionSessionPeer, cluster: "s=http://" + regionSessionPeer,
			data: filepath.Join(dir, fmt.Sprintf("s%d.etcd", i)), log: filepath.Join(dir, fmt.Sprintf("s%d.log", i)),
			pki: w.pki}
	}
	for i := 1; i <= 3; i++ {
		w.dirMembers[i].start(t)
		w.sess[i].start(t)
	}
	health := func(e *regionEtcd) {
		for deadline := time.Now().Add(60 * time.Second); ; time.Sleep(500 * time.Millisecond) {
			if _, err := e.ctl("https://"+e.client, "endpoint", "health"); err == nil {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("INVALID: etcd %s in %s did not answer within 60s; see %s", e.name, e.ns, e.log)
			}
		}
	}
	for i := 1; i <= 3; i++ {
		health(w.dirMembers[i])
		health(w.sess[i])
	}

	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	write("policy.yaml", regionPolicy())
	write("inventory.yaml", regionInventory())
	for i := 1; i <= 3; i++ {
		dcfg := write(fmt.Sprintf("r%d-port49d.yaml", i), w.daemonYAML(i))
		bcfg := write(fmt.Sprintf("r%d-port49-broker.yaml", i), w.brokerYAML(i))
		out, err := exec.Command(w.port49d, "store-roles", "--config", dcfg, "--broker-config", bcfg).CombinedOutput()
		if err != nil {
			t.Fatalf("INVALID: port49d store-roles for region %d: %v\n%s", i, err, out)
		}
		s := w.sess[i]
		ctl := map[string]func(args ...string) (string, error){
			"session": func(args ...string) (string, error) { return s.ctl("https://"+s.client, args...) }}
		if i == 1 { // the directory's roles are made once
			d := w.dirMembers[1]
			ctl["directory"] = func(args ...string) (string, error) { return d.ctl(w.dirEndpoints(), args...) }
		}
		applyRoles(t, string(out), ctl)
		w.brokers[i] = &regionProc{name: fmt.Sprintf("port49-broker r%d", i), ns: regionNS(i), bin: w.broker,
			cfg: bcfg, log: filepath.Join(dir, fmt.Sprintf("r%d-broker.log", i)), env: w.env()}
		w.daemons[i] = &regionProc{name: fmt.Sprintf("port49d r%d", i), ns: regionNS(i), bin: w.port49d,
			cfg: dcfg, log: filepath.Join(dir, fmt.Sprintf("r%d-port49d.log", i)), env: w.env()}
	}
	for _, procs := range [][4]*regionProc{w.brokers, w.daemons} {
		for i := 1; i <= 3; i++ {
			p := procs[i]
			p.start(t)
			t.Cleanup(p.stop)
			if _, err := p.wait("listening on", 60*time.Second); err != nil {
				t.Fatalf("INVALID: %v\n%s", err, tailOf(p.said(), 2000))
			}
		}
	}
	return w
}

// dirEndpoints is the directory's three client URLs, for etcdctl.
func (w *regionWorld) dirEndpoints() string {
	var eps []string
	for i := 1; i <= 3; i++ {
		eps = append(eps, "https://"+regionIP(i)+":2379")
	}
	return strings.Join(eps, ",")
}

func regionPolicy() string {
	return `scopes:
  - {name: all, match: {}}
roles:
  - {name: admin, privilege: admin, permit: ["**"]}
subjects:
  - {name: alice, identity: ["user:alice@example.com"], username: alice, token_ttl: 900s}
grants:
  - {subject: alice, scope: all, roles: [admin]}
key_groups:
  - {match: {cidr: 10.149.0.0/24}, key_ref: k}
`
}

func regionInventory() string {
	return "devices:\n  - {name: " + regionDevice + ", platform: arista_eos, addresses: [" + regionHostIP + "]}\n"
}

func (w *regionWorld) daemonYAML(i int) string {
	return fmt.Sprintf(`listen: "%[1]s:4949"
metrics_listen: "%[1]s:9049"
inventory_file: %[2]s/inventory.yaml
policy: {file: %[2]s/policy.yaml, watch_interval: 5s}
keys:
  k:
    current: {version: 1, secret_env: L74_TACACS_KEY}
encryption:
  current: {id: l74, secret_env: L74_ENC_KEY}
admin_socket: %[3]s
accounting: {spool_path: %[2]s/r%[4]d-acct.jsonl}
`, regionIP(i), w.dir, w.adminSock(i, "d"), i) + regionStoresYAML(w.pki, "daemon", regionSessionClient)
}

func (w *regionWorld) brokerYAML(i int) string {
	state := filepath.Join(w.dir, fmt.Sprintf("r%d-state", i))
	os.Mkdir(state, 0o700)
	return fmt.Sprintf(`metrics_listen: "%[1]s:9050"
inventory_file: %[2]s/inventory.yaml
key_refs: [k]
encryption:
  current: {id: l74, secret_env: L74_ENC_KEY}
admin_socket: %[3]s
broker:
  listen: "%[1]s:8443"
  tls_cert_file: %[4]s
  tls_key_file: %[5]s
  client_ca_file: %[6]s
  policy_file: %[2]s/policy.yaml
  state_dir: %[7]s
  policy_watch_interval: 5s
  certificate_status: {disabled: true}
`, regionIP(i), w.dir, w.adminSock(i, "b"), filepath.Join(w.pki.lab, testpki.LabServerCert),
		filepath.Join(w.pki.lab, testpki.LabServerKey), filepath.Join(w.pki.lab, testpki.LabCA), state) +
		regionStoresYAML(w.pki, "broker", regionSessionClient)
}

func TestRegions(t *testing.T) {
	guard := func() {
		if err := labGuardAt(l66StopSentinel, "/", l66DiskFloorMB); err != nil {
			t.Fatalf("INVALID: %v", err)
		}
	}
	guard()
	bin := os.Getenv("PORT49_LAB_ETCD_BIN")
	if bin == "" {
		t.Skip("PORT49_LAB_ETCD_BIN names no directory holding etcd and etcdctl v3.6.15")
	}
	w := startRegions(t, bin)
	w.guard = guard
	var rows []regionRow
	var missed []string
	row := func(id, claim, observed string, agrees bool) {
		rows = append(rows, regionRow{ID: id, Claim: claim, Observed: observed, Agrees: agrees})
	}
	guard()
	l74CellA(w, row)
	guard()
	l74CellB(w, row)
	guard()
	l74CellsCToG(w, row)
	guard()
	l74CellH(w, row)
	guard()
	l74CellI(w, row)
	writeRegionNote(t, w, "L74", l74Claim, rows, missed, append(w.brokers[1:], w.daemons[1:]...))
}

func l74CellA(w *regionWorld, row func(id, claim, observed string, agrees bool)) {
	var parts []string
	ok := true
	for i := 1; i <= 3; i++ {
		st, took, err := w.client(i).login("alice", w.mint(i))
		cst, ctook, cerr := w.client(i).command("alice")
		parts = append(parts, fmt.Sprintf("region %d: login %s in %v, session authorization %s in %v",
			i, st, took.Round(time.Millisecond), cst, ctook.Round(time.Millisecond)))
		ok = ok && err == nil && cerr == nil && st == "pass" && cst == "permit"
	}
	out, _ := exec.Command("sudo", "-n", "ip", "netns", "exec", regionNS(1), "ping", "-c", "5", "-q", regionIP(2)).CombinedOutput()
	parts = append(parts, "region 1 to region 2: "+lastLine(string(out)))
	row("a", "a login and a command in each region; their reply times beside the round trip between regions",
		strings.Join(parts, "; "), ok)
}

// (b) a revocation in region 1: the time until region 2's and region 3's
// next command is denied; then the lift.
func l74CellB(w *regionWorld, row func(id, claim, observed string, agrees bool)) {
	for i := 2; i <= 3; i++ {
		if err := w.session(i); err != nil {
			w.t.Fatalf("INVALID: %v", err)
		}
	}
	_, code, took := w.port49("revoke", "--socket", w.adminSock(1, "b"), "--principal", "user:alice@example.com")
	d2, ok2 := w.until(2, "deny", 30*time.Second)
	d3, ok3 := w.until(3, "deny", 30*time.Second)
	_, lcode, _ := w.port49("revoke", "--socket", w.adminSock(1, "b"), "--principal", "user:alice@example.com", "--lift")
	row("b", "a revocation made in region 1: the time until region 2's and region 3's next command is denied",
		fmt.Sprintf("revoke exit %d in %v; region 2 denied after %v (%v), region 3 after %v (%v); lift exit %d",
			code, took.Round(time.Millisecond), d2.Round(10*time.Millisecond), ok2, d3.Round(10*time.Millisecond), ok3, lcode),
		code == 0 && ok2 && ok3 && lcode == 0)
}

// metrics is region i's port49d's /metrics, "" when it does not answer.
func (w *regionWorld) metrics(i int) string {
	resp, err := http.Get("http://" + regionIP(i) + ":9049/metrics")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return string(raw)
}

// metricOf is the value of the label-less metric name in text, or -1.
func metricOf(text, name string) float64 {
	for _, l := range strings.Split(text, "\n") {
		if v, ok := strings.CutPrefix(l, name+" "); ok {
			if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
				return f
			}
		}
	}
	return -1
}

// firstLineWith is the first line of s holding sub, "" when none does.
func firstLineWith(s, sub string) string {
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, sub) {
			return strings.TrimSpace(l)
		}
	}
	return ""
}

func l74CellsCToG(w *regionWorld, row func(id, claim, observed string, agrees bool)) {
	for _, i := range []int{2, 3} {
		if err := w.session(i); err != nil {
			w.t.Fatalf("INVALID: %v", err)
		}
	}
	pre := w.mint(3)
	// A mark region 3 holds before the cut, for (e)'s lift.
	if _, code, _ := w.port49("revoke", "--socket", w.adminSock(1, "b"), "--principal", "user:carol@example.com"); code != 0 {
		w.t.Fatal("INVALID: carol's revocation before the cut")
	}
	if _, err := w.brokers[3].wait("a revocation of user:carol@example.com made elsewhere reached", 30*time.Second); err != nil {
		w.t.Fatalf("INVALID: %v", err)
	}
	// R19: region 3's port49d and broker have each written a snapshot (every
	// 60s) before the cut, for (f).
	for deadline := time.Now().Add(150 * time.Second); ; time.Sleep(2 * time.Second) {
		js, _ := w.sess[3].ctl("https://"+w.sess[3].client, "get", "--prefix", "/port49/v1/ds/m/", "--count-only", "-w", "json")
		if etcdCount(js) >= 2 {
			break
		}
		if time.Now().After(deadline) {
			w.t.Fatal("INVALID: region 3 wrote no directory snapshots within 150s")
		}
	}
	w.guard()
	if err := sudoRun(regionCut(3, true), false); err != nil {
		w.t.Fatalf("INVALID: the cut: %v", err)
	}
	healed := false
	defer func() {
		if !healed {
			_ = sudoRun(regionCut(3, false), true)
		}
	}()
	if _, err := w.daemons[3].wait("directory store: not answering", 15*time.Second); err != nil {
		w.t.Fatalf("INVALID: %v", err)
	}

	cst, _, _ := w.client(3).command("alice", "show", "version")
	lst, _, _ := w.client(3).login("alice", pre)
	status, code, _ := w.port49("store", "status", "--socket", w.adminSock(3, "d"))
	m := w.metrics(3)
	reach := metricOf(m, "port49_store_directory_reachable")
	age := float64(time.Now().Unix()) - metricOf(m, "port49_store_directory_confirmed_timestamp_seconds")
	row("c", "region 3 cut: an open session's command and a login with a token minted before the cut answered; "+
		"port49 store status and its exit code; the two metrics",
		fmt.Sprintf("command %s; login %s; `port49 store status` exit %d: %s; port49_store_directory_reachable %v; "+
			"confirmed %.0fs ago", cst, lst, code, strings.ReplaceAll(status, "\n", " / "), reach, age),
		cst == "permit" && lst == "pass" && code == 3 && reach == 0)

	w.guard()
	_, rcode, _ := w.port49("revoke", "--socket", w.adminSock(1, "b"), "--principal", "user:alice@example.com")
	time.Sleep(5 * time.Second)
	d3, _, _ := w.client(3).command("alice", "show", "version")
	d2, _, _ := w.client(2).command("alice", "show", "version")
	row("d", "during the cut, a revocation in region 1: region 3's session still permitted (region 2's denied, the control)",
		fmt.Sprintf("revoke exit %d; 5s later region 3 %s, region 2 %s", rcode, d3, d2),
		rcode == 0 && d3 == "permit" && d2 == "deny")

	w.guard()
	out1, c1, t1 := w.port49("revoke", "--socket", w.adminSock(3, "b"), "--principal", "user:bob@example.com")
	out2, c2, t2 := w.port49("revoke", "--socket", w.adminSock(3, "b"), "--principal", "user:carol@example.com", "--lift")
	row("e", "during the cut, port49 revoke and port49 revoke --lift on region 3's broker: each refused, and how long each took",
		fmt.Sprintf("revoke: exit %d in %v: %s; lift: exit %d in %v: %s", c1, t1.Round(time.Millisecond),
			firstLine(out1), c2, t2.Round(time.Millisecond), firstLine(out2)),
		c1 != 0 && c2 != 0 && t1 < 5*time.Second && t2 < 5*time.Second)

	// (f) restarts during the cut serve from region 3's snapshot (R19); with
	// its snapshots deleted, a restarted port49d stays dark until the heal.
	w.guard()
	w.daemons[3].stop()
	w.brokers[3].stop()
	w.brokers[3].start(w.t)
	w.daemons[3].start(w.t)
	_, lerr := w.daemons[3].wait("port49d: listening on", 60*time.Second)
	_, berr := w.brokers[3].wait("port49-broker: listening on", 60*time.Second)
	fst := "no token"
	if tok, merr := regionMint(w.pki, regionIP(3)+":8443"); merr == nil {
		w.hold(tok)
		fst, _, _ = w.client(3).login("alice", tok)
	}
	fstatus, _, _ := w.port49("store", "status", "--socket", w.adminSock(3, "d"))
	w.daemons[3].stop()
	if _, err := w.sess[3].ctl("https://"+w.sess[3].client, "del", "--prefix", "/port49/v1/ds/"); err != nil {
		w.t.Fatalf("INVALID: deleting region 3's snapshots: %v", err)
	}
	w.daemons[3].start(w.t)
	time.Sleep(20 * time.Second)
	said := w.daemons[3].said()
	_, derr := net.DialTimeout("tcp", regionIP(3)+":4949", 2*time.Second)
	row("f", "during the cut, port49d and port49-broker restarted in region 3 serve from its snapshot; with its "+
		"snapshots deleted, a restarted port49d's listeners stay closed until the heal",
		fmt.Sprintf("from the snapshot: port49d listened %v, the broker listened %v, a mint and login: %s, status: %s; "+
			"without: 20s after the restart said it listens %v, a dial to 4949: %v; its line: %s",
			lerr == nil, berr == nil, fst, strings.ReplaceAll(fstatus, "\n", " / "),
			strings.Contains(said, "port49d: listening on"), derr, firstLineWith(said, "no snapshot")),
		lerr == nil && berr == nil && fst == "pass" && strings.Contains(fstatus, "(snapshot)") &&
			!strings.Contains(said, "port49d: listening on") && derr != nil)

	w.guard()
	if err := sudoRun(regionCut(3, false), false); err != nil {
		w.t.Fatalf("INVALID: the heal: %v", err)
	}
	healed = true
	if _, err := w.daemons[3].wait("port49d: listening on", 60*time.Second); err != nil {
		w.t.Fatalf("INVALID: %v", err)
	}
	denied, ok := w.until(3, "deny", 60*time.Second)
	took, lerr := w.brokers[3].wait("a revocation of user:alice@example.com made elsewhere reached", 30*time.Second)
	row("g", "the heal: the time until region 3's session from (d) is denied, and region 3's runner line naming the revocation",
		fmt.Sprintf("denied %v after port49d listened again (%v); runner line after %v: %s",
			denied.Round(10*time.Millisecond), ok, took.Round(10*time.Millisecond),
			firstLineWith(w.brokers[3].said(), "user:alice@example.com made elsewhere reached")),
		ok && lerr == nil)
	for _, p := range []string{"user:alice@example.com", "user:carol@example.com"} {
		w.port49("revoke", "--socket", w.adminSock(1, "b"), "--principal", p, "--lift")
	}
}

// (h) the members port49 store status prints with auth on, from region 1's port49d.
func l74CellH(w *regionWorld, row func(id, claim, observed string, agrees bool)) {
	out, code, _ := w.port49("store", "status", "--socket", w.adminSock(1, "d"))
	row("h", "with auth on, the members port49 store status prints: whether a non-root identity's member list and per-member status answer",
		fmt.Sprintf("exit %d: %s", code, strings.ReplaceAll(out, "\n", " / ")),
		code == 0 && strings.Contains(out, "directory  etcd    3/3 members  reachable"))
}

// revisionOf is the highest header revision in `etcdctl endpoint status -w json`'s answer.
func revisionOf(js string) int64 {
	var sts []struct {
		Status struct {
			Header struct {
				Revision int64 `json:"revision"`
			} `json:"header"`
		}
	}
	if json.Unmarshal([]byte(js), &sts) != nil {
		return 0
	}
	var rev int64
	for _, s := range sts {
		rev = max(rev, s.Status.Header.Revision)
	}
	return rev
}

// etcdCount is `etcdctl get --count-only -w json`'s count.
func etcdCount(js string) int64 {
	var r struct {
		Count int64 `json:"count"`
	}
	_ = json.Unmarshal([]byte(js), &r)
	return r.Count
}

// (i) a lift in region 1 during a cut longer than a compaction: region 3's
// runner cannot tell it from a mark a restore lost, and puts it back on the
// heal (R17; plan 7e Ruling 12).
func l74CellI(w *regionWorld, row func(id, claim, observed string, agrees bool)) {
	d := w.dirMembers[1]
	near := "https://" + regionIP(1) + ":2379,https://" + regionIP(2) + ":2379" // the side that keeps its quorum
	w.port49("revoke", "--socket", w.adminSock(1, "b"), "--principal", "user:alice@example.com")
	if _, ok := w.until(3, "deny", 30*time.Second); !ok {
		w.t.Fatal("INVALID: region 3 never denied before the cut")
	}
	if err := sudoRun(regionCut(3, true), false); err != nil {
		w.t.Fatalf("INVALID: the cut: %v", err)
	}
	_, lcode, _ := w.port49("revoke", "--socket", w.adminSock(1, "b"), "--principal", "user:alice@example.com", "--lift")
	st, _ := d.ctl(near, "endpoint", "status", "-w", "json")
	rev := revisionOf(st)
	_, cerr := d.ctl(near, "compact", strconv.FormatInt(rev, 10), "--physical")
	if err := sudoRun(regionCut(3, false), false); err != nil {
		w.t.Fatalf("INVALID: the heal: %v", err)
	}
	took, perr := w.brokers[3].wait("are put back", 60*time.Second)
	cnt, _ := d.ctl(w.dirEndpoints(), "get", "/port49/v1/rv/", "--prefix", "--count-only", "-w", "json")
	n := etcdCount(cnt)
	row("i", "a lift in region 1 during a cut longer than a compaction: whether region 3's runner puts the mark back on the heal",
		fmt.Sprintf("lift exit %d; compacted at revision %d (%v); put-back line after %v: %s; marks in the directory after: %d",
			lcode, rev, cerr, took.Round(10*time.Millisecond), firstLineWith(w.brokers[3].said(), "are put back"), n),
		perr == nil && n == 1)
	w.port49("revoke", "--socket", w.adminSock(1, "b"), "--principal", "user:alice@example.com", "--lift")
}

// writeRegionNote writes tests/lab/results/<row>-regions.md and the
// processes' logs as its evidence, each filtered of every line naming a
// held secret; a note that would hold one fails the test.
func writeRegionNote(t *testing.T, w *regionWorld, row, claim string, rows []regionRow, missed []string,
	procs []*regionProc) {
	t.Helper()
	ver, _ := exec.Command(filepath.Join(w.etcdBin, "etcd"), "--version").Output()
	head, _ := exec.Command("git", "-C", root, "rev-parse", "HEAD").Output()
	note := labcreds.RedactNote(regionNote(row,
		"port49 on the lab host, three simulated regions (network namespaces, tc netem 20ms each way)",
		firstLine(string(ver)), "commit `"+strings.TrimSpace(string(head))+"`, `-run TestRegions`", claim, rows, missed))
	if hits := labcreds.Contains([]byte(note), w.secrets); len(hits) > 0 {
		t.Fatalf("the %s note holds a held secret (%d hit(s)); nothing written", row, len(hits))
	}
	for _, leak := range w.leaks {
		if leak(note) {
			t.Fatalf("the %s note holds a TOTP secret or code; nothing written", row)
		}
	}
	leaky := func(l string) bool {
		if len(labcreds.Contains([]byte(l), w.secrets)) > 0 {
			return true
		}
		for _, leak := range w.leaks {
			if leak(l) {
				return true
			}
		}
		return false
	}
	path := filepath.Join(root, "tests", "lab", "results", row+"-regions.md")
	if err := os.WriteFile(path, []byte(note), 0o644); err != nil {
		t.Fatal(err)
	}
	ev := filepath.Join(root, "tests", "lab", "evidence", row+"-regions")
	if err := os.MkdirAll(ev, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, p := range procs {
		raw, _ := os.ReadFile(p.log)
		var kept []string
		for _, l := range strings.Split(string(raw), "\n") {
			if !leaky(l) {
				kept = append(kept, l)
			}
		}
		name := strings.ReplaceAll(p.name, " ", "-") + ".log"
		if err := os.WriteFile(filepath.Join(ev, name), []byte(strings.Join(kept, "\n")), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("wrote %s", path)
}
