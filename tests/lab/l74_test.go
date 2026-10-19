//go:build lab

package lab

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
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

// regionBuildCmd builds the three binaries into bins, from the repository root.
func regionBuildCmd(repo, bins string) *exec.Cmd {
	build := exec.Command("go", "build", "-o", bins+"/", "./cmd/port49d", "./cmd/port49-broker", "./cmd/port49")
	build.Dir = repo
	return build
}

// regionNotePath and regionEvidenceDir are where a row's note and evidence go.
func regionNotePath(repo, row string) string {
	return filepath.Join(repo, "tests", "lab", "results", row+"-regions.md")
}

func regionEvidenceDir(repo, row string) string {
	return filepath.Join(repo, "tests", "lab", "evidence", row+"-regions")
}

// disagreeingCells is the ids of the rows that disagree with the claim.
func disagreeingCells(rows []regionRow) []string {
	var ids []string
	for _, r := range rows {
		if !r.Agrees {
			ids = append(ids, r.ID)
		}
	}
	return ids
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
	// envFile holds the two keys (0600, in the run directory); the wrapper
	// sources it, so no key is on any argv.
	envFile string
	// leaks are further checks a note and each evidence line must pass:
	// L75 adds the TOTP secrets' and codes' (l67Secrets.leaksIn).
	leaks []func(string) bool
}

func (w *regionWorld) hold(secret string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.secrets = append(w.secrets, secret)
}

// leaky is whether a line holds a held secret or fails a further leak check.
func (w *regionWorld) leaky(l string) bool {
	w.mu.Lock()
	secrets := append([]string(nil), w.secrets...)
	w.mu.Unlock()
	if len(labcreds.Contains([]byte(l), secrets)) > 0 {
		return true
	}
	for _, leak := range w.leaks {
		if leak(l) {
			return true
		}
	}
	return false
}

// leakless is s without every line that is leaky: what may go to the test log.
func (w *regionWorld) leakless(s string) string {
	var kept []string
	for _, l := range strings.Split(s, "\n") {
		if !w.leaky(l) {
			kept = append(kept, l)
		}
	}
	return strings.Join(kept, "\n")
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
	// Bounded: a CLI waiting on a hung proxy would rest on the server's own
	// timeouts alone.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, w.cli, args...)
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
	return w.sessionWith(i, w.mint(i))
}

// sessionTry is session, but a mint that fails is an error, not a Fatal.
func (w *regionWorld) sessionTry(i int) error {
	tok, err := regionMint(w.pki, regionIP(i)+":8443")
	if err != nil {
		return err
	}
	w.hold(tok)
	return w.sessionWith(i, tok)
}

func (w *regionWorld) sessionWith(i int, token string) error {
	st, _, err := w.client(i).login("alice", token)
	if err != nil || st != "pass" {
		return fmt.Errorf("region %d login: %s %v", i, st, err)
	}
	if st, _, err := w.client(i).command("alice"); err != nil || st != "permit" {
		return fmt.Errorf("region %d session authorization: %s %v", i, st, err)
	}
	// The session's command is permitted now: a later denial is the
	// revocation's, not the policy's.
	if st, _, err := w.client(i).command("alice", "show", "version"); err != nil || st != "permit" {
		return fmt.Errorf("region %d command before the revocation: %s %v", i, st, err)
	}
	return nil
}

// answered is a client call's answer, INVALID with what when the call
// itself failed: an error is not an answer of "deny" or "no".
func (w *regionWorld) answered(what string) func(string, time.Duration, error) string {
	return func(st string, _ time.Duration, err error) string {
		if err != nil {
			w.t.Helper()
			w.t.Fatalf("INVALID: %s: %v", what, err)
		}
		return st
	}
}

// safeLine is the first line of out, or a note that it was withheld when it
// holds a held secret or fails a leak check.
func (w *regionWorld) safeLine(out string) string {
	if l := firstLine(out); !w.leaky(l) {
		return l
	}
	return "[withheld: the line holds a secret]"
}

// until is how long until region i's command answers want, polling every
// 100ms, or false past d.
func (w *regionWorld) until(i int, want string, d time.Duration) (time.Duration, bool) {
	start := time.Now()
	for time.Since(start) < d {
		// A command that errors is not the answer waited for; the wait goes on
		// and its timeout is the measurement.
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
	if root == "" {
		t.Fatal("INVALID: the repository root is not set")
	}
	build := regionBuildCmd(root, bins)
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
	if w.envFile, err = writeRegionEnv(dir, w.encKey, w.tacacsKey); err != nil {
		t.Fatalf("INVALID: writing the run's key file: %v", err)
	}

	// The lab is single-occupant: the shared lock, before the pre-clean below
	// deletes the namespaces (it would tear down another run's network). Held
	// until TestMain's teardown (labRelease), as L73's and L76's are.
	if err := labOccupyForRun(labLockPath, "TestRegions pid "+strconv.Itoa(os.Getpid())); err != nil {
		t.Fatal(err)
	}

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
		// The configs resolve their secret_env at load: the keys are in the
		// command's environment, never on its argv.
		sr := exec.Command(w.port49d, "store-roles", "--config", dcfg, "--broker-config", bcfg)
		sr.Env = append(os.Environ(), "L74_ENC_KEY="+w.encKey, "L74_TACACS_KEY="+w.tacacsKey)
		out, err := sr.CombinedOutput()
		if err != nil {
			t.Fatalf("INVALID: port49d store-roles for region %d: %v\n%s", i, err, w.leakless(string(out)))
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
			cfg: bcfg, log: filepath.Join(dir, fmt.Sprintf("r%d-broker.log", i)), envFile: w.envFile}
		w.daemons[i] = &regionProc{name: fmt.Sprintf("port49d r%d", i), ns: regionNS(i), bin: w.port49d,
			cfg: dcfg, log: filepath.Join(dir, fmt.Sprintf("r%d-port49d.log", i)), envFile: w.envFile}
	}
	for _, procs := range [][4]*regionProc{w.brokers, w.daemons} {
		for i := 1; i <= 3; i++ {
			p := procs[i]
			p.start(t)
			t.Cleanup(p.stop)
			if _, err := p.wait("listening on", 60*time.Second); err != nil {
				t.Fatalf("INVALID: %v\n%s", err, w.leakless(tailOf(p.said(), 2000)))
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
	// The run brings up no platform, so initGlobal never sets root: the build
	// runs from it and the note is written under it (as L72 does).
	if root == "" {
		r, err := repoRoot()
		if err != nil {
			t.Fatalf("INVALID: repo root: %v", err)
		}
		root = r
		t.Cleanup(func() { root = "" })
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
	sortRows(rows)
	writeRegionNote(t, w, "L74", l74Claim, rows, missed, append(w.brokers[1:], w.daemons[1:]...))
	// L74's disagreements do not stop L75: both notes are written, then the test fails.
	disagree := disagreeingCells(rows)
	guard()
	if d75 := l75(t, w); len(d75) > 0 {
		disagree = append(disagree, "L75:"+strings.Join(d75, ",L75:"))
	}
	if len(disagree) > 0 {
		t.Fatalf("cells %v disagree with decision 51: the note records what was observed", disagree)
	}
}

// sortRows orders rows by cell id.
func sortRows(rows []regionRow) {
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
}

func l74CellA(w *regionWorld, row func(id, claim, observed string, agrees bool)) {
	var parts []string
	ok := true
	for i := 1; i <= 3; i++ {
		st, took, err := w.client(i).login("alice", w.mint(i))
		cst, ctook, cerr := w.client(i).command("alice")
		vst, vtook, verr := w.client(i).command("alice", "show", "version")
		parts = append(parts, fmt.Sprintf("region %d: login %s in %v, session authorization %s in %v, command %s in %v",
			i, st, took.Round(time.Millisecond), cst, ctook.Round(time.Millisecond), vst, vtook.Round(time.Millisecond)))
		ok = ok && err == nil && cerr == nil && verr == nil && st == "pass" && cst == "permit" && vst == "permit"
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

// (c) to (g) and (f)'s dark half: one cut of region 3 (c, d, e, f's first
// half), the heal and the catch-up of the port49d served from its snapshot
// (g), then a second cut for the restart with no snapshot (f's second half).
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
		js, cerr := w.sess[3].ctl("https://"+w.sess[3].client, snapshotCountArgs()...)
		if cerr != nil {
			w.t.Fatalf("INVALID: counting region 3's marks records: %v: %s", cerr, js)
		}
		if etcdCount(js) >= 2 {
			break
		}
		if time.Now().After(deadline) {
			w.t.Fatal("INVALID: region 3 wrote no directory snapshots within 150s")
		}
	}
	cut := w.cutRegion3()
	defer cut.heal()

	if _, err := w.daemons[3].wait("directory store: not answering", 15*time.Second); err != nil {
		w.t.Fatalf("INVALID: %v", err)
	}

	cst := w.answered("(c) region 3's open session's command")(w.client(3).command("alice", "show", "version"))
	lst := w.answered("(c) region 3's login with the token minted before the cut")(w.client(3).login("alice", pre))
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
	rout, rcode, _ := w.port49("revoke", "--socket", w.adminSock(1, "b"), "--principal", "user:alice@example.com")
	// Region 2's port49d learns the mark from its marks watch, which sits on one
	// member's connection: on the cut member's it is silent until gRPC's
	// keepalive (10s + 2s) fails that connection, so the control is polled for
	// 15s and the latency recorded, not read at a fixed 5s.
	var d2 string
	var d2After time.Duration
	for start := time.Now(); time.Since(start) < 15*time.Second; time.Sleep(time.Second) {
		d2 = w.answered("(d) region 2's command")(w.client(2).command("alice", "show", "version"))
		if d2After = time.Since(start); d2 == "deny" {
			break
		}
	}
	d3 := w.answered("(d) region 3's command")(w.client(3).command("alice", "show", "version"))
	row("d", "during the cut, a revocation in region 1: region 3's session still permitted (region 2's denied, the control, "+
		"within gRPC keepalive's 10s + 2s)",
		fmt.Sprintf("revoke exit %d: %s; region 2 %s after %v; region 3 %s", rcode, w.safeLine(rout), d2,
			d2After.Round(100*time.Millisecond), d3),
		rcode == 0 && d3 == "permit" && d2 == "deny")

	w.guard()
	out1, c1, t1 := w.port49("revoke", "--socket", w.adminSock(3, "b"), "--principal", "user:bob@example.com")
	out2, c2, t2 := w.port49("revoke", "--socket", w.adminSock(3, "b"), "--principal", "user:carol@example.com", "--lift")
	row("e", "during the cut, port49 revoke and port49 revoke --lift on region 3's broker: each refused, and how long each took",
		fmt.Sprintf("revoke: exit %d in %v: %s; lift: exit %d in %v: %s", c1, t1.Round(time.Millisecond),
			firstLine(out1), c2, t2.Round(time.Millisecond), firstLine(out2)),
		c1 != 0 && c2 != 0 && t1 < 5*time.Second && t2 < 5*time.Second)

	// (f), first half: restarts during the cut serve from region 3's snapshot (R19).
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
		// A port49d that did not listen answers with an error: the row says
		// so through lerr, and the empty answer is not "pass".
		fst, _, _ = w.client(3).login("alice", tok)
	}
	// The session open before the restart: its command is served from the
	// snapshot too (alice's revocation was not in it).
	fcmd, _, _ := w.client(3).command("alice", "show", "version")
	fstatus, _, _ := w.port49("store", "status", "--socket", w.adminSock(3, "d"))
	snapOK := lerr == nil && berr == nil && fst == "pass" && fcmd == "permit" && strings.Contains(fstatus, "(snapshot)")
	snapSaid := fmt.Sprintf("from the snapshot: port49d listened %v, the broker listened %v, a mint and login: %s, "+
		"the open session's command: %s, status: %s", lerr == nil, berr == nil, fst, fcmd, strings.ReplaceAll(fstatus, "\n", " / "))

	// (g) the heal, measured on the port49d that was served from its snapshot
	// and held the session of (d): how long until it catches up and denies.
	w.guard()
	if err := cut.healNow(); err != nil {
		w.t.Fatalf("INVALID: the heal: %v", err)
	}
	healedAt := time.Now()
	denied, ok := w.until(3, "deny", 60*time.Second)
	took, rerr := w.brokers[3].wait("a revocation of user:alice@example.com made elsewhere reached", 30*time.Second)
	row("g", "the heal: the time until region 3's session from (d), held by the port49d served from its snapshot, is "+
		"denied, and region 3's runner line naming the revocation",
		fmt.Sprintf("denied %v after the heal (%v; heal at %s); runner line after %v: %s",
			denied.Round(10*time.Millisecond), ok, healedAt.UTC().Format("15:04:05"), took.Round(10*time.Millisecond),
			firstLineWith(w.brokers[3].said(), "user:alice@example.com made elsewhere reached")),
		ok && rerr == nil)
	for _, p := range []string{"user:alice@example.com", "user:carol@example.com"} {
		// Cleanup between cells: a lift that fails shows as a mint still refused
		// just below, where the retry ends in INVALID.
		w.port49("revoke", "--socket", w.adminSock(1, "b"), "--principal", p, "--lift")
	}

	// Broker 3 has the lifts before the next cut: a session opens at region 3
	// again (a mint refused for a mark not yet lifted is tried again), so (i)
	// starts from a state it did not have to wait for.
	var lastTry error
	opened := false
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(time.Second) {
		if lastTry = w.sessionTry(3); lastTry == nil {
			opened = true
			break
		}
	}
	if !opened {
		w.t.Fatalf("INVALID: region 3 would not open a session after the lifts: %v", lastTry)
	}

	// (f), second half: a second cut; with its snapshots deleted, a restarted
	// port49d stays dark until the heal.
	w.guard()
	if err := cut.cutNow(); err != nil {
		w.t.Fatalf("INVALID: the second cut: %v", err)
	}
	w.daemons[3].stop()
	if _, err := w.sess[3].ctl("https://"+w.sess[3].client, "del", "--prefix", "/port49/v1/ds/"); err != nil {
		w.t.Fatalf("INVALID: deleting region 3's snapshots: %v", err)
	}
	w.daemons[3].start(w.t)
	time.Sleep(20 * time.Second)
	said := w.daemons[3].said()
	running := true
	select {
	case <-w.daemons[3].done:
		running = false
	default:
	}
	darkLine := firstLineWith(said, "no snapshot")
	_, derr := net.DialTimeout("tcp", regionIP(3)+":4949", 2*time.Second)
	listened := strings.Contains(said, "port49d: listening on")
	row("f", "during the cut, port49d and port49-broker restarted in region 3 serve from its snapshot (a mint, a login, "+
		"a session's command permitted); with its snapshots deleted, a restarted port49d's listeners stay closed until the heal",
		fmt.Sprintf("%s; without: the process still running %v, 20s after the restart said it listens %v, a dial to 4949: %v; its line: %s",
			snapSaid, running, listened, derr, darkLine),
		snapOK && running && !listened && derr != nil && darkLine != "")

	w.guard()
	if err := cut.healNow(); err != nil {
		w.t.Fatalf("INVALID: the heal: %v", err)
	}
	if _, err := w.daemons[3].wait("port49d: listening on", 60*time.Second); err != nil {
		w.t.Fatalf("INVALID: %v", err)
	}
}

// regionCutState is region 3's cut, healed however the cell ends: the
// deferred heal runs on a failed cell too.
type regionCutState struct {
	w   *regionWorld
	cut bool
}

func (w *regionWorld) cutRegion3() *regionCutState {
	c := &regionCutState{w: w}
	w.guard()
	if err := c.cutNow(); err != nil {
		w.t.Fatalf("INVALID: the cut: %v", err)
	}
	return c
}

func (c *regionCutState) cutNow() error {
	if err := sudoRun(regionCut(3, true), false); err != nil {
		return err
	}
	c.cut = true
	return nil
}

func (c *regionCutState) healNow() error {
	if err := sudoRun(regionCut(3, false), false); err != nil {
		return err
	}
	c.cut = false
	return nil
}

// heal removes the cut if it is still in; errors are ignored (a deferred call).
func (c *regionCutState) heal() {
	if c.cut {
		_ = sudoRun(regionCut(3, false), true)
		c.cut = false
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

// snapshotCountArgs is the etcdctl read that counts the marks records.
// --count-only is refused with -w json (v3.6.15: "only for --write-out=fields"),
// so the keys are listed, without values, and the JSON's top-level count read.
func snapshotCountArgs() []string {
	return []string{"get", "--prefix", "/port49/v1/ds/m/", "--keys-only", "-w", "json"}
}

// etcdCount is the count of `etcdctl get --keys-only -w json`.
func etcdCount(js string) int64 {
	var r struct {
		Count int64 `json:"count"`
	}
	_ = json.Unmarshal([]byte(js), &r)
	return r.Count
}

// markRevisionOf is the mod_revision of the first key holding who in
// `etcdctl get --prefix -w json`'s answer, 0 when none does.
func markRevisionOf(js, who string) int64 {
	var r struct {
		Kvs []struct {
			Key         []byte `json:"key"`
			ModRevision int64  `json:"mod_revision"`
		} `json:"kvs"`
	}
	if json.Unmarshal([]byte(js), &r) != nil {
		return 0
	}
	for _, kv := range r.Kvs {
		if strings.Contains(string(kv.Key), who) {
			return kv.ModRevision
		}
	}
	return 0
}

// compactedPastTheLift is nil when the compaction at compacted is above the
// revision just after the revocation at revoked: etcd keeps the event at the
// compaction revision, so a watch resuming from the revocation's successor
// still gets the lift, unless something was written after it.
func compactedPastTheLift(revoked, compacted int64) error {
	if revoked == 0 || compacted <= revoked+1 {
		return fmt.Errorf("the compaction at revision %d is not above the revocation's %d plus its lift", compacted, revoked)
	}
	return nil
}

// feedCompacted waits up to d for p to say its marks feed's revision was
// compacted: without that line no rescan ran, so cell (i) measured a lift
// that arrived as an event.
func feedCompacted(p *regionProc, d time.Duration, compactedAt int64) error {
	if _, err := p.wait("the marks feed's revision was compacted", d); err != nil {
		return fmt.Errorf("region 3's marks feed did not report its revision compacted, a port49 finding if the compaction "+
			"(at revision %d, above the lift) landed: %w", compactedAt, err)
	}
	return nil
}

// feedStopped waits up to d for p to say its marks feed stopped (since the
// last mark), or errs naming what it did not say: the cut did not reach the
// feed, so cell (i) would measure a lift that arrived as an event.
func feedStopped(p *regionProc, d time.Duration) error {
	if _, err := p.wait("the marks feed stopped", d); err != nil {
		return fmt.Errorf("the cut did not stop the marks feed, so a lift after it would not be a missed event, a port49 finding if the cut held: %w", err)
	}
	return nil
}

// (i) a lift in region 1 during a cut longer than a compaction: region 3's
// runner cannot tell it from a mark a restore lost, and puts it back on the
// heal (R17; plan 7e Ruling 12).
func l74CellI(w *regionWorld, row func(id, claim, observed string, agrees bool)) {
	d := w.dirMembers[1]
	near := "https://" + regionIP(1) + ":2379,https://" + regionIP(2) + ":2379" // the side that keeps its quorum
	// A session in region 3 that is permitted now, so its denial below is the
	// revocation's, and broker 3's own copy of the mark (its marks file) holds
	// the mark before the cut.
	if err := w.session(3); err != nil {
		w.t.Fatalf("INVALID: %v", err)
	}
	w.brokers[3].mark()
	if _, code, _ := w.port49("revoke", "--socket", w.adminSock(1, "b"), "--principal", "user:alice@example.com"); code != 0 {
		w.t.Fatalf("INVALID: alice's revocation before the cut: exit %d", code)
	}
	if _, ok := w.until(3, "deny", 30*time.Second); !ok {
		w.t.Fatal("INVALID: region 3 never denied after the revocation")
	}
	if _, err := w.brokers[3].wait("a revocation of user:alice@example.com made elsewhere reached", 30*time.Second); err != nil {
		w.t.Fatalf("INVALID: broker 3 never learned the mark before the cut: %v", err)
	}
	marks, merr := d.ctl(w.dirEndpoints(), "get", "/port49/v1/rv/", "--prefix", "-w", "json")
	if merr != nil {
		w.t.Fatalf("INVALID: reading alice's mark before the cut: %v", merr)
	}
	revokedAt := markRevisionOf(marks, "alice@example.com")
	if revokedAt == 0 {
		w.t.Fatal("INVALID: alice's mark revision could not be read before the cut")
	}
	w.brokers[3].mark() // the put-back line is looked for from here
	cut := w.cutRegion3()
	defer cut.heal()
	// The lift must reach region 3 as a missed event: until broker 3's marks
	// feed has stopped, its watch stream may still deliver the lift's delete
	// after the heal, and there is nothing to put back. A stalled stream is
	// failed by gRPC keepalive (10s + 2s) or the minority member's no-leader
	// cancel, so the wait is 30s.
	if err := feedStopped(w.brokers[3], 30*time.Second); err != nil {
		w.t.Fatalf("INVALID: %v", err)
	}
	if _, lcode, _ := w.port49("revoke", "--socket", w.adminSock(1, "b"), "--principal", "user:alice@example.com", "--lift"); lcode != 0 {
		w.t.Fatalf("INVALID: the lift in region 1: exit %d", lcode)
	}
	// One write after the lift, and the compaction at that revision: etcd keeps
	// the event at the compaction revision, so compacting at the lift's own
	// would leave region 3's watch its delete.
	if out, perr := d.ctl(near, "put", "/l74/after-lift", "1"); perr != nil {
		w.t.Fatalf("INVALID: the write after the lift: %v: %s", perr, out)
	}
	st, serr := d.ctl(near, "endpoint", "status", "-w", "json")
	if serr != nil {
		w.t.Fatalf("INVALID: the directory's endpoint status: %v: %s", serr, st)
	}
	rev := revisionOf(st)
	if rev == 0 {
		w.t.Fatal("INVALID: the directory's revision could not be read")
	}
	if err := compactedPastTheLift(revokedAt, rev); err != nil {
		w.t.Fatalf("INVALID: %v", err)
	}
	if _, cerr := d.ctl(near, "compact", strconv.FormatInt(rev, 10), "--physical"); cerr != nil {
		w.t.Fatalf("INVALID: the compaction at revision %d: %v", rev, cerr)
	}
	w.guard()
	if err := cut.healNow(); err != nil {
		w.t.Fatalf("INVALID: the heal: %v", err)
	}
	if err := feedCompacted(w.brokers[3], 30*time.Second, rev); err != nil {
		w.t.Fatalf("INVALID: %v", err)
	}
	took, perr := w.brokers[3].wait("are put back", 60*time.Second)
	keys, kerr := d.ctl(w.dirEndpoints(), "get", "/port49/v1/rv/", "--prefix", "--keys-only")
	if kerr != nil {
		w.t.Fatalf("INVALID: reading the directory's marks after the heal: %v", kerr)
	}
	n := strings.Count(keys, "alice@example.com") // alice's own mark, not every mark under rv/
	row("i", "a lift in region 1 during a cut longer than a compaction: whether region 3's runner puts the mark back on the heal",
		fmt.Sprintf("alice's mark written at revision %d; lift exit 0; compacted at revision %d (after one more write); put-back line after %v: %s; alice's marks in the directory after: %d",
			revokedAt, rev, took.Round(10*time.Millisecond), firstLineWith(w.brokers[3].said(), "are put back"), n),
		perr == nil && n == 1)
	// Cleanup after the last cell: nothing is measured from it.
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
	path := regionNotePath(root, row)
	if err := os.WriteFile(path, []byte(note), 0o644); err != nil {
		t.Fatal(err)
	}
	ev := regionEvidenceDir(root, row)
	if err := os.MkdirAll(ev, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, p := range procs {
		raw, _ := os.ReadFile(p.log)
		var kept []string
		for _, l := range strings.Split(string(raw), "\n") {
			if !w.leaky(l) {
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
