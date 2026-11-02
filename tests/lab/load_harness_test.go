//go:build lab

package lab

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/broker/api"
	"github.com/blanketfish/port49/internal/devicemock"
	"github.com/blanketfish/port49/internal/testpki"
)

// The load harness (plan 12c, Task 6): port49d and port49-broker on a
// three-member directory etcd and a session etcd, all on this host's loopback,
// driven open loop by devicemock's Fleet at the design §5 rate. TestLoad runs
// it (Task 7); nothing here runs unless PORT49_LAB_LOAD=1.
const (
	loadPrincipals = 50
	loadHumans     = 450
	loadDevices    = 10000
	loadRate       = 170.0 // logins per second (design §5)

	loadMinDuration  = 10 * time.Minute // a, b, d and e
	loadStepDuration = time.Minute      // one step of c
	loadNetemRun     = 2 * time.Minute  // f

	loadCallTimeout = 500 * time.Millisecond // stores.*.etcd.call_timeout, as the regions' configs set it
	loadNetemDelay  = "40ms"

	loadTCPAddr, loadTLSAddr = "127.0.0.1:14949", "127.0.0.1:14300"
	loadDaemonMetrics        = "127.0.0.1:19049"
	loadBrokerMetrics        = "127.0.0.1:19050"
	loadBrokerAddr           = "127.0.0.1:18443"
	loadServerName           = "tacacs.example.net"
	loadProfile              = "arista_eos/cEOS-lab-4.36.3M.yaml"
)

// loadDirectoryClientPorts are the three directory members' client ports,
// which the netem of cell f delays.
var loadDirectoryClientPorts = []string{"12379", "12389", "12399"}

// loadCellIDs are the cells in the order they run.
var loadCellIDs = []string{"a", "b", "c", "d", "e", "f"}

// loadCell is one cell's result: what was driven, whether it passed, and what
// was observed, as text a note can print.
type loadCell struct {
	ID        string
	Transport string
	Rate      float64
	Duration  time.Duration
	Pass      bool
	Observed  map[string]string
}

// parseLoadCells is PORT49_LAB_LOAD_CELLS: comma-separated cell IDs, empty for
// all of them. The cells come back in run order; an unknown or repeated ID is
// an error, so a typo never runs a shorter load than the one asked for.
func parseLoadCells(s string) ([]string, error) {
	if strings.TrimSpace(s) == "" {
		return slices.Clone(loadCellIDs), nil
	}
	want := map[string]bool{}
	for _, id := range strings.Split(s, ",") {
		id = strings.TrimSpace(id)
		if !slices.Contains(loadCellIDs, id) {
			return nil, fmt.Errorf("PORT49_LAB_LOAD_CELLS: %q is not a load cell (cells: %s)", id, strings.Join(loadCellIDs, ","))
		}
		if want[id] {
			return nil, fmt.Errorf("PORT49_LAB_LOAD_CELLS: %q is listed twice", id)
		}
		want[id] = true
	}
	var out []string
	for _, id := range loadCellIDs {
		if want[id] {
			out = append(out, id)
		}
	}
	return out, nil
}

// validateLoadCell refuses a run too short to mean anything: ten minutes at
// the design rate, a minute for one of c's steps, two for f's netem run.
func validateLoadCell(c loadCell) error {
	min := loadMinDuration
	switch c.ID {
	case "c":
		min = loadStepDuration
	case "f":
		min = loadNetemRun
	}
	switch {
	case c.Rate <= 0:
		return fmt.Errorf("load cell %q: rate %v is not a rate", c.ID, c.Rate)
	case c.Duration < min:
		return fmt.Errorf("load cell %q: %s is shorter than the %s a measurement needs", c.ID, c.Duration, min)
	}
	return nil
}

func loadDeviceName(i int) string { return fmt.Sprintf("load-%05d", i) }

func loadPrincipalEmail(p int) string { return fmt.Sprintf("svc%02d@example.com", p) }

func loadPrincipalEmails() []string {
	var out []string
	for p := range loadPrincipals {
		out = append(out, loadPrincipalEmail(p))
	}
	return out
}

// loadPolicy is the run's policy: 50 machine principals, each granted the
// batch role over every device, and 450 people with a read grant, which the
// resolve and compare work sees as the rest of a 500-subject fleet.
func loadPolicy() string {
	var b strings.Builder
	b.WriteString(`scopes:
  - {name: all_devices, match: {}}
  - {name: arista, match: {platform: arista_eos}, on_missing: include}
roles:
  - {name: load_admin, privilege: admin, permit: ["**"]}
  - {name: load_read, privilege: readonly, permit: ["show **"]}
  - {name: load_denies, deny: ["show users"]}
subjects:
`)
	for p := range loadPrincipals {
		fmt.Fprintf(&b, "  - {name: svc_%02d, identity: [\"user:%s\"], username: svc%02d, token_ttl: 900s}\n", p, loadPrincipalEmail(p), p)
	}
	for h := range loadHumans {
		fmt.Fprintf(&b, "  - {name: human_%03d, identity: [\"user:human%03d@example.com\"], username: human%03d, token_ttl: 900s}\n", h, h, h)
	}
	b.WriteString("grants:\n")
	for p := range loadPrincipals {
		fmt.Fprintf(&b, "  - {subject: svc_%02d, scope: all_devices, roles: [load_admin], max_privilege: admin}\n", p)
		fmt.Fprintf(&b, "  - {subject: svc_%02d, scope: arista, roles: [load_denies], max_privilege: admin}\n", p)
	}
	for h := range loadHumans {
		fmt.Fprintf(&b, "  - {subject: human_%03d, scope: all_devices, roles: [load_read], max_privilege: readonly}\n", h)
	}
	b.WriteString(`key_groups:
  - {match: {cidr: 127.0.0.0/8}, key_ref: k}
keys:
  k:
    current: {version: 1, secret_ref: env:PORT49_KEY_LOAD}
`)
	return b.String()
}

// loadInventory is n arista_eos devices, device i on LoopbackSource(i), each
// on transport ("tcp" is left unwritten, as the default).
func loadInventory(n int, transport string) string {
	var b strings.Builder
	b.WriteString("devices:\n")
	for i := range n {
		fmt.Fprintf(&b, "  - {name: %s, platform: arista_eos, addresses: [%s]", loadDeviceName(i), devicemock.LoopbackSource(i))
		if transport != "" && transport != "tcp" {
			fmt.Fprintf(&b, ", transport: %s", transport)
		}
		b.WriteString("}\n")
	}
	return b.String()
}

// loadNetem is the tc commands (each run under sudo -n) that delay the
// directory members' client ports by loadNetemDelay, and no other loopback
// traffic: netem hangs off the third band of a prio qdisc that only the
// u32 filters send to. Down removes the qdisc.
func loadNetem(up bool) [][]string {
	if !up {
		return [][]string{{"tc", "qdisc", "del", "dev", "lo", "root"}}
	}
	cmds := [][]string{
		{"tc", "qdisc", "add", "dev", "lo", "root", "handle", "1:", "prio"},
		{"tc", "qdisc", "add", "dev", "lo", "parent", "1:3", "handle", "30:", "netem", "delay", loadNetemDelay},
	}
	for _, port := range loadDirectoryClientPorts {
		cmds = append(cmds, []string{"tc", "filter", "add", "dev", "lo", "protocol", "ip", "parent", "1:", "prio", "3",
			"u32", "match", "ip", "dport", port, "0xffff", "flowid", "1:3"})
	}
	return cmds
}

// loadLongRun is a run of 24 or more token-alphabet characters, the
// repository's filter; loadLeaky is whether a value holds one or a word that
// names a credential. Keys are our own names, long ones included, so only the
// words are checked in them.
var loadLongRun = regexp.MustCompile(`[A-Za-z0-9_+/=.-]{24,}`)

func loadNamesCredential(s string) bool {
	l := strings.ToLower(s)
	for _, w := range []string{"token", "credential", "password", "secret", "eyj", "bearer"} {
		if strings.Contains(l, w) {
			return true
		}
	}
	return false
}

func loadLeaky(v string) bool { return loadNamesCredential(v) || loadLongRun.MatchString(v) }

func loadMS(d time.Duration) string {
	return strconv.FormatFloat(float64(d)/float64(time.Millisecond), 'f', 2, 64)
}

// loadObserved is what a fleet result says, as note text: counts and
// durations only, never a login.
func loadObserved(res devicemock.FleetResult, mintP50, mintP99 time.Duration) map[string]string {
	o := map[string]string{
		"plays":       strconv.Itoa(res.Plays),
		"errors":      strconv.Itoa(res.Errors),
		"late":        strconv.Itoa(res.Late),
		"play_p50_ms": loadMS(res.P50),
		"play_p99_ms": loadMS(res.P99),
		"play_max_ms": loadMS(res.Max),
	}
	for kind, n := range res.ErrorKinds {
		o["errors_"+kind] = strconv.Itoa(n)
	}
	for step, d := range res.StepP50 {
		o["step_p50_ms_"+step] = loadMS(d)
	}
	for step, d := range res.StepP99 {
		o["step_p99_ms_"+step] = loadMS(d)
	}
	o["mint_p50_ms"], o["mint_p99_ms"] = loadMS(mintP50), loadMS(mintP99)
	return o
}

// hostFacts is the machine the load ran on: a capacity number means nothing without it.
type hostFacts struct {
	CPU    string
	Cores  int
	RAMMB  int
	Disk   string
	Kernel string
}

func readHostFacts(dir string) hostFacts {
	h := hostFacts{Cores: runtime.NumCPU()}
	if raw, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, l := range strings.Split(string(raw), "\n") {
			if k, v, ok := strings.Cut(l, ":"); ok && strings.TrimSpace(k) == "model name" {
				h.CPU = strings.TrimSpace(v)
				break
			}
		}
	}
	if raw, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, l := range strings.Split(string(raw), "\n") {
			if f := strings.Fields(l); len(f) >= 2 && f[0] == "MemTotal:" {
				kb, _ := strconv.Atoi(f[1])
				h.RAMMB = kb / 1024
			}
		}
	}
	if raw, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		h.Kernel = strings.TrimSpace(string(raw))
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err == nil {
		h.Disk = fmt.Sprintf("%d GB total, %d GB free under the run directory",
			st.Blocks*uint64(st.Bsize)>>30, st.Bavail*uint64(st.Bsize)>>30)
	}
	return h
}

// loadNote is the results note for cells. It is refused, whole, when any
// value in it could hold a credential: the check runs before a byte is printed.
func loadNote(cells []loadCell, host hostFacts) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "# Load at the design rate\n\n- **Date measured:** %s\n- **Host CPU:** %s, %d cores\n- **Host RAM:** %d MB\n"+
		"- **Host disk:** %s\n- **Host kernel:** %s\n- **Fleet:** %d devices, %d machine principals, %d people\n\n",
		time.Now().UTC().Format("2006-01-02"), host.CPU, host.Cores, host.RAMMB, host.Disk, host.Kernel,
		loadDevices, loadPrincipals, loadHumans)
	for _, c := range cells {
		verdict := "PASS"
		if !c.Pass {
			verdict = "**FAIL**"
		}
		fmt.Fprintf(&b, "## Cell %s\n\n- **Transport:** %s\n- **Rate:** %.0f per second\n- **Duration:** %s\n- **Verdict:** %s\n\n",
			c.ID, c.Transport, c.Rate, c.Duration.Round(time.Second), verdict)
		keys := make([]string, 0, len(c.Observed))
		for k := range c.Observed {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "- `%s`: %s\n", k, c.Observed[k])
		}
		b.WriteString("\n")
	}
	if loadNamesCredential(b.String()) {
		return "", errors.New("the load note was not written: it names a credential")
	}
	for _, v := range []string{host.CPU, host.Disk, host.Kernel} {
		if loadLongRun.MatchString(v) {
			return "", errors.New("the load note was not written: a host fact could hold a credential")
		}
	}
	for _, c := range cells {
		for k, v := range c.Observed {
			if loadNamesCredential(k) || loadLeaky(v) {
				return "", fmt.Errorf("the load note was not written: cell %s's %q could hold a credential", c.ID, k)
			}
		}
	}
	return b.String(), nil
}

// loadMetrics is what a /metrics read yields: the gauges as read, and the
// store-call latency histogram's cumulative buckets summed over its labels.
type loadMetrics struct {
	Connections float64 // port49_connections, over every state
	SpoolDepth  float64
	SpoolDrops  float64 // port49_accounting_spool_drops_total, over every stage
	buckets     map[float64]float64
}

var loadBucket = regexp.MustCompile(`le="([^"]+)"`)

func parseLoadMetrics(text string) loadMetrics {
	m := loadMetrics{buckets: map[float64]float64{}}
	for _, l := range strings.Split(text, "\n") {
		if l == "" || l[0] == '#' {
			continue
		}
		i := strings.LastIndexByte(l, ' ')
		if i < 0 {
			continue
		}
		v, err := strconv.ParseFloat(l[i+1:], 64)
		if err != nil {
			continue
		}
		name := l[:i]
		switch {
		case strings.HasPrefix(name, "port49_connections{"):
			m.Connections += v
		case name == "port49_accounting_spool_depth":
			m.SpoolDepth = v
		case strings.HasPrefix(name, "port49_accounting_spool_drops_total"):
			m.SpoolDrops += v
		case strings.HasPrefix(name, "port49_store_call_seconds_bucket"):
			if sm := loadBucket.FindStringSubmatch(name); sm != nil {
				le := math.Inf(1)
				if sm[1] != "+Inf" {
					le, _ = strconv.ParseFloat(sm[1], 64)
				}
				m.buckets[le] += v
			}
		}
	}
	return m
}

// Sub is m less an earlier read: the store calls made between the two. The
// gauges are m's own.
func (m loadMetrics) Sub(earlier loadMetrics) loadMetrics {
	out := m
	out.buckets = map[float64]float64{}
	for le, v := range m.buckets {
		out.buckets[le] = v - earlier.buckets[le]
	}
	return out
}

// Quantile is the upper bound of the bucket holding the q-th store call, 0
// with no calls; a call past the last bucket reads as that bucket's bound.
func (m loadMetrics) Quantile(q float64) time.Duration {
	total := m.buckets[math.Inf(1)]
	if total <= 0 {
		return 0
	}
	want := math.Ceil(q * total)
	var les []float64
	for le := range m.buckets {
		if !math.IsInf(le, 1) {
			les = append(les, le)
		}
	}
	sort.Float64s(les)
	for _, le := range les {
		if m.buckets[le] >= want {
			return time.Duration(le * float64(time.Second))
		}
	}
	if len(les) == 0 {
		return 0
	}
	return time.Duration(les[len(les)-1] * float64(time.Second))
}

// loadScrape reads a /metrics endpoint over plain HTTP.
func loadScrape(addr string) (loadMetrics, error) {
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get("http://" + addr + "/metrics")
	if err != nil {
		return loadMetrics{}, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return loadMetrics{}, err
	}
	return parseLoadMetrics(string(raw)), nil
}

// loadSampler reads a process's /metrics every two seconds and keeps the
// peaks of the gauges.
type loadSampler struct {
	addr                 string
	stop, done           chan struct{}
	peakConns, peakDepth float64
	first, last          loadMetrics
	got                  bool
}

func startLoadSampler(addr string) *loadSampler {
	s := &loadSampler{addr: addr, stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(s.done)
		tick := time.NewTicker(2 * time.Second)
		defer tick.Stop()
		for {
			if m, err := loadScrape(addr); err == nil {
				if !s.got {
					s.first, s.got = m, true
				}
				s.last = m
				s.peakConns = math.Max(s.peakConns, m.Connections)
				s.peakDepth = math.Max(s.peakDepth, m.SpoolDepth)
			}
			select {
			case <-s.stop:
				return
			case <-tick.C:
			}
		}
	}()
	return s
}

func (s *loadSampler) finish() *loadSampler {
	close(s.stop)
	<-s.done
	return s
}

// loadProcUsage is a process's CPU seconds so far and its peak resident set
// in kB, from /proc, by the PID in its pidfile.
func loadProcUsage(pidfile string) (cpu float64, peakKB int, err error) {
	raw, err := os.ReadFile(pidfile)
	if err != nil {
		return 0, 0, err
	}
	pid := strings.TrimSpace(string(raw))
	stat, err := os.ReadFile("/proc/" + pid + "/stat")
	if err != nil {
		return 0, 0, err
	}
	// Fields after the command's closing parenthesis: state is the first,
	// utime and stime the 12th and 13th.
	s := string(stat)
	f := strings.Fields(s[strings.LastIndexByte(s, ')')+1:])
	if len(f) < 13 {
		return 0, 0, errors.New("short /proc stat")
	}
	ut, _ := strconv.ParseFloat(f[11], 64)
	st, _ := strconv.ParseFloat(f[12], 64)
	status, _ := os.ReadFile("/proc/" + pid + "/status")
	for _, l := range strings.Split(string(status), "\n") {
		if fs := strings.Fields(l); len(fs) >= 2 && fs[0] == "VmHWM:" {
			peakKB, _ = strconv.Atoi(fs[1])
		}
	}
	return (ut + st) / 100, peakKB, nil // USER_HZ is 100 on Linux
}

// loadRun is the stack: the etcd members, the broker and the daemon, the lab
// PKI, and the mint clients.
type loadRun struct {
	t          *testing.T
	dir        string
	pki        *regionPKI
	etcdBin    string
	dirMembers []*regionEtcd
	sess       *regionEtcd
	broker     *regionProc
	daemon     *regionProc
	port49d    string
	brokerBin  string
	encKey     string
	tacacsKey  string
	envFile    string
	devices    int
	profile    *devicemock.Profile
	clients    []*http.Client // one per machine principal
	policyPath string
	reloads    int

	// The device PKI of the TLS cells, built when first used.
	tlsOnce sync.Once
	tlsMat  []*devicemock.TLSMaterial

	mu        sync.Mutex
	mints     []time.Duration
	mintErrs  int
	transport string // the daemon's current inventory: tcp or tls
}

func (r *loadRun) writeFile(name, body string) string {
	r.t.Helper()
	p := filepath.Join(r.dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		r.t.Fatal(err)
	}
	return p
}

// loadStoresYAML is the stores: block for role (daemon or broker): the
// directory across the members, the session store beside it.
func (r *loadRun) loadStoresYAML(role string) string {
	id, key := r.pki.daemon, r.pki.daemonKey
	if role == "broker" {
		id, key = r.pki.broker, r.pki.brokerKey
	}
	var eps []string
	for _, m := range r.dirMembers {
		eps = append(eps, "https://"+m.client)
	}
	return fmt.Sprintf("stores:\n  directory:\n    backend: etcd\n    etcd:\n      endpoints: [%s]\n      ca_file: %s\n"+
		"      %s: {cert_file: %s, key_file: %s}\n      call_timeout: %s\n"+
		"  session:\n    backend: etcd\n    etcd:\n      endpoints: [https://%s]\n      ca_file: %s\n"+
		"      %s: {cert_file: %s, key_file: %s}\n      hold_ttl: 15s\n",
		strings.Join(eps, ", "), r.pki.ca, role, id, key, loadCallTimeout, r.sess.client, r.pki.ca, role, id, key)
}

func (r *loadRun) daemonYAML(transport string) string {
	inv := filepath.Join(r.dir, "inventory-"+transport+".yaml")
	y := fmt.Sprintf(`listen: %q
metrics_listen: %q
inventory_file: %s
policy: {file: %s, watch_interval: 5s}
encryption:
  current: {id: load, secret_ref: env:LOAD_ENC_KEY}
accounting: {spool_path: %s}
`, loadTCPAddr, loadDaemonMetrics, inv, r.policyPath, filepath.Join(r.dir, "acct.jsonl"))
	if transport == "tls" {
		y += fmt.Sprintf("tls_listener:\n  listen: %q\n  cert_file: %s\n  key_file: %s\n  client_ca_file: %s\n"+
			"  server_names: [%s]\n  handshake_timeout: 10s\n  session_ticket_lifetime: 0s\n  state_dir: %s\n"+
			"  certificate_status: {disabled: true}\n",
			loadTLSAddr, filepath.Join(r.dir, "srv.crt"), filepath.Join(r.dir, "srv.key"),
			filepath.Join(r.dir, "device-ca.pem"), loadServerName, r.mkdir("tls-state"))
	}
	return y + r.loadStoresYAML("daemon")
}

func (r *loadRun) brokerYAML(transport string) string {
	inv := filepath.Join(r.dir, "inventory-"+transport+".yaml")
	return fmt.Sprintf(`metrics_listen: %q
inventory_file: %s
encryption:
  current: {id: load, secret_ref: env:LOAD_ENC_KEY}
broker:
  listen: %q
  tls_cert_file: %s
  tls_key_file: %s
  client_ca_file: %s
  policy_file: %s
  state_dir: %s
  policy_watch_interval: 5s
  certificate_status: {disabled: true}
`, loadBrokerMetrics, inv, loadBrokerAddr, filepath.Join(r.pki.lab, testpki.LabServerCert),
		filepath.Join(r.pki.lab, testpki.LabServerKey), filepath.Join(r.pki.lab, testpki.LabCA), r.policyPath,
		r.mkdir("broker-state")) + r.loadStoresYAML("broker")
}

func (r *loadRun) mkdir(name string) string {
	p := filepath.Join(r.dir, name)
	if err := os.MkdirAll(p, 0o700); err != nil {
		r.t.Fatal(err)
	}
	return p
}

// loadStack builds the run: members directory etcd members (one, or three) and
// a session etcd, the roles, port49-broker and port49d on the tcp inventory.
// Everything is removed at t's cleanup. The caller holds the lab lock.
func loadStack(t *testing.T, members int, devices int) *loadRun {
	t.Helper()
	bin := os.Getenv("PORT49_LAB_ETCD_BIN")
	if bin == "" {
		t.Fatal("INVALID: PORT49_LAB_ETCD_BIN names no directory holding etcd and etcdctl v3.6.15")
	}
	if members != 1 && members != 3 || members > len(loadDirectoryClientPorts) {
		t.Fatalf("INVALID: %d directory members; the harness runs 1 or 3", members)
	}
	if root == "" {
		t.Fatal("INVALID: the repository root is not set")
	}
	dir, err := os.MkdirTemp("", "p49load")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	r := &loadRun{t: t, dir: dir, etcdBin: bin, devices: devices, pki: newRegionPKIFor(t, loadPrincipalEmails()), transport: "tcp"}
	r.profile, err = devicemock.Load(filepath.Join(root, "tests", "qual", "profiles", loadProfile), root)
	if err != nil {
		t.Fatalf("INVALID: the load profile: %v", err)
	}
	bins := filepath.Join(dir, "bin")
	if out, err := regionBuildCmd(root, bins).CombinedOutput(); err != nil {
		t.Fatalf("INVALID: building the binaries: %v\n%s", err, out)
	}
	r.port49d, r.brokerBin = filepath.Join(bins, "port49d"), filepath.Join(bins, "port49-broker")
	r.encKey, r.tacacsKey = randomHex(t, 16), randomHex(t, 12)
	r.envFile = filepath.Join(dir, "run.env")
	if err := writeEnvFile(r.envFile, [2]string{"LOAD_ENC_KEY", r.encKey}, [2]string{"PORT49_KEY_LOAD", r.tacacsKey}); err != nil {
		t.Fatalf("INVALID: writing the run's key file: %v", err)
	}

	var initial []string
	for i := range members {
		initial = append(initial, fmt.Sprintf("d%d=http://127.0.0.1:%d", i+1, atoiPort(loadDirectoryClientPorts[i])+1))
	}
	for i := range members {
		port := atoiPort(loadDirectoryClientPorts[i])
		r.dirMembers = append(r.dirMembers, &regionEtcd{name: fmt.Sprintf("d%d", i+1), bin: bin,
			client: fmt.Sprintf("127.0.0.1:%d", port), peer: fmt.Sprintf("127.0.0.1:%d", port+1), cluster: strings.Join(initial, ","),
			data: filepath.Join(dir, fmt.Sprintf("d%d.etcd", i+1)), log: filepath.Join(dir, fmt.Sprintf("d%d.log", i+1)), pki: r.pki})
	}
	r.sess = &regionEtcd{name: "s", bin: bin, client: "127.0.0.1:12479", peer: "127.0.0.1:12480", cluster: "s=http://127.0.0.1:12480",
		data: filepath.Join(dir, "s.etcd"), log: filepath.Join(dir, "s.log"), pki: r.pki}
	all := append(slices.Clone(r.dirMembers), r.sess)
	for _, e := range all {
		e.start(t)
	}
	for _, e := range all {
		for deadline := time.Now().Add(60 * time.Second); ; time.Sleep(500 * time.Millisecond) {
			if _, err := e.ctl("https://"+e.client, "endpoint", "health"); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("INVALID: etcd %s did not answer within 60s; see %s", e.name, e.log)
			}
		}
	}

	r.policyPath = r.writeFile("policy.yaml", loadPolicy())
	r.writeFile("inventory-tcp.yaml", loadInventory(devices, "tcp"))
	r.writeFile("inventory-tls.yaml", loadInventory(devices, "tls"))
	dcfg := r.writeFile("port49d.yaml", r.daemonYAML("tcp"))
	bcfg := r.writeFile("port49-broker.yaml", r.brokerYAML("tcp"))
	sr := exec.Command(r.port49d, "store-roles", "--config", dcfg, "--broker-config", bcfg)
	sr.Env = append(os.Environ(), "LOAD_ENC_KEY="+r.encKey, "PORT49_KEY_LOAD="+r.tacacsKey)
	out, err := sr.CombinedOutput()
	if err != nil {
		t.Fatalf("INVALID: port49d store-roles: %v\n%s", err, tailOf(string(out), 1000))
	}
	d0 := r.dirMembers[0]
	applyRoles(t, string(out), map[string]func(args ...string) (string, error){
		"session":   func(args ...string) (string, error) { return r.sess.ctl("https://"+r.sess.client, args...) },
		"directory": func(args ...string) (string, error) { return d0.ctl(r.dirEndpoints(), args...) },
	})
	r.broker = &regionProc{name: "port49-broker", bin: r.brokerBin, cfg: bcfg, log: filepath.Join(dir, "broker.log"), envFile: r.envFile}
	r.daemon = &regionProc{name: "port49d", bin: r.port49d, cfg: dcfg, log: filepath.Join(dir, "port49d.log"), envFile: r.envFile}
	r.startProcs()
	t.Cleanup(r.stopProcs)

	for p := range loadPrincipals {
		cert, key := testpki.LabClientFiles(loadPrincipalEmail(p))
		c, err := tls.LoadX509KeyPair(filepath.Join(r.pki.lab, cert), filepath.Join(r.pki.lab, key))
		if err != nil {
			t.Fatalf("INVALID: %v", err)
		}
		caPEM, err := os.ReadFile(filepath.Join(r.pki.lab, testpki.LabCA))
		if err != nil {
			t.Fatalf("INVALID: %v", err)
		}
		roots := x509.NewCertPool()
		roots.AppendCertsFromPEM(caPEM)
		r.clients = append(r.clients, &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
			MaxIdleConnsPerHost: 64,
			TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{c}, RootCAs: roots, ServerName: "port49-broker",
				MinVersion: tls.VersionTLS13}}})
	}
	return r
}

func atoiPort(s string) int { n, _ := strconv.Atoi(s); return n }

func (r *loadRun) dirEndpoints() string {
	var eps []string
	for _, m := range r.dirMembers {
		eps = append(eps, "https://"+m.client)
	}
	return strings.Join(eps, ",")
}

// startProcs starts the broker, then the daemon, and waits until each listens.
func (r *loadRun) startProcs() {
	r.t.Helper()
	for _, p := range []*regionProc{r.broker, r.daemon} {
		p.start(r.t)
		if _, err := p.wait("listening on", 120*time.Second); err != nil {
			r.t.Fatalf("INVALID: %v\n%s", err, tailOf(p.said(), 2000))
		}
	}
}

func (r *loadRun) stopProcs() {
	r.daemon.stop()
	r.broker.stop()
}

// useTransport restarts the broker and the daemon on the inventory (and, for
// tls, the listener) of transport. A device record names one transport, so
// the cells of each run on their own.
func (r *loadRun) useTransport(transport string) {
	r.t.Helper()
	if r.transport == transport {
		return
	}
	if transport == "tls" {
		r.tlsPKI()
	}
	r.stopProcs()
	if err := os.WriteFile(r.daemon.cfg, []byte(r.daemonYAML(transport)), 0o600); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(r.broker.cfg, []byte(r.brokerYAML(transport)), 0o600); err != nil {
		r.t.Fatal(err)
	}
	r.startProcs()
	r.transport = transport
}

// tlsPKI issues the daemon's server certificate and one client certificate
// per device, named for it, once.
func (r *loadRun) tlsPKI() {
	r.t.Helper()
	r.tlsOnce.Do(func() {
		now := time.Now()
		ca, err := testpki.NewCA("Load Device CA", now.Add(-time.Hour), now.Add(24*time.Hour))
		if err != nil {
			r.t.Fatal(err)
		}
		srv, err := ca.Issue(testpki.Leaf{DNSNames: []string{loadServerName}, IPs: testpki.Loopback(),
			NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour)})
		if err != nil {
			r.t.Fatal(err)
		}
		certPEM, keyPEM, err := testpki.PEMs(srv)
		if err != nil {
			r.t.Fatal(err)
		}
		r.writeFile("srv.crt", string(certPEM))
		r.writeFile("srv.key", string(keyPEM))
		r.writeFile("device-ca.pem", string(ca.PEM()))
		for i := range r.devices {
			c, err := ca.Issue(testpki.Leaf{DNSNames: []string{loadDeviceName(i)}, Client: true,
				NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour)})
			if err != nil {
				r.t.Fatal(err)
			}
			r.tlsMat = append(r.tlsMat, &devicemock.TLSMaterial{Client: c, ServerCAs: ca.Pool(), ServerIP: "127.0.0.1", ServerName: loadServerName})
		}
	})
}

// mint is device i's login, minted by principal i % 50 at the broker's batch
// API, with the time the broker took. It is goroutine-safe and calls no *testing.T
// helper: it runs in the fleet's player goroutines. The token lives only in the
// Login; an error carries a status and a verdict, never a body.
func (r *loadRun) mint(i int) (devicemock.Login, time.Duration, error) {
	start := time.Now()
	out, err := r.mintBatch(i%loadPrincipals, []string{loadDeviceName(i)})
	took := time.Since(start)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err == nil && (len(out.Results) != 1 || out.Results[0].Login == "") {
		err = fmt.Errorf("mint: no login in the answer (%s)", loadItemWhy(out))
	}
	if err != nil {
		r.mintErrs++
		return devicemock.Login{}, took, err
	}
	r.mints = append(r.mints, took)
	it := out.Results[0]
	return devicemock.Login{User: it.Username, Credential: []byte(it.Login), RemAddr: "192.0.2.50"}, took, nil
}

func loadItemWhy(out api.MintResponse) string {
	if len(out.Results) == 0 {
		return "no results"
	}
	return out.Results[0].Verdict + " " + out.Results[0].Reason + " " + out.Results[0].Error
}

// mintBatch is one POST /v1/tokens for devices as principal p, decoded.
func (r *loadRun) mintBatch(p int, devices []string) (api.MintResponse, error) {
	var out api.MintResponse
	body, _ := json.Marshal(api.MintRequest{Devices: devices})
	resp, err := r.clients[p].Post("https://"+loadBrokerAddr+"/v1/tokens", "application/json", bytes.NewReader(body))
	if err != nil {
		return out, fmt.Errorf("mint: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return out, fmt.Errorf("mint: reading the answer: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("mint: status %d", resp.StatusCode)
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, errors.New("mint: an answer that is not a mint response")
	}
	return out, nil
}

// takeMints returns the mints since the last call, and the errors among them.
func (r *loadRun) takeMints() (p50, p99 time.Duration, errs int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d := r.mints
	errs = r.mintErrs
	r.mints, r.mintErrs = nil, 0
	slices.Sort(d)
	return loadPercentile(d, 50), loadPercentile(d, 99), errs
}

// loadPercentile is the nearest-rank p-th percentile of sorted.
func loadPercentile(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	return sorted[max(0, (p*len(sorted)+99)/100-1)]
}

// fleet runs the profile open loop at rate for d over transport, every device
// in turn. accountingOnly plays account_start and account_stop alone, with no mint.
func (r *loadRun) fleet(ctx context.Context, transport string, rate float64, d time.Duration, accountingOnly bool) devicemock.FleetResult {
	prof, scenario := r.profile, "token_login"
	if transport == "tls" {
		scenario = "tls_token_login"
	}
	if accountingOnly {
		cp := *r.profile
		cp.Stimulus.Steps = nil
		for _, s := range r.profile.Stimulus.Steps {
			if s.Type == "acct" {
				cp.Stimulus.Steps = append(cp.Stimulus.Steps, s)
			}
		}
		prof = &cp
	}
	target := func(i int) devicemock.Target {
		tg := devicemock.Target{Addr: loadTCPAddr, Transport: "tcp", Key: []byte(r.tacacsKey), LocalAddr: devicemock.LoopbackSource(i), Scale: 1}
		if transport == "tls" {
			tg.Addr, tg.Transport, tg.Key, tg.TLS = loadTLSAddr, "tls", nil, r.tlsMat[i]
		}
		return tg
	}
	login := func(i int) devicemock.Login {
		if accountingOnly {
			return devicemock.Login{User: "svc00", RemAddr: "192.0.2.50"}
		}
		l, _, _ := r.mint(i) // a failed mint plays a login with no credential: counted in the mint errors, and an error play
		return l
	}
	return devicemock.Fleet{Profile: prof, N: r.devices, Rate: rate, Duration: d, Scenario: scenario}.Run(ctx, target, login)
}

// loadSignal sends sig to the process whose pidfile and command-line
// arguments are given, only while /proc says it still runs those arguments.
func loadSignal(pidfile string, want []string, sig syscall.Signal) string {
	return killRecorded("/proc", pidfile, want, func(pid int) error { return syscall.Kill(pid, sig) })
}

// usage is each process's CPU seconds and peak RSS, for a cell's note.
func (r *loadRun) usage() map[string][2]float64 {
	out := map[string][2]float64{}
	pids := map[string]string{"port49d": r.daemon.pidfile(), "port49-broker": r.broker.pidfile(), "etcd_session": r.sess.pidfile()}
	for _, m := range r.dirMembers {
		pids["etcd_"+m.name] = m.pidfile()
	}
	for name, pf := range pids {
		if cpu, kb, err := loadProcUsage(pf); err == nil {
			out[name] = [2]float64{cpu, float64(kb)}
		}
	}
	return out
}

// loadNetemOn applies the netem of cell f under sudo -n and answers how to
// remove it; the removal is also run at t's cleanup.
func (r *loadRun) loadNetemOn() (undo func()) {
	r.t.Helper()
	_ = sudoRun(loadNetem(false), true) // an earlier run's
	if err := sudoRun(loadNetem(true), false); err != nil {
		_ = sudoRun(loadNetem(false), true)
		r.t.Fatalf("INVALID: netem on the directory's client ports: %v", err)
	}
	var once sync.Once
	undo = func() { once.Do(func() { _ = sudoRun(loadNetem(false), true) }) }
	r.t.Cleanup(undo)
	return undo
}
