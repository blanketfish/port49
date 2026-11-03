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
	"maps"
	"math"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
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
// loadStartWait is how long a process has to say "listening on": one
// policy.Parse at fleet size is about 70 s on the lab CPU (BenchmarkParseFleet),
// and a start runs it.
const loadStartWait = 6 * time.Minute

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
	loadSessionMetrics       = "127.0.0.1:12481" // the session etcd's /metrics, plain HTTP
	loadBrokerAddr           = "127.0.0.1:18443"
	loadServerName           = "tacacs.example.net"
	loadProfile              = "arista_eos/cEOS-lab-4.36.3M.yaml"
)

// loadDirectoryClientPorts are the three directory members' client ports,
// which the netem of cell f delays.
var loadDirectoryClientPorts = []string{"12379", "12389", "12399"}

// loadCellIDs are the cells in the order they run.
var loadCellIDs = []string{"a", "b", "c", "d", "e", "e2", "f"}

// loadCell is one cell's result: what was driven, whether it passed, and what
// was observed, as text a note can print.
type loadCell struct {
	ID        string
	Transport string
	Rate      float64
	Duration  time.Duration
	Pass      bool
	Observed  map[string]string

	// Invalid is why the cell ended INVALID; empty for a cell that ran to a verdict.
	Invalid string

	// daemonStore is the daemon's store-call histogram over the cell: what a
	// verdict gate reads, never the note's label text for it.
	daemonStore loadMetrics
	// daemonScrapes is how many of the daemon sampler's scrapes answered. A
	// delta needs two: with fewer, daemonStore is empty or zero, not measured,
	// and no gate may pass on it.
	daemonScrapes int
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
		{"tc", "qdisc", "add", "dev", "lo", "root", "handle", "1:", "prio", "bands", "3",
			"priomap", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1"},
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
	CPU      string
	Cores    int
	RAMMB    int
	Disk     string
	Kernel   string
	Host     string
	Commit   string // the tree the harness ran from, +dirty when it had changes
	RunDirFS string // the run directory's filesystem: tmpfs hides an fsync cost a disk shows

	// WALFsyncMeanMS is the session etcd's mean WAL fsync as the last cell saw it.
	WALFsyncMeanMS string
}

func readHostFacts(dir string) hostFacts {
	h := hostFacts{Cores: runtime.NumCPU()}
	h.Host, _ = os.Hostname()
	if out, err := exec.Command("git", "-C", root, "rev-parse", "HEAD").Output(); err == nil {
		h.Commit = strings.TrimSpace(string(out))
		if st, err := exec.Command("git", "-C", root, "status", "--porcelain", "--untracked-files=no").Output(); err == nil && len(strings.TrimSpace(string(st))) > 0 {
			h.Commit += "+dirty"
		}
	}
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
		h.RunDirFS = loadFSName(int64(st.Type))
	}
	return h
}

// loadFSName is the name of the filesystem a statfs magic number says.
func loadFSName(magic int64) string {
	switch magic {
	case 0x01021994:
		return "tmpfs"
	case 0xEF53:
		return "ext4"
	case 0x58465342:
		return "xfs"
	case 0x9123683E:
		return "btrfs"
	case 0x6969:
		return "nfs"
	case 0x794c7630:
		return "overlayfs"
	case 0x2fc12fc1:
		return "zfs"
	case 0xF2F52010:
		return "f2fs"
	case 0x01021997:
		return "9p"
	case 0x65735546:
		return "fuseblk"
	}
	return fmt.Sprintf("unknown_%#x", magic)
}

// loadInvalidReason is why a cell ended INVALID as note text: the first line,
// capped, or a pointer to the test log when it could hold a credential.
func loadInvalidReason(why string) string {
	why, _, _ = strings.Cut(why, "\n")
	if len(why) > 200 {
		why = why[:200]
	}
	if loadLeaky(why) {
		return "withheld: see the test log"
	}
	return why
}

// loadNote is the results note for cells. It is refused, whole, when any
// value in it could hold a credential: the check runs before a byte is printed.
func loadNote(cells []loadCell, host hostFacts) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "# Load at the design rate\n\n- **Date measured:** %s\n- **Host CPU:** %s, %d cores\n- **Host RAM:** %d MB\n"+
		"- **Host disk:** %s\n- **Host kernel:** %s\n- **Host:** %s\n- **Commit:** %s\n- **Fleet:** %d devices, %d machine principals, %d people\n"+
		"- **run_dir_fs:** %s\n- **etcd_session_wal_fsync_mean_ms:** %s\n\n"+
		"Sizing the session etcd's quota: compare `etcd_session_db_mb` (the file's total size, which the quota counts) "+
		"with 8589934592 bytes (8192 MB). `etcd_session_db_growth_mb_per_min` is the in-use size's change and is "+
		"understated when `etcd_session_compacted_during_cell` is true (a compaction freed space in the cell); "+
		"`etcd_session_revisions_per_min` is the write rate compaction cannot hide.\n\n",
		time.Now().UTC().Format("2006-01-02"), host.CPU, host.Cores, host.RAMMB, host.Disk, host.Kernel, host.Host, host.Commit,
		loadDevices, loadPrincipals, loadHumans, host.RunDirFS, host.WALFsyncMeanMS)
	for _, c := range cells {
		verdict := "PASS"
		if !c.Pass {
			verdict = "**FAIL**"
		}
		if c.Invalid != "" {
			verdict = "**INVALID**"
		}
		fmt.Fprintf(&b, "## Cell %s\n\n- **Transport:** %s\n- **Rate:** %.0f per second\n- **Duration:** %s\n- **Verdict:** %s\n",
			c.ID, c.Transport, c.Rate, c.Duration.Round(time.Second), verdict)
		if c.Invalid != "" {
			fmt.Fprintf(&b, "- **Reason:** %s\n", loadInvalidReason(c.Invalid))
		}
		b.WriteString("\n")
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
	Evicted     float64 // port49_broker_connection_events_total{event="principal_cap_evicted"}
	buckets     map[float64]float64

	// WALFsyncSum and WALFsyncCount are etcd_disk_wal_fsync_duration_seconds'
	// sum and count, on a session etcd's /metrics.
	WALFsyncSum, WALFsyncCount float64

	// DBBytes and DBInUseBytes are etcd_mvcc_db_total_size_in_bytes and
	// ..._in_use_in_bytes: the file's size, and what compaction cannot free.
	DBBytes, DBInUseBytes float64

	// Revision and CompactRevision are etcd_debugging_mvcc_current_revision and
	// ..._compact_revision (the names in etcd v3.6.15).
	Revision, CompactRevision float64

	// commitBuckets and SlowApply are etcd_disk_backend_commit_duration_seconds'
	// buckets and etcd_server_slow_apply_total (the names in etcd v3.6.15, read
	// from its binary): the bbolt commit cost on a large file, and the applies
	// etcd itself calls slow.
	commitBuckets map[float64]float64
	SlowApply     float64
}

// loadRevisionsPerMin is etcd's revision counter's climb over d, per minute: the
// write rate, which compaction cannot hide.
func loadRevisionsPerMin(start, end float64, d time.Duration) string {
	if d <= 0 {
		return "unknown"
	}
	return strconv.FormatFloat((end-start)/d.Minutes(), 'f', 0, 64)
}

// loadCompacted is whether the compacted revision moved: a compaction landed.
func loadCompacted(start, end float64) string { return strconv.FormatBool(end > start) }

// loadPartialNote is the note for a run that ended before its last cell: the
// finished cells, the cell in progress as INVALID with why, and with none in
// progress a closing line saying why the run ended. Empty when no cell finished
// and none was running.
func loadPartialNote(cells []loadCell, running *loadCell, why string, host hostFacts) (string, error) {
	if len(cells) == 0 && running == nil {
		return "", nil
	}
	all := slices.Clone(cells)
	if running != nil {
		c := *running
		c.Invalid = why
		if c.Invalid == "" {
			c.Invalid = "the test ended during the cell; see the test log"
		}
		all = append(all, c)
		why = ""
	}
	host.WALFsyncMeanMS = loadWALFact(all)
	note, err := loadNote(all, host)
	if err != nil || why == "" {
		return note, err
	}
	return note + "## Run ended\n\n- **Reason:** " + loadInvalidReason(why) + "\n", nil
}

// loadWALFact is the session etcd's mean WAL fsync as the last cell that saw it did.
func loadWALFact(cells []loadCell) string {
	fact := "unknown"
	for _, c := range cells {
		if v := c.Observed["etcd_session_wal_fsync_mean_ms"]; v != "" {
			fact = v
		}
	}
	return fact
}

// loadDBGrowthMBPerMin is the in-use database size's change over d, in MB a
// minute: the operator's sizing figure for the quota.
func loadDBGrowthMBPerMin(startInUse, endInUse float64, d time.Duration) string {
	if d <= 0 {
		return "unknown"
	}
	return strconv.FormatFloat((endInUse-startInUse)/(1<<20)/d.Minutes(), 'f', 2, 64)
}

var loadBucket = regexp.MustCompile(`le="([^"]+)"`)

func parseLoadMetrics(text string) loadMetrics {
	m := loadMetrics{buckets: map[float64]float64{}, commitBuckets: map[float64]float64{}}
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
		case strings.HasPrefix(name, "port49_broker_connection_events_total{") && strings.Contains(name, `event="principal_cap_evicted"`):
			m.Evicted += v
		case strings.HasPrefix(name, "port49_accounting_spool_drops_total"):
			m.SpoolDrops += v
		case name == "etcd_debugging_mvcc_current_revision":
			m.Revision = v
		case name == "etcd_debugging_mvcc_compact_revision":
			m.CompactRevision = v
		case name == "etcd_mvcc_db_total_size_in_bytes":
			m.DBBytes = v
		case name == "etcd_mvcc_db_total_size_in_use_in_bytes":
			m.DBInUseBytes = v
		case name == "etcd_disk_wal_fsync_duration_seconds_sum":
			m.WALFsyncSum = v
		case name == "etcd_disk_wal_fsync_duration_seconds_count":
			m.WALFsyncCount = v
		case name == "etcd_server_slow_apply_total":
			m.SlowApply = v
		case strings.HasPrefix(name, "etcd_disk_backend_commit_duration_seconds_bucket"):
			if sm := loadBucket.FindStringSubmatch(name); sm != nil {
				le := math.Inf(1)
				if sm[1] != "+Inf" {
					le, _ = strconv.ParseFloat(sm[1], 64)
				}
				m.commitBuckets[le] += v
			}
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
	out.WALFsyncSum, out.WALFsyncCount = m.WALFsyncSum-earlier.WALFsyncSum, m.WALFsyncCount-earlier.WALFsyncCount
	out.SlowApply = m.SlowApply - earlier.SlowApply
	out.buckets = map[float64]float64{}
	for le, v := range m.buckets {
		out.buckets[le] = v - earlier.buckets[le]
	}
	out.commitBuckets = map[float64]float64{}
	for le, v := range m.commitBuckets {
		out.commitBuckets[le] = v - earlier.commitBuckets[le]
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

// WALFsyncMeanMS is the mean WAL fsync in milliseconds, "unknown" with none seen.
func (m loadMetrics) WALFsyncMeanMS() string {
	if m.WALFsyncCount <= 0 {
		return "unknown"
	}
	return strconv.FormatFloat(m.WALFsyncSum/m.WALFsyncCount*1000, 'f', 2, 64)
}

// PastLastBucket is whether the q-th store call is past the last finite
// bucket: Quantile then reads that bucket's bound, which is only a lower bound.
func (m loadMetrics) PastLastBucket(q float64) bool {
	total := m.buckets[math.Inf(1)]
	if total <= 0 {
		return false
	}
	top := 0.0
	for le := range m.buckets {
		if !math.IsInf(le, 1) {
			top = math.Max(top, le)
		}
	}
	return m.buckets[top] < math.Ceil(q*total)
}

// QuantileLabel is Quantile in milliseconds, as note text: "<=<bound>" for a
// quantile in a finite bucket, and ">=<last bound>" only for one past the last
// finite bucket (+Inf), which is a lower bound. Text for the note, never a gate.
func (m loadMetrics) QuantileLabel(q float64) string {
	d := m.Quantile(q)
	if m.buckets[math.Inf(1)] <= 0 {
		return loadMS(d)
	}
	if m.PastLastBucket(q) {
		return ">=" + loadMS(d)
	}
	return "<=" + loadMS(d)
}

// BackendCommitP99 is the p99 of etcd's backend (bbolt) commit in this window,
// as note text: a stall from commit cost on a large file shows here.
func (m loadMetrics) BackendCommitP99() string {
	return loadMetrics{buckets: m.commitBuckets}.QuantileLabel(0.99)
}

var loadScrapeClient = &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}

// loadScrape reads a /metrics endpoint over plain HTTP. A status other than 200
// is an error, never an empty read: an error page parses as zero metrics. The
// client keeps no connection alive, so a scrape after a process restarted
// reads the new process.
func loadScrape(addr string) (loadMetrics, error) {
	resp, err := loadScrapeClient.Get("http://" + addr + "/metrics")
	if err != nil {
		return loadMetrics{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return loadMetrics{}, fmt.Errorf("scrape %s: status %d", addr, resp.StatusCode)
	}
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
	ok                   int // scrapes that answered; none means every peak below is unread, not zero
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
				s.ok++
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

// loadRSSSampler keeps each process's peak resident set (VmRSS) over one
// cell: a new sampler per cell, so a cell's peak is its own and not the
// process's lifetime high-water mark (VmHWM), which a heavy earlier cell sets
// for every cell after it.
type loadRSSSampler struct {
	read       func(pidfile string) (kB int, err error)
	pids       map[string]string
	stop, done chan struct{}
	mu         sync.Mutex
	peakKB     map[string]int
}

func startLoadRSSSampler(pids map[string]string, read func(string) (int, error), every time.Duration) *loadRSSSampler {
	s := &loadRSSSampler{read: read, pids: pids, stop: make(chan struct{}), done: make(chan struct{}), peakKB: map[string]int{}}
	s.sample()
	go func() {
		defer close(s.done)
		tick := time.NewTicker(every)
		defer tick.Stop()
		for {
			select {
			case <-s.stop:
				return
			case <-tick.C:
				s.sample()
			}
		}
	}()
	return s
}

func (s *loadRSSSampler) sample() {
	for name, pf := range s.pids {
		if kb, err := s.read(pf); err == nil {
			s.mu.Lock()
			s.peakKB[name] = max(s.peakKB[name], kb)
			s.mu.Unlock()
		}
	}
}

// finish samples once more, so the cell's last moment counts, and returns the
// peaks in kB by process; -1 for a process whose RSS was never read.
func (s *loadRSSSampler) finish() map[string]int {
	close(s.stop)
	<-s.done
	s.sample()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := maps.Clone(s.peakKB)
	for name := range s.pids {
		if _, ok := out[name]; !ok {
			out[name] = -1
		}
	}
	return out
}

// addRSSObserved records each process's cell peak in MB; a process whose RSS
// could not be read reads scrape_failed, never a missing key.
func addRSSObserved(obs map[string]string, peaks map[string]int) {
	for name, kb := range peaks {
		if kb < 0 {
			obs["peak_rss_mb_"+name] = loadScrapeFailed
			continue
		}
		obs["peak_rss_mb_"+name] = strconv.FormatFloat(float64(kb)/1024, 'f', 0, 64)
	}
}

// loadProcRSS is a process's resident set in kB now, by the PID in its pidfile.
func loadProcRSS(pidfile string) (int, error) {
	raw, err := os.ReadFile(pidfile)
	if err != nil {
		return 0, err
	}
	status, err := os.ReadFile("/proc/" + strings.TrimSpace(string(raw)) + "/status")
	if err != nil {
		return 0, err
	}
	for _, l := range strings.Split(string(status), "\n") {
		if fs := strings.Fields(l); len(fs) >= 2 && fs[0] == "VmRSS:" {
			return strconv.Atoi(fs[1])
		}
	}
	return 0, errors.New("no VmRSS in /proc status")
}

// addSamplerObserved records what a cell's two samplers read. A sampler that
// never got a scrape answered reads scrape_failed for every key it feeds, never
// the 0 of an unread peak.
func addSamplerObserved(obs map[string]string, dsam, bsam *loadSampler) {
	num := func(v float64) string { return strconv.FormatFloat(v, 'f', 0, 64) }
	// A peak needs one scrape; a delta (drops, a histogram's p99) needs two,
	// since one scrape is a point, not a change.
	for _, k := range []string{"peak_port49_connections", "peak_spool_depth"} {
		obs[k] = loadScrapeFailed
	}
	for _, k := range []string{"spool_drops_during", "daemon_store_call_p99_ms"} {
		obs[k] = loadScrapeFailed
	}
	if dsam.ok >= 1 {
		obs["peak_port49_connections"] = num(dsam.peakConns)
		obs["peak_spool_depth"] = num(dsam.peakDepth)
	}
	if dsam.ok >= 2 {
		obs["spool_drops_during"] = num(dsam.last.SpoolDrops - dsam.first.SpoolDrops)
		obs["daemon_store_call_p99_ms"] = dsam.last.Sub(dsam.first).QuantileLabel(0.99)
	}
	if bsam.ok < 2 {
		obs["broker_store_call_p99_ms"] = loadScrapeFailed
	} else {
		obs["broker_store_call_p99_ms"] = bsam.last.Sub(bsam.first).QuantileLabel(0.99)
	}
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
	port49Bin  string // the CLI, built from the branch beside the daemon
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

	abortMu   sync.Mutex
	aborts    []loadAbort
	abortOnce sync.Once

	mu       sync.Mutex
	mints    []time.Duration
	mintErrs int
	// mintFails are the failed mints' times, and mintBuckets their count by
	// "<status>_<reason>".
	invalidWhy  string // why the test ended INVALID, for the note (invalid)
	mintFails   []time.Duration
	mintBuckets map[string]int
	transport   string // the daemon's current inventory: tcp or tls
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

// loadCleanRunDir removes the run directory at the end of a run, unless keep
// (PORT49_LAB_LOAD_KEEP) is "1": then the processes' logs and the stores'
// data stay for a diagnosis, and the path is said. A kept directory still
// holds the run's keys (run.env, the PKI), 0700 as made; delete it when done.
// It answers the line for the test log.
func loadCleanRunDir(dir, keep string) string {
	if keep == "1" {
		return "the run directory is kept (PORT49_LAB_LOAD_KEEP=1): " + dir
	}
	if err := os.RemoveAll(dir); err != nil {
		return "the run directory was not removed: " + err.Error()
	}
	return "the run directory is removed"
}

// loadStack builds the run: members directory etcd members (one, or three) and
// a session etcd, the roles, port49-broker and port49d on the tcp inventory.
// Everything is removed at t's cleanup, unless PORT49_LAB_LOAD_KEEP=1
// (loadCleanRunDir). The caller holds the lab lock.
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
	t.Cleanup(func() { t.Log(loadCleanRunDir(dir, os.Getenv("PORT49_LAB_LOAD_KEEP"))) })
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
	r.port49d, r.brokerBin, r.port49Bin = filepath.Join(bins, "port49d"), filepath.Join(bins, "port49-broker"), filepath.Join(bins, "port49")
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
	r.sess = &regionEtcd{name: "s", bin: bin, client: "127.0.0.1:12479", peer: "127.0.0.1:12480", metrics: loadSessionMetrics, cluster: "s=http://127.0.0.1:12480",
		data: filepath.Join(dir, "s.etcd"), log: filepath.Join(dir, "s.log"), pki: r.pki}
	loadReapStaleSession(t, bin)
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

	// Record the session etcd's PID where the next run finds it, in case this
	// one is killed while the cell-d fault has the member stopped.
	if raw, err := os.ReadFile(r.sess.pidfile()); err == nil {
		_ = os.WriteFile(loadSessionPidfile(), []byte(strings.TrimSpace(string(raw))+"\n"+r.sess.data+"\n"), 0o600)
		t.Cleanup(func() { _ = os.Remove(loadSessionPidfile()) })
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
		r.clients = append(r.clients, &http.Client{Timeout: loadClientTimeout, Transport: loadBrokerTransport(&tls.Config{
			Certificates: []tls.Certificate{c}, RootCAs: roots, ServerName: "port49-broker", MinVersion: tls.VersionTLS13})})
	}
	return r
}

// loadClientTimeout is the agent's: its broker client times out at 30 s
// (internal/agent/agent.go, a.client). On one connection a burst queues, and
// the timeout includes the queue wait, so a shorter one would fail the harness
// where the agent would not.
const loadClientTimeout = 30 * time.Second

// loadBrokerTransport is a machine principal's transport to the broker. The
// real agent never opens more than one connection to the broker
// (internal/agent/agent.go, MaxConnsPerHost: 1), so a burst of forks queues on
// that one connection; the broker's per-principal cap (max_conns_per_principal,
// spec §13 decision 53 ruling 8) evicts the oldest of a fifth. A transport
// without the limit would open one connection a concurrent mint and have the
// broker evict most of them, which the shipped client never does.
func loadBrokerTransport(tlsConf *tls.Config) *http.Transport {
	return &http.Transport{MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1, TLSClientConfig: tlsConf}
}

func atoiPort(s string) int { n, _ := strconv.Atoi(s); return n }

func (r *loadRun) dirEndpoints() string {
	var eps []string
	for _, m := range r.dirMembers {
		eps = append(eps, "https://"+m.client)
	}
	return strings.Join(eps, ",")
}

// loadStartLines are the lines a process says before the load may start, by
// regionProc name. The broker listens before it opens mints: until it logs
// "policy: mints open" (internal/port49d/policyskew.go) it refuses every mint
// with 503.
var loadStartLines = map[string][]string{
	"port49-broker": {"listening on", "policy: mints open"},
	"port49d":       {"listening on"},
}

// startProcs starts the broker, then the daemon, and waits until each listens.
func (r *loadRun) startProcs() {
	r.t.Helper()
	for _, p := range []*regionProc{r.broker, r.daemon} {
		p.start(r.t)
		lines, ok := loadStartLines[p.name]
		if !ok || len(lines) == 0 {
			r.t.Fatalf("INVALID: no start lines are known for %q", p.name)
		}
		for _, want := range lines {
			if _, err := p.wait(want, loadStartWait); err != nil {
				r.invalid(err, "\n"+tailOf(p.said(), 2000))
			}
		}
	}
}

// invalid ends the test INVALID, recording err as the reason the cell in
// progress is written to the note with; detail is for the test log alone.
func (r *loadRun) invalid(err error, detail string) {
	r.t.Helper()
	r.invalidWhy = err.Error()
	r.t.Fatalf("INVALID: %v%s", err, detail)
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
	if err == nil && (len(out.Results) != 1 || out.Results[0].Login == "") {
		err = &loadMintError{status: http.StatusOK, reason: loadSafeReason(loadItemReason(out))}
	}
	r.noteMint(took, err == nil, err)
	if err != nil {
		return devicemock.Login{}, took, err
	}
	it := out.Results[0]
	return devicemock.Login{User: it.Username, Credential: []byte(it.Login), RemAddr: "192.0.2.50"}, took, nil
}

// loadMintError is a mint that failed: the HTTP status, and the reason code
// the reply's error or reason field carried. It holds no body text.
type loadMintError struct {
	status int
	reason string
}

func (e *loadMintError) Error() string {
	return fmt.Sprintf("mint: status %d (%s)", e.status, e.reason)
}

var loadReasonCode = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)

// loadSafeReason is reason when it is a snake_case code the note may print,
// "other" when it is anything else (a body that is not a reply, or a word the
// note refuses).
func loadSafeReason(reason string) string {
	if loadReasonCode.MatchString(reason) && !loadNamesCredential(reason) {
		return reason
	}
	return "other"
}

// noteMint records one mint: its time, and for a failure its status and reason.
// A failure that is not a loadMintError never reached the broker's reply.
func (r *loadRun) noteMint(took time.Duration, ok bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ok {
		r.mints = append(r.mints, took)
		return
	}
	r.mintErrs++
	r.mintFails = append(r.mintFails, took)
	key := "0_transport"
	var me *loadMintError
	if errors.As(err, &me) {
		key = fmt.Sprintf("%d_%s", me.status, loadSafeReason(me.reason))
	}
	if r.mintBuckets == nil {
		r.mintBuckets = map[string]int{}
	}
	r.mintBuckets[key]++
}

// loadItemReason is the first result's reason (or verdict with none), a code.
func loadItemReason(out api.MintResponse) string {
	if len(out.Results) == 0 {
		return "no_results"
	}
	if it := out.Results[0]; it.Reason != "" {
		return it.Reason
	} else if it.Error != "" {
		return it.Error
	} else if it.Verdict != "" {
		return it.Verdict
	}
	return "no_login"
}

// mintBatch is one POST /v1/tokens for devices as principal p, decoded.
func (r *loadRun) mintBatch(p int, devices []string) (api.MintResponse, error) {
	body, _ := json.Marshal(api.MintRequest{Devices: devices})
	resp, err := r.clients[p].Post("https://"+loadBrokerAddr+"/v1/tokens", "application/json", bytes.NewReader(body))
	if err != nil {
		return api.MintResponse{}, errors.New("mint: the request failed")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return api.MintResponse{}, errors.New("mint: reading the answer failed")
	}
	return decodeMint(resp.StatusCode, raw)
}

// decodeMint is a mint reply: a 200 as a mint response, anything else as a
// loadMintError whose reason is the reply's error code, never its detail.
func decodeMint(status int, raw []byte) (api.MintResponse, error) {
	var out api.MintResponse
	if status != http.StatusOK {
		var e api.Error
		if json.Unmarshal(raw, &e) != nil {
			return out, &loadMintError{status: status, reason: "other"}
		}
		return out, &loadMintError{status: status, reason: loadSafeReason(e.Error)}
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, &loadMintError{status: status, reason: "other"}
	}
	return out, nil
}

// loadMintStats is the mints since the last takeMints: the successful ones'
// percentiles, the failed ones' (a cell that fails every mint has no
// successful time to report), the error count, and the failures by
// "<status>_<reason>".
type loadMintStats struct {
	P50, P99, FailP50, FailP99 time.Duration
	Errs                       int
	Buckets                    map[string]int
}

// addTo puts the failure side of the stats in a cell's observed values.
func (m loadMintStats) addTo(o map[string]string) {
	o["mint_fail_p50_ms"], o["mint_fail_p99_ms"] = loadMS(m.FailP50), loadMS(m.FailP99)
	for k, n := range m.Buckets {
		o["mint_errors_"+k] = strconv.Itoa(n)
	}
}

// takeMints returns the mints since the last call, and the errors among them.
func (r *loadRun) takeMints() loadMintStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, f := r.mints, r.mintFails
	out := loadMintStats{Errs: r.mintErrs, Buckets: r.mintBuckets}
	r.mints, r.mintFails, r.mintErrs, r.mintBuckets = nil, nil, 0, nil
	slices.Sort(d)
	slices.Sort(f)
	out.P50, out.P99 = loadPercentile(d, 50), loadPercentile(d, 99)
	out.FailP50, out.FailP99 = loadPercentile(f, 50), loadPercentile(f, 99)
	return out
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

// pidfiles is each process of the stack by its note name.
func (r *loadRun) pidfiles() map[string]string {
	pids := map[string]string{"port49d": r.daemon.pidfile(), "port49-broker": r.broker.pidfile(), "etcd_session": r.sess.pidfile()}
	for _, m := range r.dirMembers {
		pids["etcd_"+m.name] = m.pidfile()
	}
	return pids
}

// usage is each process's CPU seconds and lifetime peak RSS (VmHWM); a cell's
// own RSS peak is loadRSSSampler's.
func (r *loadRun) usage() map[string][2]float64 {
	out := map[string][2]float64{}
	for name, pf := range r.pidfiles() {
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
	show, err := exec.Command("tc", "qdisc", "show", "dev", "lo").Output()
	if err != nil {
		r.invalid(fmt.Errorf("tc qdisc show dev lo: %w", err), "")
	}
	stale, err := loadNetemPlan(string(show))
	if err != nil {
		r.invalid(err, "")
	}
	if stale {
		_ = sudoRun(loadNetem(false), true) // an earlier run's, left by a timeout or a kill
	}
	if err := sudoRun(loadNetem(true), false); err != nil {
		_ = sudoRun(loadNetem(false), true)
		r.invalid(fmt.Errorf("netem on the directory's client ports: %w", err), "")
	}
	var once sync.Once
	undo = func() { once.Do(func() { _ = sudoRun(loadNetem(false), true) }) }
	r.onAbort(1, undo)
	return undo
}

// onAbort registers undo, which must be safe to call twice, to run at t's
// cleanup, on SIGINT or SIGTERM, and 30 s before the test binary's -timeout
// would panic (a panic runs no cleanup), so a netem qdisc or a stopped etcd is
// not left behind by an aborted run. One handler runs every undo in order
// (lowest first: netem 1, then the continue 2) and only then re-raises the
// signal, so no undo races another to the exit.
func (r *loadRun) onAbort(order int, undo func()) {
	r.abortMu.Lock()
	defer r.abortMu.Unlock()
	r.aborts = append(r.aborts, loadAbort{order, undo})
	slices.SortStableFunc(r.aborts, func(a, b loadAbort) int { return a.order - b.order })
	r.t.Cleanup(r.runAborts)
	r.abortOnce.Do(func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		var timer *time.Timer
		if dl, ok := r.t.Deadline(); ok {
			timer = time.AfterFunc(time.Until(dl)-30*time.Second, r.runAborts)
		}
		stop := make(chan struct{})
		go func() {
			select {
			case s := <-sig:
				r.runAborts()
				signal.Reset(syscall.SIGINT, syscall.SIGTERM)
				_ = syscall.Kill(os.Getpid(), s.(syscall.Signal))
			case <-stop:
			}
		}()
		r.t.Cleanup(func() {
			signal.Stop(sig)
			close(stop)
			if timer != nil {
				timer.Stop()
			}
		})
	})
}

type loadAbort struct {
	order int
	undo  func()
}

// runAborts runs every registered undo, in order.
func (r *loadRun) runAborts() {
	r.abortMu.Lock()
	aborts := slices.Clone(r.aborts)
	r.abortMu.Unlock()
	for _, a := range aborts {
		a.undo()
	}
}

// loadStopOnSentinel is ctx, cancelled within every of check's polls that
// fails: the lab's STOP sentinel or its disk floor (labGuardAt). stopped ends
// the poller and answers the error that cancelled the run, nil when none did.
func loadStopOnSentinel(ctx context.Context, check func() error, every time.Duration) (context.Context, func() error) {
	ctx, cancel := context.WithCancel(ctx)
	var (
		mu       sync.Mutex
		why      error
		stop     = make(chan struct{})
		done     = make(chan struct{})
		stopOnce sync.Once
	)
	go func() {
		defer close(done)
		tick := time.NewTicker(every)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ctx.Done():
				return
			case <-tick.C:
				if err := check(); err != nil {
					mu.Lock()
					why = err
					mu.Unlock()
					cancel()
					return
				}
			}
		}
	}()
	return ctx, func() error {
		stopOnce.Do(func() { close(stop) })
		<-done
		cancel()
		mu.Lock()
		defer mu.Unlock()
		return why
	}
}

// loadAwaitSwaps waits, for each named process at once, for the swap it
// should say, and answers what each took in seconds, or "no swap seen". ok is
// whether every process swapped.
func loadAwaitSwaps(waits map[string]func() (time.Duration, error)) (obs map[string]string, ok bool) {
	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	obs, ok = map[string]string{}, true
	for name, wait := range waits {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d, err := wait()
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				obs[name+"_reload"] = "no swap seen"
				ok = false
				return
			}
			obs[name+"_reload_seconds"] = strconv.FormatFloat(d.Seconds(), 'f', 1, 64)
		}()
	}
	wg.Wait()
	return obs, ok
}

// loadNetemPlan reads `tc qdisc show dev lo`: remove is whether it holds what
// an earlier run of this harness left, the prio qdisc (handle 1:) with its
// netem child (30: on parent 1:3, the loadNetemDelay), which the pre-clean may
// delete. Any other root qdisc, or a prio 1: without that child, is somebody
// else's: an error.
func loadNetemPlan(show string) (remove bool, err error) {
	var prio, child bool
	for _, l := range strings.Split(show, "\n") {
		f := strings.Fields(l)
		if len(f) < 3 || f[0] != "qdisc" {
			continue
		}
		switch {
		case f[1] == "prio" && f[2] == "1:":
			prio = true
		case f[1] == "netem" && f[2] == "30:" && slices.Contains(f, "1:3") && slices.Contains(f, "delay") && slices.Contains(f, loadNetemDelay):
			child = true
		case f[1] == "noqueue" || slices.Contains(f, "parent"):
		default:
			return false, fmt.Errorf("lo has a root qdisc this harness did not install (%s %s); refusing to replace it", f[1], f[2])
		}
	}
	if prio && !child {
		return false, errors.New("lo has a prio 1: qdisc without this harness's netem child; refusing to remove it")
	}
	return prio, nil
}

// loadFaultInWindow is whether cell d's fault, the session store stopped at
// stop and continued at cont, fell wholly inside the fleet's run, which ended
// at end. A fault that never happened, never ended or ended after the fleet
// measured nothing.
func loadFaultInWindow(stop, cont, end time.Time) bool {
	return !stop.IsZero() && !cont.IsZero() && cont.Before(end)
}

// loadStaleSession decides whether a session etcd that a killed run left (it
// may be stopped) is to be reaped. pidfile holds the PID and, on the next
// line, the run's own --data-dir. Both must still hold: /proc/<pid>/exe,
// resolved, is the etcd binary, and /proc/<pid>/cmdline carries that exact
// --data-dir (other lab harnesses run the same binary). Anything else is left
// alone, and why says so.
func loadStaleSession(pidfile, procRoot, wantExe string) (pid int, reap bool, why string) {
	raw, err := os.ReadFile(pidfile)
	if err != nil {
		return 0, false, "no pidfile"
	}
	first, dataDir, _ := strings.Cut(strings.TrimSpace(string(raw)), "\n")
	dataDir = strings.TrimSpace(dataDir)
	pid, err = strconv.Atoi(strings.TrimSpace(first))
	if err != nil || pid <= 1 || dataDir == "" {
		return 0, false, "the pidfile holds no PID and data directory"
	}
	exe, err := filepath.EvalSymlinks(filepath.Join(procRoot, strconv.Itoa(pid), "exe"))
	if err != nil {
		return pid, false, fmt.Sprintf("pid %d is gone", pid)
	}
	want, err := filepath.EvalSymlinks(wantExe)
	if err != nil || exe != want {
		return pid, false, fmt.Sprintf("pid %d no longer runs the etcd binary", pid)
	}
	cmdline, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cmdline"))
	if err != nil || !cmdlineHasArgs(cmdline, "--data-dir", dataDir) {
		return pid, false, fmt.Sprintf("pid %d runs the etcd binary on another data directory", pid)
	}
	return pid, true, ""
}

// loadSessionPidfile is where the harness records the session etcd it starts,
// outside the run's own directory, so a run that was killed leaves it for the
// next run to find.
func loadSessionPidfile() string {
	dir := filepath.Join(os.TempDir(), "port49-load")
	_ = os.MkdirAll(dir, 0o700)
	return filepath.Join(dir, "session-etcd.pid")
}

// loadReapStaleSession continues and kills the session etcd a killed run left,
// by the PID recorded for it and only while it still runs the etcd binary.
func loadReapStaleSession(t testing.TB, etcdBin string) {
	t.Helper()
	pidfile := loadSessionPidfile()
	pid, reap, why := loadStaleSession(pidfile, "/proc", filepath.Join(etcdBin, "etcd"))
	if reap {
		t.Logf("reaping the session etcd an earlier run left (pid %d)", pid)
		_ = syscall.Kill(pid, syscall.SIGCONT)
		_ = syscall.Kill(pid, syscall.SIGKILL)
	} else if why != "no pidfile" {
		t.Logf("the earlier run's session etcd record is stale: %s", why)
	}
	_ = os.Remove(pidfile)
}
