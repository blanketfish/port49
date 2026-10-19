//go:build lab

package lab

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/testpki"
)

// The split's three configs (port49d A, port49d B, port49-broker), derived
// from port49d-lab.yaml and slice/broker.yaml, load under the real config
// loader in their own roles: a daemon with no seeds and no broker: block, a
// broker with the seeds and no keys:. A run that fails here fails at its first
// start on a device, minutes into a boot.
func TestSplitConfigsLoadInTheirRoles(t *testing.T) {
	baseRaw, err := os.ReadFile("port49d-lab.yaml")
	if err != nil {
		t.Fatal(err)
	}
	sliceBroker, err := os.ReadFile(filepath.Join("slice", "broker.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	pki := filepath.Join(dir, "pki")
	if err := testpki.WriteLab(pki, sliceEmail, time.Now()); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PORT49_LAB_KEY", "labsecret")
	t.Setenv("PORT49_LAB_ENC_KEY", labEncKeyDefault)
	file := func(name string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	policy, err := os.ReadFile(filepath.Join("slice", "policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	pol := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(pol, policy, 0o600); err != nil {
		t.Fatal(err)
	}
	inv, err := os.ReadFile("inventory-lab.yaml")
	if err != nil {
		t.Fatal(err)
	}
	invPath := filepath.Join(dir, "inventory.yaml")
	if err := os.WriteFile(invPath, inv, 0o600); err != nil {
		t.Fatal(err)
	}
	ca, cert, key := file("ca.pem"), file("c.pem"), file("c-key.pem")
	daemonStore := "\nstores:\n  directory:\n    backend: etcd\n    etcd:\n      endpoints: [https://127.0.0.1:2379]\n      ca_file: " + ca +
		"\n      daemon: {cert_file: " + cert + ", key_file: " + key + "}\n      hold_ttl: 60s\n"
	brokerStore := "\nstores:\n  directory:\n    backend: etcd\n    etcd:\n      endpoints: [https://127.0.0.1:2379]\n      ca_file: " + ca +
		"\n      broker: {cert_file: " + cert + ", key_file: " + key + "}\n      hold_ttl: 60s\n"
	state := filepath.Join(dir, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}

	for name, n := range map[string]splitNode{
		"A": {Listen: tacacsAddr, Metrics: metricsAddr, Admin: filepath.Join(dir, "a.sock"), Spool: spoolPath},
		"B": {Listen: splitSecondAddr + ":49", Metrics: splitMetricsB, Admin: filepath.Join(dir, "b.sock"),
			Spool: "/tmp/port49-lab-acct-b.jsonl"},
	} {
		body, err := splitDaemonYAML(string(baseRaw), n, pol, invPath, daemonStore)
		if err != nil {
			t.Fatalf("port49d %s: %v", name, err)
		}
		p := filepath.Join(dir, "port49d-"+name+".yaml")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Load(p)
		if err != nil {
			t.Fatalf("port49d %s's config does not load: %v\n%s", name, err, body)
		}
		if cfg.Listen != n.Listen || cfg.MetricsListen != n.Metrics || cfg.AdminSocket != n.Admin ||
			cfg.Accounting.SpoolPath != n.Spool {
			t.Errorf("port49d %s: listen %q, metrics %q, admin %q, spool %q; want %+v", name, cfg.Listen,
				cfg.MetricsListen, cfg.AdminSocket, cfg.Accounting.SpoolPath, n)
		}
		if cfg.Broker != nil || cfg.Policy == nil || cfg.Policy.File != pol {
			t.Errorf("port49d %s: broker %v, policy %v; want no broker: block and policy.file %s", name, cfg.Broker,
				cfg.Policy, pol)
		}
		if cfg.Lab == nil || len(cfg.Lab.SeedTokens) != 0 || len(cfg.Lab.SessionAttributes) == 0 {
			t.Errorf("port49d %s: lab %+v; want the lab's answers and no seeds", name, cfg.Lab)
		}
	}

	body, err := splitBrokerYAML(string(baseRaw), string(sliceBroker), splitBrokerOpts{Policy: pol, Inventory: invPath,
		State: state, Metrics: splitMetricsBroker, Admin: filepath.Join(dir, "broker.sock"), Store: brokerStore,
		PKI: pki})
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "port49-broker.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadBroker(p)
	if err != nil {
		t.Fatalf("the broker's config does not load: %v\n%s", err, body)
	}
	if cfg.Broker == nil || cfg.Broker.PolicyFile != pol || cfg.Broker.StateDir != state || cfg.Broker.RevocationsFile != "" {
		t.Errorf("the broker block: %+v", cfg.Broker)
	}
	if cfg.Lab == nil || cfg.Lab.SeedTokenFile != "/tmp/port49-lab-tokens.jsonl" || len(cfg.Lab.SeedTokens) < 100 {
		t.Errorf("the broker's lab block: %+v; want the lab's seeds and their file", cfg.Lab)
	}
	if !strings.Contains(body, filepath.Join(pki, testpki.LabServerCert)) {
		t.Errorf("the broker's certificate is not under the PKI directory %s", pki)
	}
}

func TestSplitDaemonYAMLRefusesABaseItCannotDerive(t *testing.T) {
	n := splitNode{Listen: "x:49", Metrics: "m", Admin: "a", Spool: "s"}
	if _, err := splitDaemonYAML("listen: other\n", n, "p", "i", "\nstores: {}\n"); err == nil {
		t.Fatal("a base with none of the lines to swap was derived from without an error")
	}
}

// Every pushed line names the second server's address and nothing the first
// server's; the inverse names the same address and removes what the push
// added, so a failed test's cleanup leaves the device as it found it.
func TestSecondServerLines(t *testing.T) {
	for _, platform := range []string{"arista_eos", "cisco_nxos", "cisco_iosxe", "juniper_vjunos-router", "juniper_vsrx"} {
		add, del := secondServerLines(platform, true), secondServerLines(platform, false)
		if len(add) == 0 || len(del) == 0 {
			t.Fatalf("%s: %d lines to add, %d to remove", platform, len(add), len(del))
		}
		for _, ln := range add {
			if strings.Contains(ln, "172.100.100.1 ") || strings.HasSuffix(ln, "172.100.100.1") {
				t.Errorf("%s: %q names the first server", platform, ln)
			}
		}
		if got := strings.Join(add, "\n"); !strings.Contains(got, splitSecondAddr) && !strings.Contains(got, "port49-host2") {
			t.Errorf("%s: the lines to add name neither the second address nor its server: %q", platform, got)
		}
		joined := strings.Join(del, "\n")
		if !strings.Contains(joined, "no ") && !strings.Contains(joined, "delete ") {
			t.Errorf("%s: the lines to remove remove nothing: %q", platform, joined)
		}
	}
}

// synthPcap builds a capture a packet at a time, in the shape `tcpdump -i any`
// writes: little-endian microsecond pcap, LINUX_SLL2 frames.
type synthPcap struct {
	buf  []byte
	base time.Time
}

func newSynthPcap(base time.Time) *synthPcap {
	buf := make([]byte, 24)
	binary.LittleEndian.PutUint32(buf[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(buf[4:6], 2)
	binary.LittleEndian.PutUint16(buf[6:8], 4)
	binary.LittleEndian.PutUint32(buf[16:20], 262144)
	binary.LittleEndian.PutUint32(buf[20:24], 276)
	return &synthPcap{buf: buf, base: base}
}

func (s *synthPcap) seg(at time.Duration, src, dst string, sport, dport uint16, flags byte, payload int) {
	tcp := make([]byte, 20+payload)
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	tcp[12], tcp[13] = 5<<4, flags
	ip := make([]byte, 20)
	ip[0], ip[8], ip[9] = 0x45, 64, 6
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(tcp)))
	copy(ip[12:16], net.ParseIP(src).To4())
	copy(ip[16:20], net.ParseIP(dst).To4())
	sll := make([]byte, 20)
	binary.BigEndian.PutUint16(sll[0:2], 0x0800)
	pkt := append(append(sll, ip...), tcp...)
	hdr := make([]byte, 16)
	t := s.base.Add(at)
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(t.Unix()))
	binary.LittleEndian.PutUint32(hdr[4:8], uint32(t.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(len(pkt)))
	binary.LittleEndian.PutUint32(hdr[12:16], uint32(len(pkt)))
	s.buf = append(append(s.buf, hdr...), pkt...)
}

func (s *synthPcap) write(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.pcap")
	if err := os.WriteFile(p, s.buf, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A stopped A refuses the device's connection and the device then connects to
// B: the capture, not the log, says how long the device took to try B, and
// which server answered and which refused.
func TestSplitAttemptsReadsWhichServerRefusedAndWhichAnswered(t *testing.T) {
	const dev, a, b = "172.100.100.11", "172.100.100.1", "172.100.100.2"
	const syn, ack, psh, rst = 0x02, 0x10, 0x08, 0x04
	base := time.Unix(1_790_000_000, 0)
	c := newSynthPcap(base)
	// Before the window: an earlier connection to A, not read.
	c.seg(-5*time.Second, dev, a, 40000, 49, syn, 0)
	// The window opens at +0. The device tries A, which refuses, then B.
	c.seg(1*time.Second, dev, a, 40001, 49, syn, 0)
	c.seg(1*time.Second, dev, a, 40001, 49, syn, 0) // the same segment, seen on the second interface
	c.seg(1*time.Second+2*time.Millisecond, a, dev, 49, 40001, rst|ack, 0)
	c.seg(4*time.Second, dev, b, 40002, 49, syn, 0)
	c.seg(4*time.Second+3*time.Millisecond, b, dev, 49, 40002, syn|ack, 0)
	c.seg(4*time.Second+4*time.Millisecond, dev, b, 40002, 49, psh|ack, 40)
	// A device that is not this one.
	c.seg(2*time.Second, "172.100.100.41", a, 40003, 49, syn, 0)
	path := c.write(t)

	got, err := splitAttempts(path, dev, base, base.Add(10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("%d attempts, want 2 (A, then B): %+v", len(got), got)
	}
	if got[0].Server != a || got[0].At != time.Second || got[0].Outcome != "refused after 2ms" {
		t.Errorf("the first attempt: %+v", got[0])
	}
	if got[1].Server != b || got[1].At != 4*time.Second || got[1].Outcome != "accepted after 3ms" {
		t.Errorf("the second attempt: %+v", got[1])
	}
	text := renderAttempts(got)
	for _, want := range []string{"+1.00s to 172.100.100.1: refused after 2ms", "+4.00s to 172.100.100.2: accepted after 3ms"} {
		if !strings.Contains(text, want) {
			t.Errorf("%q is not in %q", want, text)
		}
	}
	syns, sent, err := splitSent(path, dev, base, base.Add(10*time.Second))
	if err != nil || syns != 2 || sent != 1 {
		t.Errorf("splitSent: %d SYNs, %d packets with a payload, %v; want 2 and 1", syns, sent, err)
	}
}

func TestDarkBoundAtTheLabsValues(t *testing.T) {
	// 5 failed pings 10s apart, hold_ttl for the open circuit, a sixth more
	// for the next call, the call's own timeout, and 5s of slack.
	if got, want := darkBound(60*time.Second, 500*time.Millisecond, 5), 125500*time.Millisecond; got != want {
		t.Fatalf("darkBound = %s, want %s", got, want)
	}
	if darkBound(15*time.Second, 500*time.Millisecond, 5) >= darkBound(60*time.Second, 500*time.Millisecond, 5) {
		t.Error("the bound does not grow with hold_ttl")
	}
}

func TestServerListedReadsTheGroupBack(t *testing.T) {
	both := map[string]string{
		"arista_eos":  "aaa group server tacacs+ port49\n   server 172.100.100.1\n   server 172.100.100.2\n",
		"cisco_nxos":  "tacacs-server host 172.100.100.1 key 7 x\ntacacs-server host 172.100.100.2 key 7 x\naaa group server tacacs+ port49\n  server 172.100.100.1\n  server 172.100.100.2\n",
		"cisco_iosxe": "tacacs server port49-host\n address ipv4 172.100.100.1\ntacacs server port49-host2\n address ipv4 172.100.100.2\naaa group server tacacs+ port49\n server name port49-host\n server name port49-host2\n",
		"juniper_vsrx": "set system tacplus-server 172.100.100.1 secret <removed>\nset system tacplus-server 172.100.100.2 secret <removed>\n" +
			"set system accounting destination tacplus server 172.100.100.2 secret <removed>\n",
	}
	one := map[string]string{
		"arista_eos":   "aaa group server tacacs+ port49\n   server 172.100.100.1\n",
		"cisco_nxos":   "tacacs-server host 172.100.100.1 key 7 x\naaa group server tacacs+ port49\n  server 172.100.100.1\n",
		"cisco_iosxe":  "tacacs server port49-host\n address ipv4 172.100.100.1\naaa group server tacacs+ port49\n server name port49-host\n",
		"juniper_vsrx": "set system tacplus-server 172.100.100.1 secret <removed>\n",
	}
	for p, rb := range both {
		if err := serverListed(p, rb, true); err != nil {
			t.Errorf("%s: both listed, add check: %v", p, err)
		}
		if err := serverListed(p, rb, false); err == nil {
			t.Errorf("%s: both listed, but the removal check passed", p)
		}
		if err := serverListed(p, one[p], true); err == nil {
			t.Errorf("%s: one listed, but the add check passed", p)
		}
		if err := serverListed(p, one[p], false); err != nil {
			t.Errorf("%s: one listed, removal check: %v", p, err)
		}
	}
	// The second server listed before the first is not the order the cells measure.
	rev := "aaa group server tacacs+ port49\n   server 172.100.100.2\n   server 172.100.100.1\n"
	if err := serverListed("arista_eos", rev, true); err == nil {
		t.Error("the second server listed first passed the add check")
	}
}

func TestRepliesWithCountsAStatusFromAServer(t *testing.T) {
	lines := []string{"AUTHOR seq 1 -> FAIL from 172.100.100.1 in 500ms", "AUTHOR seq 1 -> PASS_ADD from 172.100.100.2 in 3ms",
		"AUTHOR seq 1 unanswered"}
	if got := repliesWith(lines, "FAIL", ""); got != 1 {
		t.Errorf("FAIL from anyone: %d", got)
	}
	if got := repliesWith(lines, "PASS_ADD", "172.100.100.1"); got != 0 {
		t.Errorf("PASS_ADD from .1: %d", got)
	}
	if got := repliesWith(lines, "PASS_ADD", "172.100.100.2"); got != 1 {
		t.Errorf("PASS_ADD from .2: %d", got)
	}
}

func TestDenialBeforeAttributesASessionEnd(t *testing.T) {
	end := time.Now()
	denied := []authorReply{{At: end.Add(-5 * time.Second), Status: "FAIL"}}
	if !denialBefore(denied, end, 60*time.Second) {
		t.Error("a FAIL 5s before the end was not attributed")
	}
	if denialBefore([]authorReply{{At: end.Add(-5 * time.Second), Status: "PASS_ADD"}}, end, 60*time.Second) {
		t.Error("a PASS 5s before the end was attributed as a denial")
	}
	if denialBefore([]authorReply{{At: end.Add(-5 * time.Minute), Status: "FAIL"}}, end, 60*time.Second) {
		t.Error("a FAIL five minutes before the end was attributed")
	}
	if denialBefore([]authorReply{{At: end.Add(5 * time.Second), Status: "FAIL"}}, end, 60*time.Second) {
		t.Error("a FAIL after the end was attributed")
	}
	if !denialBefore([]authorReply{{At: end.Add(-time.Second), Status: "ERROR"}}, end, 60*time.Second) {
		t.Error("an ERROR 1s before the end was not attributed")
	}
}

func TestDarkTimesVerdictJudgesBothSpans(t *testing.T) {
	s := time.Second
	for _, c := range []struct {
		name string
		d    darkTimes
		bad  int
	}{
		{"as designed", darkTimes{Open: 50 * s, Dark: 112 * s}, 0},
		{"past the bound", darkTimes{Open: 100 * s, Dark: 170 * s}, 1},
		{"never dark", darkTimes{Open: 50 * s}, 1},
		{"dark with no circuit line", darkTimes{Dark: 100 * s}, 1},
		{"dark too soon after opening", darkTimes{Open: 50 * s, Dark: 70 * s}, 1},
	} {
		if got := c.d.verdict("port49d"); len(got) != c.bad {
			t.Errorf("%s: %d findings %v, want %d", c.name, len(got), got, c.bad)
		}
	}
}

func TestGuardClosedRefusesAClosedEntryWithANote(t *testing.T) {
	r, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	defer func(was string) { root = was }(root)
	root = r
	// A synthetic spec: one closed row, one open row.
	spec := "| **L7** | claim | doc | all | closed — measured 2026-10-04; notes |\n" +
		"| **L8** | claim | doc | all | open — added 2026-10-04 |\n"
	if !registerRowClosed(spec, "L7") || !registerRowClosed(spec, "L7-restore") {
		t.Error("L7 (and its restore run) is closed and must be refused")
	}
	if registerRowClosed(spec, "L8") {
		t.Error("L8 is open and must be written")
	}
	if registerRowClosed(spec, "login") || registerRowClosed(spec, "L999") {
		t.Error("an entry with no row is not closed")
	}
	// The real spec: L35 is closed, with notes.
	raw, err := os.ReadFile(filepath.Join(root, "docs", "design", "2026-08-23-policy-engine-spec.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !registerRowClosed(string(raw), "L35") {
		t.Error("L35 is closed in the spec")
	}
	// The guard itself: L35 with a note is refused unless named; an entry with no row passes.
	l := &lab{p: platform{name: "arista_eos"}}
	if _, err := os.Stat(filepath.Join(root, "tests", "lab", "results", "L35-arista_eos.md")); err != nil {
		t.Fatalf("the closed L35 note is not there to guard: %v", err)
	}
	for _, c := range []struct {
		entry, remeasure string
		refused          bool
	}{{"L35", "", true}, {"L35", "L35", false}, {"login", "", false}, {"L35", "L53,L35", false},
		{"L35", "L350", true}} {
		t.Setenv("PORT49_LAB_REMEASURE", c.remeasure)
		if got := l.guardRefusal(c.entry) != ""; got != c.refused {
			t.Errorf("%s with REMEASURE=%q: refused %v, want %v", c.entry, c.remeasure, got, c.refused)
		}
	}
}
