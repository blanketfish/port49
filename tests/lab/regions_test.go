//go:build lab

package lab

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

	"github.com/blanketfish/port49/internal/broker/api"
	"github.com/blanketfish/port49/internal/tacacs/wire"
	"github.com/blanketfish/port49/internal/testpki"
)

// The three-region lab (plan 11a; spec §15 L74, L75): three network
// namespaces on a host bridge, tc netem on each region's link, a directory
// etcd stretched one member per region, and in each region a session etcd,
// a port49-broker and a port49d. The TACACS+ client is the harness.
const (
	regionBridge        = "p49rbr0"
	regionHostIP        = "10.149.0.1"
	regionDelay         = "20ms"
	regionSessionClient = "127.0.0.1:2479" // each namespace's own loopback
	regionSessionPeer   = "127.0.0.1:2480"
	regionDevice        = "l74-client"
)

func regionNS(i int) string { return fmt.Sprintf("p49r%d", i) }

// regionOncall is the person who revokes and lifts: the rights are in
// regionPolicy, the touch key is a software one (admin_api_test.go).
const regionOncall = "oncall@example.com"

func regionIP(i int) string { return fmt.Sprintf("10.149.0.%d", 10+i) }

// inNetns is argv run as root in namespace ns (the caller adds sudo -n).
func inNetns(ns string, argv ...string) []string {
	return append([]string{"ip", "netns", "exec", ns}, argv...)
}

// regionNetUp is every command that builds the network, in order, each run
// under sudo -n.
func regionNetUp() [][]string {
	cmds := [][]string{
		{"ip", "link", "add", regionBridge, "type", "bridge"},
		{"ip", "addr", "add", regionHostIP + "/24", "dev", regionBridge},
		{"ip", "link", "set", regionBridge, "up"},
	}
	for i := 1; i <= 3; i++ {
		ns, host, peer := regionNS(i), regionNS(i)+"h", regionNS(i)+"n"
		cmds = append(cmds,
			[]string{"ip", "netns", "add", ns},
			[]string{"ip", "link", "add", host, "type", "veth", "peer", "name", peer},
			[]string{"ip", "link", "set", host, "master", regionBridge},
			[]string{"ip", "link", "set", host, "up"},
			[]string{"ip", "link", "set", peer, "netns", ns},
			inNetns(ns, "ip", "addr", "add", regionIP(i)+"/24", "dev", peer),
			inNetns(ns, "ip", "link", "set", peer, "up"),
			inNetns(ns, "ip", "link", "set", "lo", "up"),
			inNetns(ns, "tc", "qdisc", "add", "dev", peer, "root", "netem", "delay", regionDelay),
		)
	}
	return cmds
}

// regionNetDown removes the network; each is run and its error ignored, so
// what an interrupted run left is removed too.
func regionNetDown() [][]string {
	var cmds [][]string
	for i := 1; i <= 3; i++ {
		cmds = append(cmds, []string{"ip", "netns", "del", regionNS(i)})
	}
	// A namespace that still held a process when it was deleted leaves the
	// host side of its veth behind; the next run's `ip link add` would fail.
	for i := 1; i <= 3; i++ {
		cmds = append(cmds, []string{"ip", "link", "del", regionNS(i) + "h"})
	}
	return append(cmds, []string{"ip", "link", "del", regionBridge})
}

// regionCut is the iptables rules in region i's namespace that drop its
// traffic with the other two regions, added (-I) or removed (-D). The host
// still reaches it.
func regionCut(i int, add bool) [][]string {
	op := "-D"
	if add {
		op = "-I"
	}
	var cmds [][]string
	for j := 1; j <= 3; j++ {
		if j == i {
			continue
		}
		cmds = append(cmds,
			[]string{"ip", "netns", "exec", regionNS(i), "iptables", op, "OUTPUT", "-d", regionIP(j), "-j", "DROP"},
			[]string{"ip", "netns", "exec", regionNS(i), "iptables", op, "INPUT", "-s", regionIP(j), "-j", "DROP"})
	}
	return cmds
}

// regionHold is the iptables rules in region i's namespace that drop the
// clients there (the broker, port49d) from each directory member's client
// port, added (-I) or removed (-D). Peer traffic (2380) and the host's reads
// are untouched. Holding a process away from etcd by the network, never by a
// signal: sudo stops itself when its command is stopped.
func regionHold(i int, add bool) [][]string {
	op := "-D"
	if add {
		op = "-I"
	}
	var cmds [][]string
	for j := 1; j <= 3; j++ {
		cmds = append(cmds, []string{"ip", "netns", "exec", regionNS(i), "iptables", op, "OUTPUT",
			"-p", "tcp", "-d", regionIP(j), "--dport", "2379", "-j", "DROP"})
	}
	return cmds
}

// sudoRun runs each command under sudo -n, stopping at the first error
// unless keepGoing.
func sudoRun(cmds [][]string, keepGoing bool) error {
	for _, c := range cmds {
		out, err := exec.Command("sudo", append([]string{"-n"}, c...)...).CombinedOutput()
		if err != nil && !keepGoing {
			return fmt.Errorf("sudo %s: %v: %s", strings.Join(c, " "), err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// sudoRunAll runs every command under sudo -n, whatever an earlier one did,
// and joins the failures: a release that stops at the first would leave the
// later rules in place.
func sudoRunAll(cmds [][]string) error {
	return runAll(cmds, func(c []string) error { return sudoRun([][]string{c}, false) })
}

func runAll(cmds [][]string, run func([]string) error) error {
	var errs []error
	for _, c := range cmds {
		if err := run(c); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// inNS is argv run in namespace ns as this user, with env: sudo resets the
// environment, so env carries it.
func inNS(ns string, env []string, argv ...string) []string {
	out := []string{"sudo", "-n", "ip", "netns", "exec", ns, "sudo", "-n", "-u", os.Getenv("USER"), "--", "env"}
	return append(append(out, env...), argv...)
}

// regionPKI is the lab's etcd CA and certificates, and the brokers' lab PKI
// (testpki.WriteLab: the API's server certificate, the lab client's).
type regionPKI struct {
	dir, ca, server, serverKey, root, rootKey string
	daemon, daemonKey, broker, brokerKey      string
	lab                                       string
}

func newRegionPKI(t *testing.T) *regionPKI { return newRegionPKIFor(t, []string{regionOncall}) }

// newRegionPKIFor is newRegionPKI with the lab client certificates of others
// (testpki.LabClientFiles) beside alice's: the load run's machine principals.
func newRegionPKIFor(t *testing.T, others []string) *regionPKI {
	t.Helper()
	p := &regionPKI{dir: t.TempDir(), lab: t.TempDir()}
	now := time.Now()
	ca, err := testpki.NewCA("L74 etcd CA", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, body []byte) string {
		path := filepath.Join(p.dir, name)
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	p.ca = write("ca.pem", ca.PEM())
	issue := func(leaf testpki.Leaf, name string) (string, string) {
		leaf.NotBefore, leaf.NotAfter = now.Add(-time.Hour), now.Add(24*time.Hour)
		c, err := ca.Issue(leaf)
		if err != nil {
			t.Fatal(err)
		}
		cp, kp, err := testpki.PEMs(c)
		if err != nil {
			t.Fatal(err)
		}
		return write(name+".pem", cp), write(name+"-key.pem", kp)
	}
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP(regionHostIP)}
	for i := 1; i <= 3; i++ {
		ips = append(ips, net.ParseIP(regionIP(i)))
	}
	p.server, p.serverKey = issue(testpki.Leaf{CommonName: "etcd", IPs: ips, NoExtKeyUsage: true}, "server")
	p.root, p.rootKey = issue(testpki.Leaf{CommonName: "root", Client: true}, "root")
	p.daemon, p.daemonKey = issue(testpki.Leaf{CommonName: "port49-daemon", Client: true}, "port49-daemon")
	p.broker, p.brokerKey = issue(testpki.Leaf{CommonName: "port49-broker", Client: true}, "port49-broker")
	// The brokers answer on their regions' addresses, so the server certificate
	// names them; the on-call is the second person (regionOncall).
	var brokerIPs []net.IP
	for i := 1; i <= 3; i++ {
		brokerIPs = append(brokerIPs, net.ParseIP(regionIP(i)))
	}
	if err := testpki.WriteLabAt(p.lab, "alice@example.com", others, brokerIPs, now); err != nil {
		t.Fatal(err)
	}
	return p
}

// regionEtcd is one etcd member, in namespace ns ("" for the host).
type regionEtcd struct {
	ns, name, bin string
	client, peer  string // host:port
	metrics       string // host:port of a plain-HTTP /metrics listener; empty is none
	cluster       string // --initial-cluster
	data, log     string
	pki           *regionPKI
	cmd           *exec.Cmd
	done          chan struct{}
}

func (e *regionEtcd) argv() []string {
	a := []string{filepath.Join(e.bin, "etcd"), "--name", e.name, "--data-dir", e.data,
		"--listen-client-urls", "https://" + e.client, "--advertise-client-urls", "https://" + e.client,
		"--listen-peer-urls", "http://" + e.peer, "--initial-advertise-peer-urls", "http://" + e.peer,
		"--initial-cluster", e.cluster, "--initial-cluster-state", "new",
		"--cert-file", e.pki.server, "--key-file", e.pki.serverKey, "--trusted-ca-file", e.pki.ca, "--client-cert-auth"}
	if e.metrics != "" {
		a = append(a, "--listen-metrics-urls", "http://"+e.metrics)
	}
	a = pidWrap(e.pidfile(), "", a)
	if e.ns != "" {
		return inNS(e.ns, nil, a...)
	}
	return a
}

// pidfile holds the member's real PID, written by the command that execs it.
func (e *regionEtcd) pidfile() string { return e.data + ".pid" }

func (e *regionEtcd) start(t *testing.T) {
	t.Helper()
	lf, err := os.Create(e.log)
	if err != nil {
		t.Fatal(err)
	}
	a := e.argv()
	e.cmd = exec.Command(a[0], a[1:]...)
	e.cmd.Stdout, e.cmd.Stderr = lf, lf
	if err := e.cmd.Start(); err != nil {
		lf.Close()
		t.Fatalf("INVALID: starting etcd %s: %v", e.name, err)
	}
	e.done = make(chan struct{})
	go func() { e.cmd.Wait(); lf.Close(); close(e.done) }()
	t.Cleanup(e.stop)
}

// stop ends the member by its recorded PID (stopRecorded): SIGTERM, then
// SIGKILL past the grace period, each only while /proc/<pid>/cmdline still
// names this member's data directory. Nothing is ever ended by a pattern.
func (e *regionEtcd) stop() {
	if e.cmd == nil || e.cmd.Process == nil {
		return
	}
	stopRecorded(e.name, e.done, e.pidfile(), "--data-dir", e.data)
	e.cmd = nil
}

// pidWrap is argv run so its real PID is recorded: sh writes its own PID to
// pidfile, sources envFile when there is one (so the run's keys never travel
// on argv, which sudo logs and /proc shows) and execs argv, so the PID is the
// program's, not sudo's. It runs as this user.
func pidWrap(pidfile, envFile string, argv []string) []string {
	const script = `echo $$ > "$0"; if [ -n "$1" ]; then set -a; . "$1"; set +a; fi; shift; exec "$@"`
	return append([]string{"sh", "-c", script, pidfile, envFile}, argv...)
}

// writeRegionEnv writes the run's two keys to a 0600 file in dir (the run's
// 0700 directory) for pidWrap to source, and answers its path. Each value is
// single-quoted, so the shell that sources the file takes it as data.
func writeRegionEnv(dir, encKey, tacacsKey string) (string, error) {
	path := filepath.Join(dir, "run.env")
	return path, writeEnvFile(path, [2]string{"L74_ENC_KEY", encKey}, [2]string{"PORT49_KEY_L74", tacacsKey})
}

// writeEnvFile writes NAME='value' lines to a 0600 file, each value single-quoted.
func writeEnvFile(path string, kv ...[2]string) error {
	var b strings.Builder
	for _, p := range kv {
		b.WriteString(p[0] + "=" + shellQuote(p[1]) + "\n")
	}
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

// cmdlineHasArgs is whether a /proc cmdline (NUL-separated) holds want as
// consecutive whole arguments.
func cmdlineHasArgs(cmdline []byte, want ...string) bool {
	args := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
	for i := 0; i+len(want) <= len(args); i++ {
		if strings.Join(args[i:i+len(want)], "\x00") == strings.Join(want, "\x00") {
			return true
		}
	}
	return false
}

// killRecorded kills the PID in pidfile through kill, once procRoot's
// <pid>/cmdline holds want. It answers why it did not, or "" when it did.
func killRecorded(procRoot, pidfile string, want []string, kill func(pid int) error) string {
	raw, err := os.ReadFile(pidfile)
	if err != nil {
		return "no pidfile: " + err.Error()
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 1 {
		return "the pidfile holds no PID"
	}
	cmdline, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return fmt.Sprintf("pid %d is gone: %v", pid, err)
	}
	if !cmdlineHasArgs(cmdline, want...) {
		return fmt.Sprintf("pid %d no longer runs %s", pid, strings.Join(want, " "))
	}
	if err := kill(pid); err != nil {
		return fmt.Sprintf("kill %d: %v", pid, err)
	}
	return ""
}

// The stop's two waits: how long a SIGTERMed process has before SIGKILL, and
// how long the run waits on a process it could not end, before it reports and
// goes on. Variables so a unit test shortens them.
var (
	stopGrace = 15 * time.Second
	stopBound = 10 * time.Second
)

// stopRecorded ends a process this harness started, by the PID its wrapper
// recorded: SIGTERM, then SIGKILL after stopGrace, each only when
// /proc/<pid>/cmdline still holds want. The program runs as this user, so no
// sudo is needed. A refusal is logged and the wait is bounded by stopBound:
// a declined stop never hangs the run.
func stopRecorded(name string, done <-chan struct{}, pidfile string, want ...string) {
	signal := func(sig syscall.Signal) string {
		return killRecorded("/proc", pidfile, want, func(pid int) error { return syscall.Kill(pid, sig) })
	}
	wait := func(d time.Duration) bool {
		select {
		case <-done:
			return true
		case <-time.After(d):
			return false
		}
	}
	if why := signal(syscall.SIGTERM); why != "" {
		fmt.Fprintf(os.Stderr, "lab: %s: not signalled: %s\n", name, why)
		if !wait(stopBound) {
			fmt.Fprintf(os.Stderr, "lab: %s: still running after %v; going on\n", name, stopBound)
		}
		return
	}
	if wait(stopGrace) {
		return
	}
	if why := signal(syscall.SIGKILL); why != "" {
		fmt.Fprintf(os.Stderr, "lab: %s: not killed after %v: %s\n", name, stopGrace, why)
	}
	if !wait(stopBound) {
		fmt.Fprintf(os.Stderr, "lab: %s: still running after SIGKILL and %v; going on\n", name, stopBound)
	}
}

// ctl is etcdctl as etcd's root at endpoints, run where the member runs.
func (e *regionEtcd) ctl(endpoints string, args ...string) (string, error) {
	return runCtl(e.argvIn(e.ns, endpoints, args...))
}

// hostCtl is ctl run on the host, not in the member's namespace: it reaches
// the member through the bridge, so a rule that drops the namespace's own
// clients (regionHold) does not drop it.
func (e *regionEtcd) hostCtl(endpoints string, args ...string) (string, error) {
	return runCtl(e.hostArgv(endpoints, args...))
}

func (e *regionEtcd) hostArgv(endpoints string, args ...string) []string {
	return e.argvIn("", endpoints, args...)
}

// argvIn is etcdctl at endpoints run in namespace ns ("" for the host).
func (e *regionEtcd) argvIn(ns, endpoints string, args ...string) []string {
	a := append([]string{filepath.Join(e.bin, "etcdctl"), "--endpoints", endpoints, "--cacert", e.pki.ca,
		"--cert", e.pki.root, "--key", e.pki.rootKey, "--dial-timeout", "3s", "--command-timeout", "5s"}, args...)
	if ns != "" {
		a = inNS(ns, nil, a...)
	}
	return a
}

func runCtl(a []string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, a[0], a[1:]...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// regionProc is port49d or port49-broker, in namespace ns ("" for the host).
type regionProc struct {
	name, ns, bin, cfg, log string
	envFile                 string // sourced by the wrapper; "" for none
	cmd                     *exec.Cmd
	done                    chan struct{}
	from                    int64 // the log's size at the last start
}

func (p *regionProc) start(t *testing.T) {
	t.Helper()
	lf, err := os.OpenFile(p.log, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := lf.Stat(); err == nil {
		p.from = fi.Size()
	}
	a := p.argv()
	p.cmd = exec.Command(a[0], a[1:]...)
	p.cmd.Stdout, p.cmd.Stderr = lf, lf
	if err := p.cmd.Start(); err != nil {
		lf.Close()
		t.Fatalf("INVALID: starting %s: %v", p.name, err)
	}
	done := make(chan struct{})
	p.done = done
	go func(cmd *exec.Cmd) { cmd.Wait(); lf.Close(); close(done) }(p.cmd)
}

// argv is the command that runs the process: the keys are in envFile, which
// the wrapper sources, so argv names the file and holds no key.
func (p *regionProc) argv() []string {
	a := pidWrap(p.pidfile(), p.envFile, []string{p.bin, "--config", p.cfg})
	if p.ns != "" {
		a = inNS(p.ns, nil, a...)
	}
	return a
}

// pidfile holds the process's real PID, written by the command that execs it.
func (p *regionProc) pidfile() string { return p.cfg + ".pid" }

// stop ends the process as etcd's member is ended (stopRecorded), by its
// recorded PID, while /proc/<pid>/cmdline still names its config.
func (p *regionProc) stop() {
	if p.cmd == nil || p.cmd.Process == nil {
		return
	}
	stopRecorded(p.name, p.done, p.pidfile(), "--config", p.cfg)
	p.cmd = nil
}

// mark moves the point `said` and `wait` read from to the log's end now.
func (p *regionProc) mark() {
	if fi, err := os.Stat(p.log); err == nil {
		p.from = fi.Size()
	}
}

// said is what the process wrote since its last start (or mark).
func (p *regionProc) said() string {
	raw, _ := os.ReadFile(p.log)
	if int64(len(raw)) < p.from {
		return ""
	}
	return string(raw[p.from:])
}

// wait is how long until the process said want since its last start, or an error past d.
func (p *regionProc) wait(want string, d time.Duration) (time.Duration, error) {
	start := time.Now()
	for !strings.Contains(p.said(), want) {
		if time.Since(start) > d {
			return d, fmt.Errorf("%s did not say %q within %v", p.name, want, d)
		}
		time.Sleep(100 * time.Millisecond)
	}
	return time.Since(start), nil
}

// regionStoresYAML is the stores: block for role (daemon or broker): the
// directory across the three regions' members, the session store at session.
// The daemon waits for the directory with no deadline (start_timeout 0), so
// a port49d started during a cut with no snapshot waits, its listeners
// closed (L74 f, its second half).
func regionStoresYAML(p *regionPKI, role, session string) string {
	id, key := p.daemon, p.daemonKey
	if role == "broker" {
		id, key = p.broker, p.brokerKey
	}
	var eps []string
	for i := 1; i <= 3; i++ {
		eps = append(eps, "https://"+regionIP(i)+":2379")
	}
	extraDir, extraSess := "", "      hold_ttl: 15s\n"
	if role == "daemon" {
		extraDir = "      start_timeout: 0\n"
	}
	return fmt.Sprintf("stores:\n  directory:\n    backend: etcd\n    etcd:\n      endpoints: [%s]\n      ca_file: %s\n"+
		"      %s: {cert_file: %s, key_file: %s}\n      call_timeout: 500ms\n%s"+
		"  session:\n    backend: etcd\n    etcd:\n      endpoints: [https://%s]\n      ca_file: %s\n"+
		"      %s: {cert_file: %s, key_file: %s}\n%s",
		strings.Join(eps, ", "), p.ca, role, id, key, extraDir, session, p.ca, role, id, key, extraSess)
}

// lastLine is s's last non-empty line.
func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

// regionClient is the harness's TACACS+ client to one port49d, from the host.
type regionClient struct {
	addr string
	key  []byte
}

func (c regionClient) exchange(typ wire.Type, body []byte) ([]byte, time.Duration, error) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", c.addr, 5*time.Second)
	if err != nil {
		return nil, time.Since(start), err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	h := wire.Header{MajorVersion: 0xc, Type: typ, SeqNo: 1, SessionID: uint32(time.Now().UnixNano()),
		Length: uint32(len(body))}
	if _, err := conn.Write(append(h.Encode(), wire.Obfuscate(h, c.key, body)...)); err != nil {
		return nil, time.Since(start), err
	}
	hb := make([]byte, wire.HeaderLen)
	if _, err := io.ReadFull(conn, hb); err != nil {
		return nil, time.Since(start), err
	}
	rh, err := wire.DecodeHeader(hb)
	if err != nil {
		return nil, time.Since(start), err
	}
	rb := make([]byte, rh.Length)
	if _, err := io.ReadFull(conn, rb); err != nil {
		return nil, time.Since(start), err
	}
	return wire.Obfuscate(rh, c.key, rb), time.Since(start), nil
}

// login is a PAP login's answer and its reply time. The token is the
// harness's, held in memory; it is never formatted into a line.
func (c regionClient) login(user, token string) (string, time.Duration, error) {
	raw, took, err := c.exchange(wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, PrivLvl: 1,
		AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte(user), Port: []byte("tty1"),
		RemAddr: []byte("192.0.2.74"), Data: []byte(token)}.Encode())
	if err != nil {
		return "", took, err
	}
	r, err := wire.DecodeAuthenReply(raw)
	if err != nil {
		return "", took, err
	}
	return regionAuthenStatus(r.Status), took, nil
}

// command is an authorization's answer and reply time: the session's with
// no words, a command's otherwise.
func (c regionClient) command(user string, words ...string) (string, time.Duration, error) {
	args, priv := [][]byte{[]byte("service=shell"), []byte("cmd=")}, uint8(1)
	if len(words) > 0 {
		args, priv = [][]byte{[]byte("service=shell"), []byte("cmd=" + words[0])}, 15
		for _, w := range words[1:] {
			args = append(args, []byte("cmd-arg="+w))
		}
		args = append(args, []byte("cmd-arg=<cr>"))
	}
	raw, took, err := c.exchange(wire.TypeAuthor, wire.AuthorRequest{AuthenMethod: wire.AuthenMethodTACACSPlus,
		PrivLvl: priv, AuthenType: wire.AuthenTypeASCII, Service: wire.AuthenServiceLogin, User: []byte(user),
		Port: []byte("tty1"), Args: args}.Encode())
	if err != nil {
		return "", took, err
	}
	r, err := wire.DecodeAuthorResponse(raw)
	if err != nil {
		return "", took, err
	}
	return regionAuthorStatus(r.Status), took, nil
}

func regionAuthenStatus(s uint8) string {
	switch s {
	case wire.AuthenStatusPass:
		return "pass"
	case wire.AuthenStatusFail:
		return "fail"
	case wire.AuthenStatusError:
		return "error"
	}
	return fmt.Sprintf("status %d", s)
}

func regionAuthorStatus(s uint8) string {
	switch s {
	case wire.AuthorStatusPassAdd, wire.AuthorStatusPassRepl:
		return "permit"
	case wire.AuthorStatusFail:
		return "deny"
	case wire.AuthorStatusError:
		return "error"
	}
	return fmt.Sprintf("status %d", s)
}

// regionMint mints alice's login token for the l74 device at a broker's
// API, with the lab client certificate. A 503 is tried again for 30s (the
// start's mint gate). The token is returned to be held in memory and
// registered with the leak check; an error never carries the body.
func regionMint(p *regionPKI, brokerAddr string) (string, error) {
	cert, err := tls.LoadX509KeyPair(filepath.Join(p.lab, testpki.LabClientCert), filepath.Join(p.lab, testpki.LabClientKey))
	if err != nil {
		return "", err
	}
	caPEM, err := os.ReadFile(filepath.Join(p.lab, testpki.LabCA))
	if err != nil {
		return "", err
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		Certificates: []tls.Certificate{cert}, RootCAs: roots, ServerName: "port49-broker", MinVersion: tls.VersionTLS13}}}
	deadline := time.Now().Add(30 * time.Second)
	for {
		resp, err := client.Post("https://"+brokerAddr+"/v1/tokens", "application/json",
			strings.NewReader(`{"devices":["`+regionDevice+`"]}`))
		if err == nil {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			var out api.MintResponse
			switch {
			case resp.StatusCode == http.StatusOK && json.Unmarshal(raw, &out) == nil && len(out.Results) == 1 &&
				out.Results[0].Login != "":
				return out.Results[0].Login, nil
			case resp.StatusCode != http.StatusServiceUnavailable:
				return "", fmt.Errorf("mint at %s: status %d", brokerAddr, resp.StatusCode)
			}
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("mint at %s: no token within 30s (%v)", brokerAddr, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// applyRoles runs each section of `port49d store-roles`' output (Task 11)
// against its cluster, and then the auth lines its last comment names, as
// etcd's root does once per cluster. A section with no cluster in ctl is
// skipped: the directory's roles are made once, by the first region's.
func applyRoles(t *testing.T, out string, ctl map[string]func(args ...string) (string, error)) []string {
	t.Helper()
	var said []string
	target, then := "directory", ""
	var cmds [][]string
	flush := func() {
		for _, part := range strings.Split(then, "&&") {
			if f := strings.Fields(part); len(f) > 1 && f[0] == "etcdctl" {
				cmds = append(cmds, f[1:])
			}
		}
		if run := ctl[target]; run != nil {
			for _, c := range cmds {
				got, err := run(c...)
				said = append(said, fmt.Sprintf("%s: `etcdctl %s`: %s", target, strings.Join(c, " "), firstLine(got)))
				if err != nil {
					t.Fatalf("INVALID: etcdctl %s on the %s store, as store-roles printed it: %v\n%s",
						strings.Join(c, " "), target, err, got)
				}
			}
		}
		cmds, then = nil, ""
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "# port49 roles for the directory store"):
			flush()
			target = "directory"
		case strings.HasPrefix(line, "# port49 roles for the session store"):
			flush()
			target = "session"
		case strings.HasPrefix(line, "etcdctl "):
			cmds = append(cmds, strings.Fields(line)[1:])
		case strings.HasPrefix(line, "# then, if auth is not enabled yet:"):
			then = strings.TrimPrefix(line, "# then, if auth is not enabled yet:")
		case then != "" && strings.HasPrefix(line, "#"):
			then += " " + strings.TrimSpace(strings.TrimPrefix(line, "#"))
		}
	}
	flush()
	return said
}
