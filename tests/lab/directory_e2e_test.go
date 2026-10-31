//go:build lab

package lab

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/testpki"
)

// A directory login end to end on the compose stack (plan 7g, Task 18): the
// broker resolves people and their groups from OpenLDAP, a real EOS or vJunos
// device is the other end. It is not a register row: what a device does with
// each answer is measured already (L4, L35, L41). It checks three things on
// real images: a login granted through a nested group, a removal reaching the
// open session, and an outage served from grace until the staleness ceiling and
// resumed when the directory returns.
const e2eClaim = "A person whose certificate maps to a directory entry is granted through a nested group " +
	"(alice ∈ g-leaf ∈ g-mid ∈ netops-oncall) and logs in to the device with the token the broker minted; " +
	"a member removed from the chain loses the open session at the broker's next scheduled refresh; " +
	"with the directory down, the broker mints from the stored membership within directory.grace and the " +
	"open session's commands are permitted until session.staleness_ceiling, then denied context_stale; " +
	"when the directory returns the scheduled refresh stamps the context and the same session resumes; " +
	"a broker restarted during the outage still mints for a principal it has stored, and refuses " +
	"one it has never verified directory_unavailable (plan 7g Task 18; policy engine spec §14)."

// The lab's timing (the brief's values, verbatim).
const (
	e2eRefreshInterval = time.Minute
	e2eCeiling         = 3 * time.Minute
	e2eGrace           = 3 * time.Minute
	// A directory server whose breaker opened is tried again only by the health
	// check, every circuit_breaker.probe_interval (default 1m, spec §13), so the
	// first scheduled pass that can reach it is the one after the probe: the
	// brief's refresh_interval + 30s bound left the probe out (run 4 of Task 18
	// measured 2m10s).
	e2eProbeInterval = time.Minute
	e2eRecoveryBound = e2eRefreshInterval + e2eProbeInterval + 30*time.Second /* health_check.interval: the probe waits for a tick */ + 30*time.Second
	// e2eDirDir is where the broker container sees the directory's files
	// (tests/lab/compose/directory.yaml's directory-pki volume).
	e2eDirDir = "/etc/port49-directory"

	e2eUser     = "alice"
	e2eAlice    = "user:alice@corp.example.com"
	e2eBob      = "user:bob@corp.example.com"
	e2eLDAPBase = "dc=corp,dc=example,dc=com"
)

// e2ePolicy is the lab policy: the netops-oncall group, granted
// network_admin on every device, and bob as an identity subject with no
// username (the directory supplies it).
const e2ePolicy = `# The directory end-to-end lab's policy (plan 7g, Task 18).
scopes:
  - {name: all_devices, match: {}}
roles:
  - {name: network_admin, privilege: admin, permit: ["**"]}
subjects:
  - {name: netops_oncall, group: netops-oncall, token_ttl: 15m}
  - {name: bob, identity: ["user:bob@corp.example.com"], token_ttl: 15m}
grants:
  - {subject: netops_oncall, scope: all_devices, roles: [network_admin]}
  - {subject: bob, scope: all_devices, roles: [network_admin]}
# The device key set the inventory's key group names (decision 53 ruling 3); the secret is the file
# setup places in the port49d-keys volume (composeDeviceKeyPath).
keys:
  lab_key:
    current: {version: 1, secret_ref: file:` + composeDeviceKeyPath + `}
`

// e2eDirectoryBlock is the broker's refresh_interval and broker.directory:
// block, indented under broker:, with the directory's files read from dir.
func e2eDirectoryBlock(dir string) string {
	return fmt.Sprintf(`  refresh_interval: %s
  directory:
    servers:
      - {uri: "ldaps://openldap:636", priority: 100, site: lab}
    site: lab
    ca_file: %[2]s/directory-ca.pem
    bind:
      mechanism: external
      tls_cert_file: %[2]s/directory-client.pem
      tls_key_file: %[2]s/directory-client-key.pem
    base_dn: %[3]s
    groups_base_dn: ou=G,%[3]s
    user_filter: "(objectClass=inetOrgPerson)"
    group_filter: "(objectClass=groupOfNames)"
    principal_attribute: mail
    username_attribute: uid
    certificate_mapping:
      kind: san_email
      allow_weak: true
      issuers: ["%[4]s"]
    nested_groups: recursive
    grace: %[5]s
    prewarm: {interval: 5m}
`, e2eRefreshInterval, dir, e2eLDAPBase, dirUsersCAIssuer, e2eGrace)
}

// e2eBrokerYAML adds the directory to port49-broker.yaml (as composeLabFiles
// derived it) and trusts the users CA, not the slice's, for client
// certificates: alice's is issued by it.
func e2eBrokerYAML(broker, dir string) (string, error) {
	out, err := swapLine(broker, "  client_ca_file: /etc/port49/broker/broker-ca.pem",
		"  client_ca_file: "+dir+"/users-ca.pem")
	if err != nil {
		return "", err
	}
	const state = "  state_dir: /var/lib/port49-broker\n"
	return swapLine(out, state, e2eDirectoryBlock(dir)+state)
}

// e2eDaemonYAML sets port49d's staleness ceiling to the lab's.
func e2eDaemonYAML(daemon string) (string, error) {
	return swapLine(daemon, "  staleness_ceiling: 0s", "  staleness_ceiling: "+e2eCeiling.String())
}

// e2eFiles is composeOptions.Files: the directory's policy, broker block and
// ceiling over composeLabFiles'.
func e2eFiles(files map[string]string) error {
	files["policy.yaml"] = e2ePolicy
	var err error
	if files["port49-broker.yaml"], err = e2eBrokerYAML(files["port49-broker.yaml"], e2eDirDir); err != nil {
		return err
	}
	files["port49d.yaml"], err = e2eDaemonYAML(files["port49d.yaml"])
	return err
}

// The agents' certificates, under the slice PKI directory personAgent reads.
const (
	e2eAliceCert = "client-dir-alice.pem"
	e2eAliceKey  = "client-dir-alice-key.pem"
	e2eBobCert   = "client-dir-bob.pem"
	e2eBobKey    = "client-dir-bob-key.pem"
)

// e2ePrepare is composeOptions.Prepare: the directory lab's PKI and passwords,
// written under c.local for the overlay, and alice's and bob's certificates
// (issued by the users CA) under the slice PKI directory for the agents.
func e2ePrepare(c *composeStack) error {
	dir := filepath.Join(c.local, "directory")
	for _, d := range []string{"pki", "openldap-pki", "broker"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			return err
		}
	}
	now := time.Now()
	p, err := writeDirectoryPKI(filepath.Join(dir, "pki"), now)
	if err != nil {
		return fmt.Errorf("the directory's PKI: %w", err)
	}
	copyFile := func(from, to string) error {
		b, err := os.ReadFile(from)
		if err != nil {
			return err
		}
		return os.WriteFile(to, b, 0o600)
	}
	for _, f := range []string{"ca.pem", "server.pem", "server-key.pem"} {
		if err := copyFile(filepath.Join(dir, "pki", f), filepath.Join(dir, "openldap-pki", f)); err != nil {
			return err
		}
	}
	usersCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.usersCA.Raw})
	for to, from := range map[string]string{"directory-ca.pem": "ca.pem", "directory-client.pem": "broker.pem",
		"directory-client-key.pem": "broker-key.pem"} {
		if err := copyFile(filepath.Join(dir, "pki", from), filepath.Join(dir, "broker", to)); err != nil {
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "broker", "users-ca.pem"), usersCA, 0o600); err != nil {
		return err
	}
	pw := make([]byte, 16)
	if _, err := rand.Read(pw); err != nil {
		return err
	}
	password := fmt.Sprintf("Aa1!%x", pw)
	if err := os.WriteFile(filepath.Join(c.local, "openldap.env"),
		[]byte(labEnv(password, directory.ADIssuerSerial(p.alice), os.Getuid(), os.Getgid())), 0o600); err != nil {
		return err
	}
	bob, bobKey, err := p.personCert("bob", "bob@corp.example.com", "", now)
	if err != nil {
		return err
	}
	slice := filepath.Join(root, slicePKIDir)
	for _, w := range []struct {
		cert, key  string
		c          *x509.Certificate
		keyPrivate any
	}{
		{cert: e2eAliceCert, key: e2eAliceKey, c: p.alice, keyPrivate: p.aliceKey},
		{cert: e2eBobCert, key: e2eBobKey, c: bob, keyPrivate: bobKey},
	} {
		certPEM, keyPEM, err := testpki.PEMs(tls.Certificate{Certificate: [][]byte{w.c.Raw}, PrivateKey: w.keyPrivate})
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(slice, w.cert), certPEM, 0o600); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(slice, w.key), keyPEM, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// What the test reads and does
// ---------------------------------------------------------------------------

// tryAgent is personAgent that returns the failure instead of ending the test:
// bob's login is expected to be refused. out is what `port49 login` printed,
// which names no credential.
func tryAgent(cert, key string) (sock string, pid int, out string, stop func(), err error) {
	pki := filepath.Join(root, slicePKIDir)
	dir, err := os.MkdirTemp("", "p49dir")
	if err != nil {
		return "", 0, "", nil, err
	}
	sock = filepath.Join(dir, "a", "agent.sock")
	cmd := withAgent(exec.Command(filepath.Join(root, "bin", "port49"), "login", "--broker", sliceBrokerURL,
		"--cert", filepath.Join(pki, cert), "--key", filepath.Join(pki, key),
		"--broker-ca", filepath.Join(pki, testpki.LabCA)), sock)
	cmd.Dir = root
	var b strings.Builder
	cmd.Stdout, cmd.Stderr = &b, &b
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		os.RemoveAll(dir)
		return "", 0, "", nil, err
	}
	go func() { done <- cmd.Wait() }()
	select {
	case err = <-done:
	case <-time.After(time.Minute):
		_ = cmd.Process.Kill()
		err = errors.New("port49 login did not return in 1m")
	}
	out = strings.TrimSpace(b.String())
	m := agentPID.FindStringSubmatch(out)
	if err != nil || m == nil {
		if m != nil {
			if p, _ := strconv.Atoi(m[1]); p > 0 {
				_ = syscall.Kill(p, syscall.SIGTERM)
			}
		}
		os.RemoveAll(dir)
		if err == nil {
			err = errors.New("port49 login printed no agent pid")
		}
		return "", 0, out, nil, err
	}
	pid, _ = strconv.Atoi(m[1])
	return sock, pid, out, func() {
		if err := syscall.Kill(pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
			_ = err
		}
		os.RemoveAll(dir)
	}, nil
}

// fileSize is the size of path, the offset the lines after now start at.
func fileSize(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return fi.Size()
}

// gauge reads the metric name (no labels) from the Prometheus text at url.
func gauge(url, name string) (float64, error) {
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Get(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}
	return parseGauge(string(body), name)
}

// parseGauge is the value of the unlabelled metric name in text.
func parseGauge(text, name string) (float64, error) {
	for _, line := range strings.Split(text, "\n") {
		if rest, ok := strings.CutPrefix(line, name+" "); ok {
			return strconv.ParseFloat(strings.TrimSpace(rest), 64)
		}
	}
	return 0, fmt.Errorf("no %s in the metrics", name)
}

const brokerMetrics = "http://127.0.0.1:9050/metrics"
const refreshComplete = "port49_directory_refresh_last_complete_timestamp_seconds"

// e2eRecords are the records of event for principal in recs.
func e2eRecords(recs []map[string]any, event, principal string) []map[string]any {
	var out []map[string]any
	for _, r := range recs {
		if str(r, "event") == event && str(r, "principal") == principal {
			out = append(out, r)
		}
	}
	return out
}

// e2eMint is the first permit mint record for principal in recs, or nil.
func e2eMint(recs []map[string]any, principal string) map[string]any {
	for _, r := range e2eRecords(recs, "mint", principal) {
		if str(r, "verdict") == "permit" {
			return r
		}
	}
	return nil
}

// e2eRefreshDeny is the first refresh deny of reason for principal, or nil.
func e2eRefreshDeny(recs []map[string]any, principal, reason string) map[string]any {
	for _, r := range e2eRecords(recs, "refresh", principal) {
		if str(r, "verdict") == "deny" && str(r, "reason") == reason {
			return r
		}
	}
	return nil
}

// e2eMintSaid describes a mint record for a table cell: its verdict, reason,
// subject and the directory source it read.
func e2eMintSaid(r map[string]any) string {
	if r == nil {
		return "no mint record"
	}
	dir := sub(sub(r, "auth"), "directory")
	return fmt.Sprintf("mint %s %s, policy.subject %s, auth.directory.source %s", str(r, "verdict"), str(r, "reason"),
		str(sub(r, "policy"), "subject"), str(dir, "source"))
}

// e2eCmd is one command in an open session: whether the device ran it,
// refused it, or ended the session, and a cell saying what it printed.
type e2eCmd struct {
	permitted, refused, ended bool
	took                      time.Duration
	cell                      string
}

// runCmd sends cmd in sh. EOS: permitted when the output holds its version
// line, refused when the session goes on and does not. Junos authorizes
// commands locally, so port49 never refuses one: permitted is the device
// running it.
func (l *lab) runCmd(sh *labShell, cmd string) e2eCmd {
	out, took, ended, err := sh.runOrEnd(cmd, 60*time.Second)
	body := shellBody(l.hostName(), out)
	r := e2eCmd{took: took.Round(10 * time.Millisecond), ended: ended}
	switch {
	case err != nil:
		r.cell = "not observed in 60s: " + l29Cell(body)
	case ended:
		r.cell = fmt.Sprintf("the device ended the session after %s; it printed %s", r.took, l29Cell(body))
	case strings.Contains(out, revokeVersion[l.p.name]):
		r.permitted = true
		r.cell = fmt.Sprintf("permitted in %s (the version line printed)", r.took)
	default:
		r.refused = true
		r.cell = fmt.Sprintf("refused in %s, the device printed %s", r.took, l29Cell(body))
	}
	return r
}

// runPermitted runs cmd until the device runs it or within elapses, reading
// the shell again 3s after the prompt on a slow echo (storeOutcome's reason).
func (l *lab) runPermitted(sh *labShell, cmd string, within time.Duration) e2eCmd {
	deadline := time.Now().Add(within)
	for {
		r := l.runCmd(sh, cmd)
		if r.permitted || r.ended || !time.Now().Before(deadline) {
			return r
		}
		time.Sleep(3 * time.Second)
	}
}

// lastCommandRecord is the last authorize_command record of user in recs.
func lastCommandRecord(recs []map[string]any, user string) map[string]any {
	var out map[string]any
	for _, r := range recs {
		if str(r, "event") == "authorize_command" && str(sub(r, "session"), "username") == user {
			out = r
		}
	}
	return out
}

// ldapWriter runs input through ldapmodify (or, with search set, ldapsearch)
// in the openldap container as the lab's writer account, over LDAPS. The
// password is the container's own environment: it is never on a command line
// or in the output.
func (c *composeStack) ldapWriter(input string, argv ...string) (string, error) {
	script := `umask 077; printf %s "$LAB_ADMIN_PASSWORD" > /tmp/w.pw; ` +
		`LDAPTLS_CACERT=/etc/ldap/tls/ca.pem ` + strings.Join(argv, " ") +
		` -x -H ldaps://localhost:636 -D cn=lab-writer,ou=Svc,` + e2eLDAPBase + ` -y /tmp/w.pw; rc=$?; rm -f /tmp/w.pw; exit $rc`
	return c.runIn(input, "exec", "-T", "openldap", "sh", "-c", script)
}

// e2eMemberLDIF moves g-leaf out of or back into g-mid. groupOfNames needs a
// member, and g-leaf is g-mid's only: a placeholder that names no entry is
// added in the same modify, as the fixture's own does.
func e2eMemberLDIF(remove bool) string {
	const mid = "cn=g-mid,ou=G," + e2eLDAPBase
	const leaf = "cn=g-leaf,ou=G," + e2eLDAPBase
	const holder = "cn=nobody,ou=G," + e2eLDAPBase
	if remove {
		return "dn: " + mid + "\nchangetype: modify\nadd: member\nmember: " + holder + "\n-\ndelete: member\nmember: " + leaf + "\n"
	}
	return "dn: " + mid + "\nchangetype: modify\nadd: member\nmember: " + leaf + "\n-\ndelete: member\nmember: " + holder + "\n"
}

// gMidMembers is g-mid's member values, as the directory answers a search.
func (c *composeStack) gMidMembers() (string, error) {
	out, err := c.ldapWriter("", "ldapsearch", "-LLL", "-b", "cn=g-mid,ou=G,"+e2eLDAPBase, "-s", "base", "member")
	if err != nil {
		return out, err
	}
	var members []string
	for _, line := range strings.Split(out, "\n") {
		if m, ok := strings.CutPrefix(strings.TrimSpace(line), "member: cn="); ok {
			members = append(members, strings.SplitN(m, ",", 2)[0])
		}
	}
	return strings.Join(members, ", "), nil
}

// storedMemberships are the mb/ keys the broker's store holds, read as etcd's
// root from a one-shot container on the stack's network: keys only, which hold
// a principal and no secret.
func (c *composeStack) storedMemberships() ([]string, error) {
	out, err := exec.Command("docker", "run", "--rm", "--user", "0", "--network", composeProject+"_port49",
		"-v", composeProject+"_etcd-root:/etcd-root:ro",
		"-e", "ETCDCTL_ENDPOINTS=https://etcd-1:2379,https://etcd-2:2379,https://etcd-3:2379",
		"-e", "ETCDCTL_CACERT=/etcd-root/ca.pem", "-e", "ETCDCTL_CERT=/etcd-root/root.pem", "-e", "ETCDCTL_KEY=/etcd-root/root-key.pem",
		"--entrypoint", "etcdctl", "port49-setup:dev", "get", "/port49/", "--prefix", "--keys-only").CombinedOutput()
	c.note(fmt.Sprintf("$ etcdctl get /port49/ --prefix --keys-only (filtered to mb/; %d bytes, err %v)\n", len(out), err))
	if err != nil {
		return nil, fmt.Errorf("etcdctl: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return membershipKeys(string(out)), nil
}

// membershipKeys are the mb/ keys among etcdctl's key list.
func membershipKeys(list string) []string {
	var out []string
	for _, line := range strings.Split(list, "\n") {
		if strings.Contains(line, "/mb/") {
			out = append(out, strings.TrimSpace(line))
		}
	}
	return out
}

// anyContains says whether any of list contains s.
func anyContains(list []string, s string) bool {
	for _, x := range list {
		if strings.Contains(x, s) {
			return true
		}
	}
	return false
}

// openLDAPReady waits for the openldap container to have said its fixture
// is loaded n times (once per start), then for the container to be running.
func (c *composeStack) openLDAPReady(n int, within time.Duration) error {
	deadline := time.Now().Add(within)
	for {
		out, _ := c.run("logs", "--no-color", "openldap")
		if strings.Count(out, "lab: openldap fixture loaded") >= n {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("openldap did not load its fixture %d time(s) in %s", n, within)
		}
		time.Sleep(2 * time.Second)
	}
}

// paren is s in parentheses with a leading space, nothing for an empty s.
func paren(s string) string {
	if s == "" {
		return ""
	}
	return " (" + s + ")"
}

func rd(d time.Duration) time.Duration { return d.Round(100 * time.Millisecond) }

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

// e2ePlatform says whether the end-to-end runs on name: the two images the
// brief names, one that authorizes commands and one that does not.
func e2ePlatform(name string) bool { return name == "arista_eos" || name == "juniper_vjunos-router" }

func TestDirectoryEndToEnd(t *testing.T) {
	sel, _, err := platformSelection()
	if err != nil {
		t.Fatal(err)
	}
	ran := false
	for _, p := range rowsFor(sel, false) {
		if !e2ePlatform(p.name) {
			continue // no image is brought up for a platform this does not run on
		}
		ran = true
		p := p
		t.Run(p.name, func(t *testing.T) { directoryEndToEnd(t, labFor(t, p)) })
	}
	if !ran {
		t.Skip("PORT49_LAB_PLATFORMS selects neither arista_eos nor juniper_vjunos-router")
	}
}

func directoryEndToEnd(t *testing.T, l *lab) {
	sessionOnly := strings.HasPrefix(l.p.name, "juniper_")
	var err error
	var failed []string
	fail := func(format string, args ...any) { failed = append(failed, fmt.Sprintf(format, args...)) }
	var obs strings.Builder
	cell := func(step, what string) { fmt.Fprintf(&obs, "| %s | %s |\n", step, wideCell(what)) }

	c := l.startComposeWith(t, composeOptions{Overlay: "directory.yaml", Files: e2eFiles, Prepare: e2ePrepare})
	stopCapture := l.capture(t, "directory-e2e")
	defer stopCapture()

	var agentStop func()
	var agentSock string
	newAgent := func(cert, key string) {
		if agentStop != nil {
			agentStop()
			agentStop = nil
		}
		agentSock, _, agentStop = personAgent(t, cert, key)
	}
	defer func() {
		if agentStop != nil {
			agentStop()
		}
	}()
	var sh *labShell
	defer func() {
		if sh != nil {
			sh.Close()
		}
	}()

	var preface strings.Builder
	defer func() {
		note := preface.String() + "| step | observed |\n|---|---|\n" + obs.String()
		if len(failed) > 0 {
			note += "\n**Not as the claim says:**\n\n- " + strings.Join(failed, "\n- ") + "\n"
		}
		l.result(t, "directory-e2e", e2eClaim, note)
		if len(failed) > 0 {
			t.Errorf("directory end to end on %s: %s", l.p.name, strings.Join(failed, "; "))
		}
	}()
	slapd, _ := c.run("exec", "-T", "openldap", "slapd", "-VV")
	fmt.Fprintf(&preface, "Directory: OpenLDAP (`%s`), image `port49lab/openldap:bookworm` (%s), on the compose network as `openldap`, "+
		"the broker bound by EXTERNAL over LDAPS. Configuration: `refresh_interval: %s`, `directory.grace: %s`, "+
		"`session.staleness_ceiling: %s`, `nested_groups: recursive` (OpenLDAP answers in_chain empty, L42), "+
		"`certificate_mapping: san_email` (weak, pinned to the users CA), `prewarm: {interval: 5m}`. "+
		"The lab policy grants `netops-oncall` (a group subject) and bob (an identity subject, no `username:`) "+
		"`network_admin` on every device. The directory is stopped and started with `docker compose stop`/`start`; "+
		"its entrypoint keeps the seeded data and every entryUUID across a restart (a reloaded fixture would change them, which the pin refuses).\n\n",
		oneLineMax(strings.SplitN(strings.TrimSpace(slapd), "\n", 2)[0], 120), imageID("port49lab/openldap:bookworm"),
		e2eRefreshInterval, e2eGrace, e2eCeiling)

	// ---- 1. A login granted through a nested group
	off, boff := l.mark(), fileSize(c.brokerLog)
	newAgent(e2eAliceCert, e2eAliceKey)
	said, tok := l29Mint(agentSock, l.p.node)
	if tok == "" {
		cell("1. `port49 login` with alice's certificate, `port49 token`", "no token: "+said)
		t.Fatalf("alice minted no token through the directory: %s", said)
	}
	recs := waitRecordsOf(c.brokerLog, boff, 30*time.Second, func(rs []map[string]any) bool { return e2eMint(rs, e2eAlice) != nil })
	mint := e2eMint(recs, e2eAlice)
	cell("1a. alice's certificate, `port49 login`, `port49 token` for "+l.p.node, e2eMintSaid(mint))
	switch {
	case mint == nil:
		fail("no permit mint record for %s in the broker's log", e2eAlice)
	case str(mint, "reason") != "grants_matched" || str(sub(mint, "policy"), "subject") != "netops_oncall" ||
		str(sub(sub(mint, "auth"), "directory"), "source") != "fresh":
		fail("alice's mint was %s; want grants_matched, netops_oncall, source fresh", e2eMintSaid(mint))
	}
	sh, err = l.shell(e2eUser, tok)
	if err != nil {
		cell("1b. SSH as alice with the token", "login failed: "+err.Error())
		t.Fatalf("SSH login as alice: %v", err)
	}
	first := l.runPermitted(sh, "show version", 20*time.Second)
	ctx1, v1, r1 := ctxIDOf(l.waitForRecords(off, 30*time.Second, func(rs []map[string]any) bool {
		if sessionOnly {
			return len(reasonsOf(rs, "account")) > 0
		}
		id, _, _ := ctxIDOf(rs, e2eUser)
		return id != ""
	}), e2eUser)
	if sessionOnly {
		cell("1b. SSH as alice with the token, `show version`", "the session opened; "+first.cell+"; Junos authorizes no command (decision 21), so no ctx_id")
	} else {
		cell("1b. SSH as alice with the token, `show version`", fmt.Sprintf("%s; port49d: %s %s, ctx_id %s", first.cell, v1, r1, ctx1))
	}
	if !first.permitted || (!sessionOnly && (v1 != "permit" || ctx1 == "")) {
		fail("alice's first `show version`: %s (port49d %s %s ctx %q)", first.cell, v1, r1, ctx1)
	}

	// ---- 2. A removal reaches the open session
	boff2, off2 := fileSize(c.brokerLog), l.mark()
	members, merr := c.gMidMembers()
	cell("2a. g-mid's members before", fmt.Sprintf("%s (err %v)", members, merr))
	if out, err := c.ldapWriter(e2eMemberLDIF(true), "ldapmodify"); err != nil {
		t.Fatalf("removing g-leaf from g-mid: %v\n%s", err, tailOf(out, 400))
	}
	removedAt := time.Now()
	members, merr = c.gMidMembers()
	cell("2b. `ldapmodify` removes g-leaf from g-mid", fmt.Sprintf("g-mid's members now: %s (err %v)", members, merr))
	if strings.Contains(members, "g-leaf") {
		fail("g-leaf is still a member of g-mid after the modify: %s", members)
	}
	recs = waitRecordsOf(c.brokerLog, boff2, e2eRefreshInterval+30*time.Second, func(rs []map[string]any) bool {
		return e2eRefreshDeny(rs, e2eAlice, "no_grants_matched") != nil
	})
	took := time.Since(removedAt)
	deny := e2eRefreshDeny(recs, e2eAlice, "no_grants_matched")
	if deny == nil {
		cell("2c. the broker's refresh", fmt.Sprintf("no `refresh deny no_grants_matched` for alice within %s (refresh_interval + 30s)", rd(took)))
		fail("no refresh deny no_grants_matched for alice within refresh_interval + 30s")
	} else {
		dctx, unreached := str(sub(deny, "session"), "ctx_id"), sub(deny, "session")["unreached"] == true
		cell("2c. the broker's refresh", fmt.Sprintf("`refresh deny no_grants_matched` for alice's ctx_id %s %s after the removal (bound %s); session.unreached %v",
			dctx, rd(took), e2eRefreshInterval+30*time.Second, unreached))
		if !sessionOnly && dctx != ctx1 {
			fail("the refresh denied ctx_id %s, alice's session is %s", dctx, ctx1)
		}
		if unreached != sessionOnly {
			fail("session.unreached is %v on %s; want %v", unreached, l.p.name, sessionOnly)
		}
	}
	after := l.runCmd(sh, "show version")
	if sessionOnly {
		cell("2d. the open session's next `show version` (Junos: decision 21)", after.cell)
		if !after.permitted {
			fail("the open Junos session's `show version` after the refresh: %s", after.cell)
		}
	} else {
		cctx, cv, cr := ctxIDOf(l.waitForRecords(off2, 30*time.Second, func(rs []map[string]any) bool {
			r := lastCommandRecord(rs, e2eUser)
			return r != nil && str(r, "verdict") == "deny"
		}), e2eUser)
		cell("2d. the open session's next `show version`", fmt.Sprintf("%s; port49d: %s %s, ctx_id %s", after.cell, cv, cr, cctx))
		if !after.refused || cv != "deny" || cr != "credential_revoked" {
			fail("after the removal alice's session: %s; port49d %s %s", after.cell, cv, cr)
		}
	}
	if out, err := c.ldapWriter(e2eMemberLDIF(false), "ldapmodify"); err != nil {
		t.Fatalf("putting g-leaf back in g-mid: %v\n%s", err, tailOf(out, 400))
	}
	members, merr = c.gMidMembers()
	cell("2e. the membership is put back", fmt.Sprintf("g-mid's members: %s (err %v)", members, merr))
	sh.Close()
	sh = nil

	// ---- 3. An outage, inside grace
	newAgent(e2eAliceCert, e2eAliceKey)
	off3 := l.mark()
	said, tok = l29Mint(agentSock, l.p.node)
	if tok == "" {
		cell("3a. alice logs in again", "no token: "+said)
		t.Fatalf("alice minted no token after the membership was put back: %s", said)
	}
	if sh, err = l.shell(e2eUser, tok); err != nil {
		cell("3a. alice logs in again", "SSH failed: "+err.Error())
		t.Fatalf("SSH login as alice after the removal: %v", err)
	}
	base := l.runPermitted(sh, "show version", 20*time.Second)
	ctx2, v2, r2 := ctxIDOf(l.waitForRecords(off3, 30*time.Second, func(rs []map[string]any) bool {
		if sessionOnly {
			return len(reasonsOf(rs, "account")) > 0
		}
		id, _, _ := ctxIDOf(rs, e2eUser)
		return id != ""
	}), e2eUser)
	cell("3a. alice logs in again (fresh token), `show version`", fmt.Sprintf("%s; ctx_id %s %s %s", base.cell, ctx2, v2, r2))
	if !base.permitted {
		fail("alice's login after the membership was put back: %s", base.cell)
	}
	gaugeBefore, gerr := gauge(brokerMetrics, refreshComplete)
	if gerr != nil {
		fail("reading %s before the outage: %v", refreshComplete, gerr)
	}
	berrOff3 := fileSize(c.brokerErr)
	boffOutage := fileSize(c.brokerLog)
	if _, err := c.run("stop", "-t", "5", "openldap"); err != nil {
		t.Fatalf("stopping openldap: %v", err)
	}
	stoppedAt := time.Now()
	graceTok := ""
	said, graceTok = l29Mint(agentSock, l.p.node)
	recs = waitRecordsOf(c.brokerLog, boffOutage, 30*time.Second, func(rs []map[string]any) bool { return e2eMint(rs, e2eAlice) != nil })
	gmint := e2eMint(recs, e2eAlice)
	graceLines := linesSince(c.brokerErr, berrOff3, "(grace)")
	cell("3b. the directory is stopped; a second `port49 token` for "+l.p.node, fmt.Sprintf("minted %v %s after the stop; %s; the broker said: %s",
		graceTok != "", rd(time.Since(stoppedAt)), e2eMintSaid(gmint), firstOf(graceLines)))
	if graceTok == "" || gmint == nil || str(sub(sub(gmint, "auth"), "directory"), "source") != "grace" || len(graceLines) == 0 {
		fail("the mint in the outage: token %v (%s), %s, grace lines %d", graceTok != "", said, e2eMintSaid(gmint), len(graceLines))
	}
	var timeline []string
	staleAt := time.Duration(0)
	if sessionOnly {
		// Junos asks port49d about no command, so no denial is observable
		// on the open session: it runs on, and a second login is the check.
		run := l.runCmd(sh, "show version")
		cell("3c. Junos: the open session through the outage (decision 21)", run.cell+"; context_stale is a command authorization, which Junos does not send")
	} else {
		var last e2eCmd
		for deadline := stoppedAt.Add(e2eCeiling + 90*time.Second); time.Now().Before(deadline); {
			last = l.runCmd(sh, "show version")
			timeline = append(timeline, fmt.Sprintf("%ds %s", int(time.Since(stoppedAt).Seconds()), map[bool]string{true: "permit", false: "deny"}[last.permitted]))
			if !last.permitted {
				staleAt = time.Since(stoppedAt)
				break
			}
			time.Sleep(10 * time.Second)
		}
		srec := lastCommandRecord(l.waitForRecords(off3, 30*time.Second, func(rs []map[string]any) bool {
			r := lastCommandRecord(rs, e2eUser)
			return r != nil && str(r, "verdict") == "deny"
		}), e2eUser)
		cell("3c. the open session's `show version` every 10s from the stop (seconds since the stop)", fmt.Sprintf("%s; port49d: %s %s, server_msg %q; the device: %s",
			strings.Join(timeline, ", "), str(srec, "verdict"), str(srec, "reason"), str(srec, "server_msg"), last.cell))
		// The last stamp was at most one refresh_interval before the stop, so
		// the ceiling falls between ceiling - interval and ceiling after it.
		lo, hi := e2eCeiling-e2eRefreshInterval-15*time.Second, e2eCeiling+25*time.Second
		switch {
		case last.permitted:
			fail("alice's session was still permitted %s after the stop, past the ceiling of %s", rd(time.Since(stoppedAt)), e2eCeiling)
		case srec == nil || str(srec, "reason") != "context_stale":
			fail("the denial was %s %s, want context_stale", str(srec, "verdict"), str(srec, "reason"))
		case staleAt < lo || staleAt > hi:
			fail("the first context_stale denial came %s after the stop; the ceiling %s after the last stamp puts it between %s and %s", rd(staleAt), e2eCeiling, lo, hi)
		}
		if !strings.Contains(last.cell, "staleness ceiling") && !strings.Contains(strings.ToLower(last.cell), "port49") {
			cell("3d. L2's display", "the device's refusal did not carry port49's server_msg: "+last.cell)
		}
	}
	// Past grace a mint is refused: wait out the grace from the last
	// verification (at most one refresh_interval before the stop).
	for time.Since(stoppedAt) < e2eGrace+e2eRefreshInterval/2 && time.Since(stoppedAt) < e2eGrace+30*time.Second {
		time.Sleep(5 * time.Second)
	}
	time.Sleep(15 * time.Second)
	said, lateTok := l29Mint(agentSock, l.p.node)
	cell("3e. a `port49 token` "+fmt.Sprint(rd(time.Since(stoppedAt)))+" after the stop, past grace", fmt.Sprintf("minted %v; %s", lateTok != "", oneLineMax(said, 200)))
	if lateTok != "" {
		fail("a token was minted %s into the outage, past grace %s", rd(time.Since(stoppedAt)), e2eGrace)
	} else if !strings.Contains(said, "directory_unavailable") {
		fail("the refused mint said %q, want directory_unavailable", oneLineMax(said, 200))
	}

	// ---- 4. The directory returns
	boff4, off4 := fileSize(c.brokerLog), l.mark()
	if _, err := c.run("start", "openldap"); err != nil {
		t.Fatalf("starting openldap: %v", err)
	}
	startedAt := time.Now()
	if err := c.openLDAPReady(2, 3*time.Minute); err != nil {
		t.Fatalf("%v", err)
	}
	readyAt := time.Now()
	moved := time.Duration(0)
	var gaugeAfter float64
	for deadline := startedAt.Add(e2eRecoveryBound + 2*time.Minute); time.Now().Before(deadline); time.Sleep(2 * time.Second) {
		if g, err := gauge(brokerMetrics, refreshComplete); err == nil && g > gaugeBefore {
			gaugeAfter, moved = g, time.Since(startedAt)
			break
		}
	}
	stamps := e2eRecords(recordsAt(c.brokerLog, boff4), "refresh", e2eAlice)
	cell("4a. the directory is started again: the scheduled pass", fmt.Sprintf("%s moved from %.0f to %.0f %s after the start (%s after its fixture loaded; bound %s = refresh_interval + the breaker's probe_interval + one 30s health-check tick + 30s, since the breaker the outage opened is closed only by its health check); refresh records for alice since the start: %d",
		refreshComplete, gaugeBefore, gaugeAfter, rd(moved), rd(moved-readyAt.Sub(startedAt)), e2eRecoveryBound, len(stamps)))
	switch {
	case moved == 0:
		fail("%s did not move within %s of the directory's start", refreshComplete, e2eRecoveryBound+2*time.Minute)
	case moved-readyAt.Sub(startedAt) > e2eRecoveryBound:
		fail("the scheduled pass completed %s after the directory was ready; the bound is refresh_interval + probe_interval + 30s (%s)", rd(moved-readyAt.Sub(startedAt)), e2eRecoveryBound)
	}
	if len(stamps) != 0 {
		fail("the stamping pass wrote %d refresh record(s) for alice; it writes none", len(stamps))
	}
	if sessionOnly {
		said, tok = l29Mint(agentSock, l.p.node)
		var run e2eCmd
		if tok != "" {
			if s2, err := l.shell(e2eUser, tok); err == nil {
				run = l.runPermitted(s2, "show version", 20*time.Second)
				s2.Close()
			} else {
				run.cell = "SSH failed: " + err.Error()
			}
		} else {
			run.cell = "no token: " + said
		}
		cell("4b. Junos: a fresh login after the return (the open session sends no command)", run.cell)
		if !run.permitted {
			fail("a fresh Junos login after the directory returned: %s", run.cell)
		}
	} else {
		resumed := l.runPermitted(sh, "show version", 30*time.Second)
		cctx, cv, cr := ctxIDOf(l.waitForRecords(off4, 30*time.Second, func(rs []map[string]any) bool {
			r := lastCommandRecord(rs, e2eUser)
			return r != nil && str(r, "verdict") == "permit"
		}), e2eUser)
		cell("4b. the same session's next `show version`", fmt.Sprintf("%s; port49d: %s %s, ctx_id %s (the session's was %s)", resumed.cell, cv, cr, cctx, ctx2))
		if !resumed.permitted || cv != "permit" || cctx != ctx2 {
			fail("the session did not resume on its retained context: %s; port49d %s %s ctx %s, was %s", resumed.cell, cv, cr, cctx, ctx2)
		}
	}
	sh.Close()
	sh = nil

	// ---- 5. A broker restart in an outage
	if agentStop != nil {
		agentStop()
		agentStop = nil
	}
	keys, kerr := c.storedMemberships()
	cell("5a. the broker's stored memberships (mb/ keys), before the outage", fmt.Sprintf("alice %v, bob %v (%d key(s); err %v)",
		anyContains(keys, "alice"), anyContains(keys, "bob"), len(keys), kerr))
	switch {
	case kerr != nil:
		fail("reading the store's mb/ keys: %v", kerr)
	case !anyContains(keys, "alice"):
		fail("alice has no mb/ record before the outage: %v", keys)
	case anyContains(keys, "bob"):
		fail("bob has an mb/ record before the outage, though he never logged in and pre-warm enumerates group members only: %v", keys)
	}
	boff5 := fileSize(c.brokerLog)
	if _, err := c.run("stop", "-t", "5", "openldap"); err != nil {
		t.Fatalf("stopping openldap before the restart: %v", err)
	}
	restartSince := time.Now().UTC().Format(time.RFC3339Nano)
	if out, err := c.run("restart", "port49-broker"); err != nil {
		t.Fatalf("restarting the broker: %v\n%s", err, tailOf(out, 400))
	}
	// docker logs -f ends with the container it followed; the restarted broker's
	// records and lines are followed again from the instant before the restart
	if err := c.follow(composeProject+"-port49-broker-1", restartSince, c.brokerLog, c.brokerErr); err != nil {
		t.Fatalf("following the restarted broker: %v", err)
	}
	restartedAt := time.Now()
	for deadline := time.Now().Add(3 * time.Minute); !httpOK("http://127.0.0.1:9050/readyz"); time.Sleep(time.Second) {
		if time.Now().After(deadline) {
			t.Fatalf("the restarted broker's /readyz was not 200 in 3m (directory down)\n%s", c.tail(20))
		}
	}
	cell("5b. the directory stopped, `docker compose restart port49-broker`", fmt.Sprintf("/readyz 200 %s after the restart", rd(time.Since(restartedAt))))
	if sock, _, out, stopA, err := tryAgent(e2eAliceCert, e2eAliceKey); err != nil {
		cell("5c. alice: `port49 login`, `port49 token` after the restart, within grace", "login failed: "+oneLineMax(out+" "+err.Error(), 250))
		fail("alice's login after the restart in the outage: %v: %s", err, oneLineMax(out, 200))
	} else {
		agentSock, agentStop = sock, stopA
		said, tok = l29Mint(agentSock, l.p.node)
		recs = waitRecordsOf(c.brokerLog, boff5, 30*time.Second, func(rs []map[string]any) bool { return e2eMint(rs, e2eAlice) != nil })
		m5 := e2eMint(recs, e2eAlice)
		cell("5c. alice: `port49 login`, `port49 token` after the restart, within grace", fmt.Sprintf("minted %v%s; %s", tok != "", paren(oneLineMax(said, 150)), e2eMintSaid(m5)))
		if tok == "" || m5 == nil || str(sub(sub(m5, "auth"), "directory"), "source") != "grace" {
			fail("alice's mint after the restart: token %v (%s), %s", tok != "", said, e2eMintSaid(m5))
		}
	}
	bobStop := func() {}
	bsock, _, bout, bstop, berr := tryAgent(e2eBobCert, e2eBobKey)
	var bsaid string
	if berr == nil {
		bobStop = bstop
		var btok string
		bsaid, btok = l29Mint(bsock, l.p.node)
		if btok != "" {
			fail("bob, never verified, was minted a token in the outage")
		}
	} else {
		bsaid = bout + " (login: " + berr.Error() + ")"
	}
	bobStop()
	cell("5d. bob (never logged in, so no membership is stored): `port49 login`, `port49 token`", oneLineMax(bsaid, 300))
	if !strings.Contains(bsaid, "directory_unavailable") {
		fail("bob's refusal said %q, want directory_unavailable", oneLineMax(bsaid, 200))
	}
}
