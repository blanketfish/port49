//go:build lab

package lab

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
)

// The lab on deploy/compose (plan 7f, Task 2): port49d, port49-broker and a
// three-member etcd as containers, with port49d's TACACS+ port published on
// the clab bridge's gateway, where every topology's devices already send it.
// New register rows run on it; closed rows' re-checks stay on the host
// harness (tests/lab/README.md, "The compose mode").
const (
	// composeGateway is the compose network's gateway, listed as l39_gateway
	// so a source rewritten to it is recorded rather than refused.
	composeGateway = "172.30.49.1"
	composeProject = "port49lab"
)

// The lab's health checks, which every compose run's port49d.yaml names
// (decision 37): the defaults, said. The context cache is off in the lab:
// L41 measures nothing about it, and a cache would answer cell 3's command
// from memory and play a part in what the closed listener is measured doing.
const (
	labHealthInterval = time.Second
	labCloseAfter     = 5
	labOpenAfter      = 3
)

// healthDarkBound is the longest an idle port49d on a hung store takes to
// close its listeners under its health checks (decision 37): closeAfter
// checks interval apart, the last bounded by callTimeout; 5s is slack for
// the 250ms poll and the process.
func healthDarkBound(interval, callTimeout time.Duration, closeAfter int) time.Duration {
	return time.Duration(closeAfter)*interval + callTimeout + 5*time.Second
}

// composeStoreBlock is the store: block deploy/compose's configs name for
// component ("daemon" or "broker"), with the three in-container endpoints
// and the lab's hold_ttl (storeLab's). The daemon's also names the health
// checks; the broker has none.
func composeStoreBlock(component string) string {
	identity := "port49d"
	health := ""
	if component == "broker" {
		identity = "port49-broker"
	} else {
		health = fmt.Sprintf("    health: {interval: %s, close_after: %d, open_after: %d}\n",
			labHealthInterval, labCloseAfter, labOpenAfter)
	}
	return fmt.Sprintf("\nstore:\n  backend: etcd\n  etcd:\n    endpoints: [https://etcd-1:2379, https://etcd-2:2379, https://etcd-3:2379]\n"+
		"    ca_file: /etc/port49/etcd/ca.pem\n    %s: {cert_file: /etc/port49/etcd/%s.pem, key_file: /etc/port49/etcd/%s-key.pem}\n"+
		"    hold_ttl: 60s\n%s", component, identity, identity, health)
}

// composeLabFiles is the lab's version of deploy/compose's four YAML files
// and two env files, by name. base is port49d-lab.yaml's text already
// derived for the platform; brokerSlice, policy and inventory are
// slice/broker.yaml's, slice/policy.yaml's and inventory-lab.yaml's.
// It reads no file. The device key is port49d's env alone.
func composeLabFiles(base, brokerSlice, policy, inventory string) (map[string]string, error) {
	daemon, err := splitDaemonYAML(base, splitNode{Listen: ":49", Metrics: ":9049", Admin: "/run/port49/port49d.sock",
		Spool: "/var/spool/port49d/acct.jsonl"}, "/etc/port49/policy.yaml", "/etc/port49/inventory.yaml",
		composeStoreBlock("daemon"))
	if err != nil {
		return nil, err
	}
	broker, err := splitBrokerYAML(base, brokerSlice, splitBrokerOpts{Policy: "/etc/port49/policy.yaml",
		Inventory: "/etc/port49/inventory.yaml", State: "/var/lib/port49-broker", Metrics: ":9050",
		Admin: "/run/port49/port49-broker.sock", Store: composeStoreBlock("broker"), PKI: "/etc/port49/broker"})
	if err != nil {
		return nil, err
	}
	// The slice's broker listens on its own loopback, which the published
	// 127.0.0.1:8449:8443 cannot reach from inside the container.
	if broker, err = swapLine(broker, `listen: "127.0.0.1:8449"`, `listen: ":8443"`); err != nil {
		return nil, err
	}
	// An extra device at the gateway, so a source the userland proxy rewrites
	// is recorded against it rather than refused as unknown (L39).
	at := strings.Index(inventory, "\nkey_groups:")
	if at < 0 {
		return nil, errors.New("tests/lab/inventory-lab.yaml has no key_groups: block to add the gateway's group to")
	}
	inv := inventory[:at] + "\n  - {name: l39_gateway, platform: arista_eos, addresses: [" + composeGateway + "]}" +
		strings.TrimRight(inventory[at:], "\n") + "\n  - {match: {cidr: 172.30.49.0/24}, key_ref: lab_key}\n"
	labKey, encKey := os.Getenv("PORT49_LAB_KEY"), os.Getenv("PORT49_LAB_ENC_KEY")
	if labKey == "" {
		labKey = labKeyDefault
	}
	if encKey == "" {
		encKey = labEncKeyDefault
	}
	return map[string]string{
		"port49d.yaml":       daemon,
		"port49-broker.yaml": broker,
		"policy.yaml":        policy,
		"inventory.yaml":     inv,
		"port49d.env":        "PORT49_LAB_KEY=" + labKey + "\nPORT49_LAB_ENC_KEY=" + encKey + "\n",
		"port49-broker.env":  "PORT49_LAB_ENC_KEY=" + encKey + "\n",
	}, nil
}

// proxyModeOf is "on" when ps (`ps -eo pid,args`) holds a docker-proxy
// serving 172.100.100.1:49, and "off" otherwise.
func proxyModeOf(ps string) string {
	for _, line := range strings.Split(ps, "\n") {
		if !strings.Contains(line, "docker-proxy") {
			continue
		}
		f := strings.Fields(line)
		host, port := false, false
		for i := 0; i+1 < len(f); i++ {
			host = host || (f[i] == "-host-ip" && f[i+1] == "172.100.100.1")
			port = port || (f[i] == "-host-port" && f[i+1] == "49")
		}
		if host && port {
			return "on"
		}
	}
	return "off"
}

// composeStack is the lab's compose project, as startCompose brought it up.
type composeStack struct {
	l         *lab
	t         *testing.T
	dir       string // tests/lab/logs/compose-<platform>
	local     string
	config    string
	logPath   string // compose.log: every command this stack ran
	brokerLog string
	brokerErr string
	overlays  []string // compose files after lab.yaml, by name under tests/lab/compose
	mu        sync.Mutex
	followers []*exec.Cmd
	stoppedAt time.Time
}

// run runs docker compose on the stack's files and records what it ran in
// compose.log.
func (c *composeStack) run(args ...string) (string, error) { return c.runIn("", args...) }

// runIn is run with stdin fed to the command.
func (c *composeStack) runIn(stdin string, args ...string) (string, error) {
	full := []string{"compose", "-p", composeProject, "-f", filepath.Join(root, "deploy", "compose", "compose.yaml"),
		"-f", filepath.Join(root, "tests", "lab", "compose", "lab.yaml")}
	for _, o := range c.overlays {
		full = append(full, "-f", filepath.Join(root, "tests", "lab", "compose", o))
	}
	cmd := exec.Command("docker", append(full, args...)...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "PORT49_COMPOSE_LOCAL="+c.local, "PORT49_COMPOSE_CONFIG="+c.config)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	c.note(fmt.Sprintf("$ docker compose %s\n%s\n(exit: %v)\n", strings.Join(args, " "), out, err))
	return strings.TrimSpace(string(out)), err
}

// note appends text to compose.log.
func (c *composeStack) note(s string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f, err := os.OpenFile(c.logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s", time.Now().UTC().Format(time.RFC3339), s)
}

// tail is the last n lines of compose.log, for a failure's message.
func (c *composeStack) tail(n int) string {
	raw, _ := os.ReadFile(c.logPath)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// follow starts `docker logs -f` on container, stdout appended to out and
// stderr to errp, from since ("0s" is now).
func (c *composeStack) follow(container, since, out, errp string) error {
	open := func(p string) (*os.File, error) {
		return os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	}
	of, err := open(out)
	if err != nil {
		return err
	}
	ef, err := open(errp)
	if err != nil {
		of.Close()
		return err
	}
	cmd := exec.Command("docker", "logs", "-f", "--since", since, container)
	cmd.Stdout, cmd.Stderr = of, ef
	if err := cmd.Start(); err != nil {
		of.Close()
		ef.Close()
		return err
	}
	c.note(fmt.Sprintf("$ docker logs -f --since %s %s (stdout -> %s, stderr -> %s)\n", since, container,
		filepath.Base(out), filepath.Base(errp)))
	c.mu.Lock()
	c.followers = append(c.followers, cmd)
	c.mu.Unlock()
	go func() { cmd.Wait(); of.Close(); ef.Close() }()
	return nil
}

// stopFollowers ends every log follower; what they wrote stays.
func (c *composeStack) stopFollowers() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, f := range c.followers {
		if f.Process != nil {
			_ = f.Process.Kill()
		}
	}
	c.followers = nil
}

// HangStore pauses the three etcd members: port49d's store stops answering
// without a reset, as plan 7d's lab hung it through the proxy.
func (c *composeStack) HangStore() error {
	_, err := c.run("pause", "etcd-1", "etcd-2", "etcd-3")
	return err
}

// ReleaseStore unpauses the three etcd members.
func (c *composeStack) ReleaseStore() error {
	_, err := c.run("unpause", "etcd-1", "etcd-2", "etcd-3")
	return err
}

// StopDaemon stops port49d's container.
func (c *composeStack) StopDaemon() error {
	c.mu.Lock()
	c.stoppedAt = time.Now()
	c.mu.Unlock()
	_, err := c.run("stop", "port49d") // its `docker logs -f` ends with the container
	return err
}

// StartDaemon starts port49d's container again and follows its logs from
// the stop's time, so no line is doubled in l.errPath.
func (c *composeStack) StartDaemon() error {
	if _, err := c.run("start", "port49d"); err != nil {
		return err
	}
	c.mu.Lock()
	since := c.stoppedAt.UTC().Format(time.RFC3339Nano)
	c.mu.Unlock()
	return c.follow(composeProject+"-port49d-1", since, c.l.logPath, c.l.errPath)
}

// Revoke runs `port49 revoke` on the broker's admin socket, in its
// container, and returns what it printed and whether it exited 0, as
// revokeCLI does.
func (c *composeStack) Revoke(args ...string) (string, bool) {
	out, err := c.run(append([]string{"exec", "-T", "port49-broker", "port49", "revoke", "--socket",
		"/run/port49/port49-broker.sock"}, args...)...)
	return out, err == nil
}

// ProxyMode is "on" when Docker's userland proxy serves port49d's published
// TACACS+ port, and "off" when it does not.
func (c *composeStack) ProxyMode() (string, error) {
	out, err := exec.Command("ps", "-eo", "pid,args").Output()
	if err != nil {
		return "", fmt.Errorf("ps: %w", err)
	}
	mode := proxyModeOf(string(out))
	c.note("proxy mode: " + mode + "\n")
	return mode, nil
}

// composeOptions is what a test adds to the lab's compose stack beyond the
// trial's: the plan 7g directory's overlay and configuration. The zero value
// is startCompose's stack.
type composeOptions struct {
	// Overlay is a compose file under tests/lab/compose, merged after lab.yaml.
	Overlay string
	// Files may change the config files (by name, as composeLabFiles makes
	// them) before they are written.
	Files func(files map[string]string) error
	// Prepare runs once the stack's PKI is written and before `up`, to write
	// what the overlay's files read under c.local and slicePKIDir.
	Prepare func(c *composeStack) error
}

// startCompose brings the lab's compose stack up for this platform: the
// standing host port49d stopped, the PKI and the files written, the stack
// built and started, its logs followed into l.logPath and l.errPath, and
// both processes ready. t.Cleanup takes the stack down with its volumes and
// puts the standing daemon back.
func (l *lab) startCompose(t *testing.T) *composeStack {
	t.Helper()
	return l.startComposeWith(t, composeOptions{})
}

// startComposeWith is startCompose with o's additions.
func (l *lab) startComposeWith(t *testing.T, o composeOptions) *composeStack {
	t.Helper()
	c := &composeStack{l: l, t: t}
	if o.Overlay != "" {
		c.overlays = []string{o.Overlay}
	}
	c.dir = filepath.Join(root, "tests", "lab", "logs", "compose-"+l.p.name)
	c.local, c.config = filepath.Join(c.dir, "local"), filepath.Join(c.dir, "config")
	c.logPath = filepath.Join(c.dir, "compose.log")
	c.brokerLog, c.brokerErr = filepath.Join(c.dir, "broker.log"), filepath.Join(c.dir, "broker.err")
	if err := os.RemoveAll(c.dir); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{c.config, c.local} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// The standing config with this platform's session attributes, as
	// prepareSplit derives its base.
	std, err := l.derivedConfig("compose-base", platformSessionAttributes[l.p.name], "# derived for the compose deployment")
	if err != nil {
		t.Fatal(err)
	}
	baseRaw, err := os.ReadFile(std)
	if err != nil {
		t.Fatal(err)
	}
	read := func(rel string) string {
		b, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	files, err := composeLabFiles(string(baseRaw), read("tests/lab/slice/broker.yaml"), read("tests/lab/slice/policy.yaml"),
		read("tests/lab/inventory-lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if o.Files != nil {
		if err := o.Files(files); err != nil {
			t.Fatal(err)
		}
	}

	// Registered before anything is changed, so a test that fails half way
	// still takes the stack down and puts the standing daemon back.
	t.Cleanup(func() {
		if out, err := c.run("down", "-v", "--remove-orphans"); err != nil {
			t.Errorf("docker compose down -v: %v\n%s", err, out)
		}
		c.stopFollowers()
		l.splitActive = false
		std, err := l.configPath()
		if err != nil {
			t.Errorf("derive this platform's daemon config: %v", err)
			return
		}
		if err := l.restart(std); err != nil {
			t.Errorf("could not put port49d back on the lab config: %v", err)
		}
	})
	if err := l.stopDaemon(); err != nil {
		t.Fatal(err)
	}
	l.splitActive = true

	// local/: the stack's PKI and env files, with the broker's PKI the one
	// the agent reads from slicePKIDir (revokeAgent).
	if err := testpki.WriteCompose(c.local, sliceEmail, time.Now()); err != nil {
		t.Fatal(err)
	}
	pki := filepath.Join(root, slicePKIDir)
	if err := testpki.WriteLab(pki, sliceEmail, time.Now()); err != nil {
		t.Fatal(err)
	}
	brokerPKI := filepath.Join(c.local, "broker")
	if err := os.RemoveAll(brokerPKI); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(brokerPKI, 0o700); err != nil {
		t.Fatal(err)
	}
	ents, err := os.ReadDir(pki)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		raw, err := os.ReadFile(filepath.Join(pki, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(brokerPKI, e.Name()), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range files {
		dst := filepath.Join(c.config, name)
		if strings.HasSuffix(name, ".env") {
			dst = filepath.Join(c.local, name)
		}
		if err := os.WriteFile(dst, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if o.Prepare != nil {
		if err := o.Prepare(c); err != nil {
			t.Fatal(err)
		}
	}

	// The clab management network is itself a Docker bridge network, so Docker
	// masquerades everything from 172.100.100.0/24 that leaves by another
	// interface: a device's packet DNAT'd to the compose bridge would reach
	// port49d from the compose gateway. A device off the host never matches that
	// rule (its source is not a Docker network), so this models one: traffic from the clab subnet to the
	// compose subnet is not masqueraded. Without it L39 would measure the
	// lab's own rule, not the published port.
	rule := []string{"-s", "172.100.100.0/24", "-d", "172.30.49.0/24", "-j", "RETURN"}
	sudoIptables := func(args ...string) error {
		out, err := exec.Command("sudo", append([]string{"-n", "iptables"}, args...)...).CombinedOutput()
		c.note(fmt.Sprintf("$ sudo iptables %s\n%s(exit: %v)\n", strings.Join(args, " "), out, err))
		return err
	}
	// registered before the insert, which may fail half way; a missing rule's
	// delete is reported, never fatal
	t.Cleanup(func() {
		if err := sudoIptables(append([]string{"-t", "nat", "-D", "POSTROUTING"}, rule...)...); err != nil {
			t.Logf("removing the RETURN rule for the clab subnet: %v (see compose.log)", err)
		}
	})
	// A run killed before its cleanup (a timeout, SIGQUIT, SIGKILL) leaves its
	// rule in place: purge every stale copy first, so one delete removes the
	// only one.
	purged := 0
	for sudoIptables(append([]string{"-t", "nat", "-D", "POSTROUTING"}, rule...)...) == nil {
		purged++
	}
	c.note(fmt.Sprintf("stale RETURN rules purged before the insert: %d\n", purged))
	if err := sudoIptables(append([]string{"-t", "nat", "-I", "POSTROUTING", "1"}, rule...)...); err != nil {
		t.Fatalf("inserting the RETURN rule that keeps the clab masquerade off device traffic: %v\n%s", err, c.tail(10))
	}

	if out, err := c.run("up", "-d", "--build"); err != nil {
		t.Fatalf("docker compose up: %v\n%s\ncompose.log (tail):\n%s", err, out, c.tail(40))
	}
	l.logPath = filepath.Join(c.dir, "decisions-"+l.p.name+".jsonl")
	l.errPath = filepath.Join(c.dir, "port49d-"+l.p.name+".log")
	if err := c.follow(composeProject+"-port49d-1", "0s", l.logPath, l.errPath); err != nil {
		t.Fatal(err)
	}
	if err := c.follow(composeProject+"-port49-broker-1", "0s", c.brokerLog, c.brokerErr); err != nil {
		t.Fatal(err)
	}
	for _, addr := range []string{"127.0.0.1:9050", "127.0.0.1:9049"} {
		deadline := time.Now().Add(3 * time.Minute)
		for !httpOK("http://" + addr + "/readyz") {
			if time.Now().After(deadline) {
				t.Fatalf("%s/readyz not 200 in 3m\ncompose.log (tail):\n%s", addr, c.tail(40))
			}
			time.Sleep(time.Second)
		}
	}
	if err := l.awaitTACACS(); err != nil {
		t.Fatal(err)
	}
	// The rules in force with the stack up, for the note: the compose bridge's
	// own rules exist only now.
	_ = sudoIptables("-t", "nat", "-S", "POSTROUTING")
	return c
}
