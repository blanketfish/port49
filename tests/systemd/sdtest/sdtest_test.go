package sdtest

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/rhwendt/port49/tests/kind/kindtest"
	"gopkg.in/yaml.v3"
)

func shipped(t *testing.T, rel ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{kindtest.Root(), "deploy", "systemd"}, rel...)...))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func withoutComments(s string) string {
	var keep []string
	for _, l := range strings.Split(s, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(l), "#") {
			keep = append(keep, l)
		}
	}
	return strings.Join(keep, "\n")
}

func TestMemberRewritesEachExampleToItsOwnPorts(t *testing.T) {
	seen := map[string]bool{}
	for n := 1; n <= 3; n++ {
		out, err := Member(shipped(t, "examples", "etcd-"+string(rune('0'+n))+".yaml"), n)
		if err != nil {
			t.Fatal(err)
		}
		if live := withoutComments(out); strings.Contains(live, "example.com") || strings.Contains(live, "0.0.0.0") {
			t.Errorf("member %d keeps a name it cannot use in one container:\n%s", n, out)
		}
		var doc map[string]any
		if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatal(err)
		}
		c, p := ClientPort(n), PeerPort(n)
		if doc["listen-client-urls"] != "https://127.0.0.1:"+itoa(c) || doc["listen-peer-urls"] != "https://127.0.0.1:"+itoa(p) {
			t.Errorf("member %d listens on %v / %v, want %d / %d", n, doc["listen-client-urls"], doc["listen-peer-urls"], c, p)
		}
		if doc["advertise-client-urls"] != "https://localhost:"+itoa(c) {
			t.Errorf("member %d advertises %v", n, doc["advertise-client-urls"])
		}
		ic, _ := doc["initial-cluster"].(string)
		for m := 1; m <= 3; m++ {
			if !strings.Contains(ic, "etcd-"+itoa(m)+"=https://localhost:"+itoa(PeerPort(m))) {
				t.Errorf("member %d's initial-cluster lacks member %d's peer port: %s", n, m, ic)
			}
		}
		if seen[itoa(c)] {
			t.Errorf("client port %d is used twice", c)
		}
		seen[itoa(c)] = true
	}
	if ClientPort(1) != 2379 || PeerPort(1) != 2380 || ClientPort(2) != 2479 || PeerPort(2) != 2480 || ClientPort(3) != 2579 || PeerPort(3) != 2580 {
		t.Error("the ports are not the brief's 2379/2380, 2479/2480, 2579/2580")
	}
	if _, err := Member("name: etcd-1\n", 1); err == nil {
		t.Error("a member file with nothing to rewrite was accepted")
	}
}

func TestEndpointsNamesEveryMemberByItsPort(t *testing.T) {
	for _, f := range []string{"port49d.yaml", "port49-broker.yaml"} {
		out, err := Endpoints(shipped(t, "config", f))
		if err != nil {
			t.Fatal(err)
		}
		for n := 1; n <= 3; n++ {
			if !strings.Contains(out, "https://localhost:"+itoa(ClientPort(n))) {
				t.Errorf("%s lacks member %d's URL", f, n)
			}
		}
		if strings.Contains(withoutComments(out), "example.com") {
			t.Errorf("%s keeps example.com", f)
		}
	}
	if _, err := Endpoints("stores: {}\n"); err == nil {
		t.Error("a config with no endpoints was accepted")
	}
}

func TestPolicyIsKeyedKAndAdmitsTheSubnet(t *testing.T) {
	out, err := Policy(shipped(t, "config", "policy.yaml"), "172.31.49.0/24")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		KeyGroups []struct {
			Match  struct{ CIDR string } `yaml:"match"`
			KeyRef string                `yaml:"key_ref"`
		} `yaml:"key_groups"`
		Keys map[string]struct {
			Current struct {
				SecretRef string `yaml:"secret_ref"`
			} `yaml:"current"`
		} `yaml:"keys"`
	}
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.KeyGroups) != 1 || doc.KeyGroups[0].Match.CIDR != "172.31.49.0/24" || doc.KeyGroups[0].KeyRef != "k" {
		t.Errorf("key_groups: %+v", doc.KeyGroups)
	}
	if doc.Keys["k"].Current.SecretRef != "file:/etc/port49/keys/tacacs_v1" {
		t.Errorf("keys.k: %+v", doc.Keys)
	}
}

func TestNoKeysDropsTheKeysBlockOnly(t *testing.T) {
	p, _ := Policy(shipped(t, "config", "policy.yaml"), "172.31.49.0/24")
	out, err := NoKeys(p)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc["keys"]; ok {
		t.Error("keys: is still there")
	}
	if _, ok := doc["key_groups"]; !ok {
		t.Error("key_groups was dropped with it: the refusal would be a different one")
	}
	if _, err := NoKeys("scopes: []\n"); err == nil {
		t.Error("a policy with no keys: was accepted")
	}
}

func TestBrokerForATrialAndMetricsOnTheBridge(t *testing.T) {
	b, err := Broker(shipped(t, "config", "port49-broker.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b, "certificate_status: {disabled: true}") || !strings.Contains(b, `metrics_listen: ":9050"`) || strings.Contains(b, "use_aia") {
		t.Errorf("broker config:\n%s", b)
	}
	d, err := Daemon(shipped(t, "config", "port49d.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d, `metrics_listen: ":9049"`) {
		t.Errorf("port49d config:\n%s", d)
	}
	if _, err := Daemon("listen: \":49\"\n"); err == nil {
		t.Error("a daemon config with no metrics_listen was accepted")
	}
}

func TestParseShow(t *testing.T) {
	m := ParseShow("NRestarts=3\nActiveState=activating\nExecMainStartTimestamp=Wed 2026-10-28 10:00:00 UTC\nEmpty=\n")
	if m["NRestarts"] != "3" || m["ActiveState"] != "activating" || m["ExecMainStartTimestamp"] != "Wed 2026-10-28 10:00:00 UTC" {
		t.Errorf("%v", m)
	}
	if v, ok := m["Empty"]; !ok || v != "" {
		t.Errorf("an empty value: %q %v", v, ok)
	}
}

func TestRefusalNamesTheDirectory(t *testing.T) {
	line := "port49d: config: /etc is mode drwxrwxr-x, writable by others than its owner; whoever can write it decides who gets access - chmod go-w it"
	if !Refusal(line, "/etc") {
		t.Error("the fence's line is not recognised")
	}
	if Refusal(line, "/var/spool") || Refusal("port49d: /etc is mode drwxr-xr-x; fine", "/etc") {
		t.Error("a line about another directory, or one that is not a refusal, was recognised")
	}
}

// Plan 7's 3am ruling: a unit waiting on a down store or a bad policy recovers by itself, so neither
// unit may ever reach `failed` from restarts (the smoke asserts the behaviour, this the setting).
func TestBothUnitsHaveNoStartLimit(t *testing.T) {
	for _, u := range []string{"port49d.service", "port49-broker.service"} {
		if !regexp.MustCompile(`(?m)^StartLimitIntervalSec=0$`).MatchString(shipped(t, u)) {
			t.Errorf("%s does not set StartLimitIntervalSec=0", u)
		}
	}
}

// The smoke does not make /var/lib/etcd; the shipped tmpfiles file does, 0700 etcd:etcd.
func TestTmpfilesMakesEtcdsDataDirectory(t *testing.T) {
	live := withoutComments(shipped(t, "examples", "tmpfiles-etcd.conf"))
	if !regexp.MustCompile(`(?m)^d /var/lib/etcd 0700 etcd etcd -$`).MatchString(live) {
		t.Errorf("tmpfiles-etcd.conf does not make /var/lib/etcd 0700 etcd:etcd:\n%s", live)
	}
	if !strings.Contains(shipped(t, "README.md"), "`tmpfiles-etcd.conf`, `/var/lib/etcd` 0700") {
		t.Error("the README does not say tmpfiles-etcd.conf makes /var/lib/etcd")
	}
}

func TestRunArgsGrantsOnlySysAdminAndNoDevice(t *testing.T) {
	args := RunArgs("c", "n", "img:dev")
	line := strings.Join(args, " ")
	if f := Forbidden(line); len(f) != 0 {
		t.Fatalf("the docker run line grants %v: %s", f, line)
	}
	var caps []string
	for i, a := range args {
		if a == "--cap-add" {
			caps = append(caps, args[i+1])
		}
		for _, bad := range []string{"-v", "--volume", "--mount", "--device", "--privileged", "--pid=host", "--net=host", "--network=host"} {
			if a == bad {
				t.Errorf("the docker run line has %s", bad)
			}
		}
	}
	if strings.Join(caps, ",") != "SYS_ADMIN" {
		t.Errorf("capabilities added: %v, want exactly SYS_ADMIN", caps)
	}
	for _, want := range []string{"--cgroupns=private", "--tmpfs /run", "--tmpfs /run/lock", "--tmpfs /tmp", "--security-opt apparmor=unconfined"} {
		if !strings.Contains(line, want) {
			t.Errorf("the docker run line lacks %q: %s", want, line)
		}
	}
	for i, a := range args {
		if a == "-p" && !strings.HasPrefix(args[i+1], "127.0.0.1:") {
			t.Errorf("port %s is published beyond 127.0.0.1", args[i+1])
		}
	}
	if args[len(args)-1] != "img:dev" || args[0] != "run" {
		t.Errorf("the line does not run the image: %v", args)
	}
}

func TestForbiddenFindsEveryWayToHandOverTheHostsDevices(t *testing.T) {
	for text, want := range map[string]string{
		"docker run --privileged x":                                      "--privileged",
		"docker run --device /dev/tpm0 x":                                "--device",
		"docker run --device=/dev/bus/usb x":                             "--device",
		"docker run -v /dev:/dev x":                                      "a bind mount of /dev",
		"docker run --volume /dev/bus/usb:/dev/bus/usb x":                "a bind mount of /dev",
		"docker run --volume=/dev:/dev x":                                "a bind mount of /dev",
		"docker run --mount type=bind,source=/dev,target=/dev x":         "a bind mount of /dev",
		"docker run --mount type=bind,src=/dev/hidraw0,target=/x x":      "a bind mount of /dev",
		"docker run --cap-add ALL x":                                     "--cap-add ALL",
		"docker run --cap-add=all x":                                     "--cap-add all",
		`"run", "-d", "--privileged", "--cgroupns=private"`:              "--privileged",
		"docker run --cap-add SYS_ADMIN --privileged --tmpfs /run image": "--privileged",
		"docker run --cap-add SYS_PTRACE x":                              "--cap-add SYS_PTRACE",
		"docker run --device-cgroup-rule='c 10:* rmw' x":                 "--device-cgroup-rule",
		"docker run --security-opt seccomp=unconfined x":                 "seccomp=unconfined",
		"docker run --pid=host x":                                        "the host's pid namespace",
		"docker run --pid host x":                                        "the host's pid namespace",
		"docker run --userns=host x":                                     "the host's user namespace",
		"docker run --network=host x":                                    "the host's network namespace",
		"docker run --net host x":                                        "the host's network namespace",
		"docker run -v /sys:/sys x":                                      "a bind mount of /sys",
		"docker run -v /:/host x":                                        "a bind mount of /",
		"docker run --mount type=bind,source=/,target=/h x":              "a bind mount of /",
	} {
		got := Forbidden(text)
		if len(got) == 0 || got[0] != want {
			t.Errorf("%q: found %v, want %s", text, got, want)
		}
	}
	for _, ok := range []string{
		"docker run --cgroupns=private --cap-add SYS_ADMIN --security-opt apparmor=unconfined --tmpfs /run image",
		"docker run -v /sys/fs/cgroup:/sys/fs/cgroup:ro image",
		"docker run -v /var/devices:/x image",
		"docker run --tmpfs /dev/shm image", // a tmpfs is not a host device
		"docker run -v /sys/fs/cgroup:/sys/fs/cgroup:ro --cap-add=SYS_ADMIN image",
		`"--cap-add", "SYS_ADMIN"`,
	} {
		if got := Forbidden(ok); len(got) != 0 {
			t.Errorf("%q was refused for %v", ok, got)
		}
	}
}

// Nothing the smoke runs hands the container a host device, whichever file starts it: the Go harness,
// the image, the two Makefile recipes and the workflow. The Go harness runs the container only through
// RunArgs.
func TestTheHarnessNeverGrantsTheHostsDevices(t *testing.T) {
	root := kindtest.Root()
	read := func(rel ...string) string {
		b, err := os.ReadFile(filepath.Join(append([]string{root}, rel...)...))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	files := map[string]string{
		"tests/systemd/Dockerfile":      read("tests", "systemd", "Dockerfile"),
		".github/workflows/systemd.yml": read(".github", "workflows", "systemd.yml"),
	}
	// Every Go file in the smoke's package, whatever it is named: a new file that runs docker is scanned.
	goFiles, err := filepath.Glob(filepath.Join(root, "tests", "systemd", "*.go"))
	if err != nil || len(goFiles) < 3 {
		t.Fatalf("found %d Go files in tests/systemd (%v), want smoke_test.go, cells_test.go and l84_test.go at least", len(goFiles), err)
	}
	for _, f := range goFiles {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		files["tests/systemd/"+filepath.Base(f)] = string(b)
	}
	mk := read("Makefile")
	for _, target := range []string{"systemd-smoke", "lab-l84-systemd"} {
		files["Makefile "+target] = recipe(t, mk, target)
	}
	for name, text := range files {
		if f := Forbidden(text); len(f) != 0 {
			t.Errorf("%s grants %v", name, f)
		}
	}
	smoke := files["tests/systemd/smoke_test.go"]
	if !strings.Contains(smoke, "sdtest.RunArgs(container, network, image)") || strings.Contains(smoke, `"run", "-d"`) {
		t.Error("the smoke does not start its container through sdtest.RunArgs alone")
	}
	if !strings.Contains(smoke, `breakGlass := must(sdtest.BreakGlass(readHost(t, filepath.Join(u.root, "deploy", "systemd", "README.md"))))`) ||
		!strings.Contains(smoke, "line := breakGlass\n") || !strings.Contains(smoke, "\t\tb.sh(line)\n") || strings.Contains(smoke, "runuser") {
		t.Error("the smoke does not run the README's break-glass line as written")
	}
	if !strings.Contains(read("tests", "systemd", "Dockerfile"), "dbus ca-certificates sudo") {
		t.Error("the image has no sudo, which the README's break-glass line needs")
	}
	if !strings.Contains(read("tests", "systemd", "Dockerfile"), "mount -o remount,rw /sys/fs/cgroup") {
		t.Error("the image's init does not make its own cgroup mount writable: a container without full privilege has it read-only")
	}
}

// recipe is a Makefile target's text, from its name to the next blank line.
func recipe(t *testing.T, mk, target string) string {
	t.Helper()
	i := strings.Index(mk, "\n"+target+":")
	if i < 0 {
		t.Fatalf("the Makefile has no %s target", target)
	}
	rest := mk[i+1:]
	if j := strings.Index(rest, "\n\n"); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// A killed run (the workflow cancelled, make interrupted) must not leave the container or its network:
// both targets remove them after go test whatever its result and keep its exit status, and the workflow
// does the same in a step that always runs.
func TestAKilledRunLeavesNoContainerOrNetwork(t *testing.T) {
	mk := func() string {
		b, err := os.ReadFile(filepath.Join(kindtest.Root(), "Makefile"))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}()
	for _, target := range []string{"systemd-smoke", "lab-l84-systemd"} {
		r := recipe(t, mk, target)
		goTest := strings.Index(r, "go test -tags systemd")
		rm := strings.Index(r, "docker rm -f port49systemd")
		net := strings.Index(r, "docker network rm port49systemd")
		if goTest < 0 || rm < goTest || net < goTest {
			t.Errorf("%s does not remove the container and network after go test:\n%s", target, r)
		}
		if !strings.Contains(r, "|| rc=$$?") || !strings.Contains(r, "exit $$rc") {
			t.Errorf("%s loses go test's exit status:\n%s", target, r)
		}
	}
	wf, err := os.ReadFile(filepath.Join(kindtest.Root(), ".github", "workflows", "systemd.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Jobs map[string]struct {
			Steps []struct {
				If  string `yaml:"if"`
				Run string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(wf, &doc); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range doc.Jobs["smoke"].Steps {
		if s.If == "always()" && strings.Contains(s.Run, "docker rm -f port49systemd") && strings.Contains(s.Run, "docker network rm port49systemd") {
			found = true
		}
	}
	if !found {
		t.Error("the workflow has no always() step that removes the container and the network")
	}
}

func TestParseStatAndWant(t *testing.T) {
	st, err := ParseStat("port49-broker:port49-broker 700 /var/backups/port49-broker\nroot:root 600 /var/backups/port49/etcd-2026-10-28.db\n")
	if err != nil || len(st) != 2 {
		t.Fatalf("%v %v", st, err)
	}
	if err := st[0].Want("port49-broker:port49-broker", "700"); err != nil {
		t.Error(err)
	}
	if st[1].Want("root:root", "644") == nil || st[1].Want("etcd:etcd", "600") == nil {
		t.Error("a wrong mode or owner passed")
	}
	for _, bad := range []string{"root 600 /x", "root:root rw /x", "root:root 600", ""} {
		if _, err := ParseStat(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestParseSecurityReadsTheUnitRows(t *testing.T) {
	out := "UNIT                  EXPOSURE PREDICATE HAPPY\nport49d.service            2.0 OK        \U0001F642\nport49-broker.service      1.8 OK        \U0001F642\n"
	m, err := ParseSecurity(out)
	if err != nil || m["port49d.service"] != 2.0 || m["port49-broker.service"] != 1.8 {
		t.Fatalf("%v %v", m, err)
	}
	for _, bad := range []string{"", "no table here\n", "port49d.service  UNSAFE OK\n"} {
		if _, err := ParseSecurity(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

// The smoke runs the README's break-glass line as written, so the README must hold exactly one.
func TestTheREADMEHoldsOneBreakGlassLine(t *testing.T) {
	line, err := BreakGlass(shipped(t, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	if line != "sudo -u port49-broker port49-broker revoke --offline --principal user:bob@example.com" {
		t.Errorf("the README's break-glass line is %q: the smoke revokes bob", line)
	}
	if _, err := BreakGlass("nothing here"); err == nil {
		t.Error("a README with no break-glass line was accepted")
	}
	if _, err := BreakGlass(line + "\n" + line + "\n"); err == nil {
		t.Error("two break-glass lines were accepted")
	}
}

func TestReReadFindsEveryReloadLine(t *testing.T) {
	j := "broker: SIGHUP: per_login_mfa hardware_key_touch verifies attestations against /etc/port49/broker/attestation-roots.pem; re-read: 1 roots (was 1)\n" +
		"other\nbroker: SIGHUP: x; re-read: 2 roots (was 1)\n"
	got := ReRead(j)
	if len(got) != 2 || got[0] != [2]int{1, 1} || got[1] != [2]int{2, 1} {
		t.Errorf("%v", got)
	}
	if len(ReRead("broker: SIGHUP: keeping the attestation roots already in force")) != 0 {
		t.Error("a refused reload was read as a re-read")
	}
}

// The smoke does not make the directories it puts files in: tmpfiles.d does, and the README says so.
func TestTmpfilesMakesTheConfigDirectories(t *testing.T) {
	port49 := withoutComments(shipped(t, "tmpfiles.d", "port49.conf"))
	for _, want := range []string{`^d /etc/port49/etcd 0755 root root -$`, `^d /etc/port49/broker 0755 root root -$`} {
		if !regexp.MustCompile(`(?m)` + want).MatchString(port49) {
			t.Errorf("tmpfiles.d/port49.conf lacks %s", want)
		}
	}
	etcd := withoutComments(shipped(t, "examples", "tmpfiles-etcd.conf"))
	for _, want := range []string{`^d /etc/etcd 0755 root root -$`, `^d /etc/etcd/pki 0755 root root -$`} {
		if !regexp.MustCompile(`(?m)` + want).MatchString(etcd) {
			t.Errorf("tmpfiles-etcd.conf lacks %s", want)
		}
	}
	smoke, err := os.ReadFile(filepath.Join(kindtest.Root(), "tests", "systemd", "smoke_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(smoke), "install -d") {
		t.Error("the smoke makes a directory itself (install -d): the shipped tmpfiles.d should")
	}
}

// The smokes whose containers or nodes could reach host root refuse to start on a host with a TPM or a
// Yubico key: the Makefile runs the check first, and each harness runs it before it starts anything.
func TestSmokesRefuseOnAKeyHost(t *testing.T) {
	root := kindtest.Root()
	read := func(rel ...string) string {
		b, err := os.ReadFile(filepath.Join(append([]string{root}, rel...)...))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	mk := read("Makefile")
	for _, target := range []string{"systemd-smoke", "kind-smoke", "kind-smoke-red", "lab-l84-systemd"} {
		first := strings.Fields(strings.SplitN(strings.TrimPrefix(strings.SplitN(mk[strings.Index(mk, "\n"+target+":")+1:], "\n", 2)[0], target+":"), "##", 2)[0])
		if len(first) == 0 || first[0] != "smoke-keyhost" {
			t.Errorf("%s does not run smoke-keyhost before anything else (prerequisites %v)", target, first)
		}
	}
	if r := recipe(t, mk, "smoke-keyhost"); !strings.Contains(r, "go run ./tests/shapes/cmd/keyhost") {
		t.Errorf("smoke-keyhost does not run the guard:\n%s", r)
	}
	for _, c := range []struct{ file, after string }{
		{"tests/systemd/smoke_test.go", "func newBox(t *testing.T) box {\n\tt.Helper()\n\tshapetest.RefuseOnKeyHost(t)"},
		{"tests/kind/smoke_test.go", "func TestKindSmoke(t *testing.T) {\n\tshapetest.RefuseOnKeyHost(t)"},
		{"tests/kind/kindtest/kindtest.go", "\tt.Helper()\n\tshapetest.RefuseOnKeyHost(t)\n\tkind := Bin("},
	} {
		if !strings.Contains(read(strings.Split(c.file, "/")...), c.after) {
			t.Errorf("%s does not refuse on a key host before it starts anything", c.file)
		}
	}
	if !strings.Contains(read("Makefile"), "NOT an\n# isolation boundary") && !strings.Contains(mk, "isolation boundary") {
		t.Error("the Makefile comment does not say the container is not an isolation boundary")
	}
	if strings.Contains(mk, "the host's TPM\n# and security key stay out of it") {
		t.Error("the Makefile still claims the flags keep the host's TPM and key out")
	}
}
