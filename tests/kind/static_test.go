package kind_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/rhwendt/port49/tests/kind/kindtest"
	"gopkg.in/yaml.v3"
)

func read(t *testing.T, rel ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{kindtest.Root()}, rel...)...))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestKindConfigIsPinnedAndHasTwoZones(t *testing.T) {
	var cfg struct {
		Nodes []struct {
			Role   string            `yaml:"role"`
			Image  string            `yaml:"image"`
			Labels map[string]string `yaml:"labels"`
			Ports  any               `yaml:"extraPortMappings"`
		} `yaml:"nodes"`
	}
	if err := yaml.Unmarshal([]byte(read(t, "tests", "kind", "kind.yaml")), &cfg); err != nil {
		t.Fatal(err)
	}
	pinned := regexp.MustCompile(`^kindest/node:v[0-9.]+@sha256:[0-9a-f]{64}$`)
	zones := map[string]int{}
	for _, n := range cfg.Nodes {
		if !pinned.MatchString(n.Image) {
			t.Errorf("a %s node's image %q is not pinned by digest", n.Role, n.Image)
		}
		if n.Ports != nil {
			t.Error("kind.yaml publishes ports: the device dials the node address")
		}
		if n.Role == "worker" {
			zones[n.Labels["topology.kubernetes.io/zone"]]++
		}
	}
	if len(cfg.Nodes) != 3 || zones["a"] != 1 || zones["b"] != 1 {
		t.Errorf("want a control plane and workers in zones a and b: %d nodes, zones %v", len(cfg.Nodes), zones)
	}
}

func TestMakefilePinsKindAndKubectlBySHA256(t *testing.T) {
	mk := read(t, "Makefile")
	for _, v := range []string{"KIND_SHA256_LINUX_AMD64", "KUBECTL_SHA256_LINUX_AMD64"} {
		if !regexp.MustCompile(`(?m)^` + v + ` = [0-9a-f]{64}$`).MatchString(mk) {
			t.Errorf("%s is not a 64 hex digit pin", v)
		}
	}
	for _, want := range []string{"sha256sum -c -", "bin/kind-v$(KIND_VERSION)", "bin/kubectl-$(KUBECTL_VERSION)", "kind-smoke: smoke-keyhost image"} {
		if !strings.Contains(mk, want) {
			t.Errorf("the Makefile lacks %q", want)
		}
	}
}

// A Secret is made from a file, never a literal; a failure never prints one.
func TestSmokeMakesSecretsFromFilesOnly(t *testing.T) {
	for _, f := range []string{"smoke_test.go", "stack.go"} {
		if strings.Contains(read(t, "tests", "kind", f), "--from-literal") {
			t.Errorf("%s names --from-literal", f)
		}
	}
}

// The post-renderer is a test tool: nothing the chart ships names it.
func TestThePostRendererIsNotInTheChart(t *testing.T) {
	err := filepath.WalkDir(filepath.Join(kindtest.Root(), "deploy", "helm"), func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, _ := os.ReadFile(p)
		if strings.Contains(string(b), "oldroot") || strings.Contains(string(b), "post-renderer") {
			t.Errorf("%s names the test-only post-renderer", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// recipe is a Makefile target's text, from its name to the next blank line.
func recipe(t *testing.T, target string) string {
	t.Helper()
	mk := read(t, "Makefile")
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

// A killed or failed run must not leave the cluster: both targets delete it after go test whatever
// its result, and keep go test's exit status; the red target builds the setup image the test loads.
func TestKindTargetsDeleteTheClusterWhateverTheResult(t *testing.T) {
	for _, target := range []string{"kind-smoke", "kind-smoke-red"} {
		r := recipe(t, target)
		goTest := strings.Index(r, "go test -tags kind")
		del := strings.Index(r, "delete cluster --name port49smoke")
		if goTest < 0 || del < goTest {
			t.Errorf("%s does not delete the cluster after go test:\n%s", target, r)
		}
		if !strings.Contains(r, "|| rc=$$?") || !strings.Contains(r, "exit $$rc") {
			t.Errorf("%s loses go test's exit status (needs || rc=$$? ... exit $$rc):\n%s", target, r)
		}
		if !strings.Contains(r, "docker build --target setup -t port49-setup:dev .") {
			t.Errorf("%s does not build the setup image the test loads", target)
		}
	}
}

// The smoke's own guard: Up arms it, and the host port49d is registered with it by pid.
func TestSmokeRegistersWhatAKilledRunMustStop(t *testing.T) {
	smoke := read(t, "tests", "kind", "smoke_test.go")
	if !strings.Contains(smoke, "s.c.Guard.Process(cmd)") {
		t.Error("the host port49d is not registered with the guard by pid")
	}
	up := read(t, "tests", "kind", "kindtest", "kindtest.go")
	for _, want := range []string{"shapetest.NewGuard(", `c.deleteCluster(t, "stale")`, `exec.Command(kind, "delete", "cluster"`} {
		if !strings.Contains(up, want) {
			t.Errorf("kindtest.Up lacks %q", want)
		}
	}
}

// The fsGroup cell asserts the volume is local, and the walk, before it counts as green.
func TestFSGroupCellChecksTheVolumeAndTheWalk(t *testing.T) {
	smoke := read(t, "tests", "kind", "smoke_test.go")
	if n := strings.Count(smoke, "RequireLocalPV("); n != 2 {
		t.Errorf("RequireLocalPV is called %d times, want in both the green and the red path", n)
	}
	if !strings.Contains(smoke, "walk-probe") {
		t.Error("the fsGroup cell has no walk probe")
	}
	if !strings.Contains(smoke, "kindtest.PermitMint(") || strings.Contains(smoke, "strings.Contains(logs, principal)") {
		t.Error("the workload cell does not match the permit mint record")
	}
}

// L82's target pins the operator's chart by sha256 as the others pin their tools, builds the setup
// image the test loads, and deletes its cluster after go test whatever the result. The test file
// makes Secrets from files only and never prints one: it reads a Secret only for its key names.
func TestL82TargetPinsTheChartAndDeletesTheCluster(t *testing.T) {
	mk := read(t, "Makefile")
	if !regexp.MustCompile(`(?m)^ESO_CHART_SHA256 = [0-9a-f]{64}$`).MatchString(mk) {
		t.Error("ESO_CHART_SHA256 is not a 64 hex digit pin")
	}
	chart := recipe(t, "bin/external-secrets-$(ESO_VERSION).tgz")
	if !strings.Contains(chart, `echo "$(ESO_CHART_SHA256)  bin/eso.dl" | sha256sum -c -`) {
		t.Errorf("the chart is not checked against its pin before it is moved into place:\n%s", chart)
	}
	r := recipe(t, "lab-l82")
	goTest := strings.Index(r, "go test -tags lab")
	del := strings.Index(r, "delete cluster --name port49l82")
	if goTest < 0 || del < goTest || !strings.Contains(r, "|| rc=$$?") || !strings.Contains(r, "exit $$rc") {
		t.Errorf("lab-l82 does not delete the cluster after go test and keep its exit status:\n%s", r)
	}
	if !strings.Contains(r, "docker build --target setup -t port49-setup:dev .") {
		t.Error("lab-l82 does not build the setup image the stack loads")
	}
	if !strings.Contains(r, "-run '^TestL82$$'") {
		t.Error("lab-l82 does not run its one test by an anchored name")
	}
	src := read(t, "tests", "lab", "l82_test.go")
	for _, bad := range []string{"--from-literal", "-o yaml", "-o json", "jsonpath={.data", "-o jsonpath={.data"} {
		if strings.Contains(src, bad) {
			t.Errorf("l82_test.go contains %q: a Secret is made from a file and read only for its key names", bad)
		}
	}
	if !strings.Contains(src, `go-template={{range $k, $v := .data}}{{$k}} {{end}}`) {
		t.Error("l82_test.go does not read the Secret's key names through the template that prints names only")
	}
	if !strings.Contains(src, "ExternalSecretFromExample(") || strings.Contains(src, `"creationPolicy"`) {
		t.Error("l82_test.go does not build its ExternalSecret from the shipped example, or sets creationPolicy itself: (d) measures what operators copy, Owner included")
	}
	if strings.Contains(src, "labOccupyForRun") || strings.Contains(src, "labGuardAt") {
		t.Error("l82_test.go takes the lab lock: there is no shared lab host in CI, and the key-host guard alone refuses on a developer machine")
	}
}

// L83's target pins both charts by sha256, builds the setup image, runs its one test by an anchored
// name and deletes its cluster after go test. Its test file never reads a Secret, makes Secrets from
// files only, and hands Vault's root token to nothing but a Secret made from a file and the vault
// pod's own environment variable.
func TestL83TargetPinsTheChartsAndDeletesTheCluster(t *testing.T) {
	mk := read(t, "Makefile")
	for _, v := range []string{"VAULT_CHART_SHA256", "CSI_CHART_SHA256"} {
		if !regexp.MustCompile(`(?m)^` + v + ` = [0-9a-f]{64}$`).MatchString(mk) {
			t.Errorf("%s is not a 64 hex digit pin", v)
		}
	}
	for _, c := range []struct{ target, dl, sum string }{
		{"bin/vault-$(VAULT_VERSION).tgz", "bin/vault.dl", "$(VAULT_CHART_SHA256)"},
		{"bin/secrets-store-csi-driver-$(CSI_VERSION).tgz", "bin/csi.dl", "$(CSI_CHART_SHA256)"},
	} {
		if r := recipe(t, c.target); !strings.Contains(r, `echo "`+c.sum+`  `+c.dl+`" | sha256sum -c -`) {
			t.Errorf("%s is not checked against its pin before it is moved into place:\n%s", c.target, r)
		}
	}
	r := recipe(t, "lab-l83")
	goTest := strings.Index(r, "go test -tags lab")
	del := strings.Index(r, "delete cluster --name port49l83")
	if goTest < 0 || del < goTest || !strings.Contains(r, "|| rc=$$?") || !strings.Contains(r, "exit $$rc") {
		t.Errorf("lab-l83 does not delete the cluster after go test and keep its exit status:\n%s", r)
	}
	if !strings.Contains(r, "docker build --target setup -t port49-setup:dev .") || !strings.Contains(r, "-run '^TestL83$$'") {
		t.Error("lab-l83 does not build the setup image, or does not run its one test by an anchored name")
	}
	for _, need := range []string{"bin/vault-$(VAULT_VERSION).tgz", "bin/secrets-store-csi-driver-$(CSI_VERSION).tgz"} {
		if !strings.Contains(r, need) && !strings.Contains(mk[strings.Index(mk, "\nlab-l83:"):], need) {
			t.Errorf("lab-l83 does not depend on %s", need)
		}
	}
	src := read(t, "tests", "lab", "l83_test.go")
	for _, bad := range []string{"--from-literal", "-o yaml", "devRootToken: root", `"get", "secret"`, "get secret", "jsonpath={.data"} {
		if strings.Contains(src, bad) {
			t.Errorf("l83_test.go contains %q: a Secret is made from a file and never read, and the root token is random", bad)
		}
	}
	for _, want := range []string{`"--from-file=token="+`, `-dev-root-token-id="$L83_ROOT"`, `secretName: vault-root, secretKey: token`} {
		if !strings.Contains(src, want) {
			t.Errorf("l83_test.go lacks %q: the root token is a Secret made from a file, read by the vault pod's own variable", want)
		}
	}
	// the token is made once, from the random helper, and is the only thing the file passes through
	// `write`; nothing prints or logs it
	if strings.Count(src, "root") > 0 {
		for i, ln := range strings.Split(src, "\n") {
			if strings.Contains(ln, "root") && regexp.MustCompile(`(?i)(Logf|Errorf|Fatalf|Printf|Println|Sprintf)\(.*\broot\b`).MatchString(ln) {
				t.Errorf("l83_test.go:%d prints the root token: %s", i+1, ln)
			}
		}
	}
	if strings.Contains(src, "labOccupyForRun") || strings.Contains(src, "labGuardAt") {
		t.Error("l83_test.go takes the lab lock: there is no shared lab host in CI")
	}
}

// L85's target pins the chart by sha256, runs its one test by an anchored name and removes the
// cluster, the two containers and the network it makes, by their fixed names, after go test. Its
// test file pins FRR by digest, never reads a Secret and never prints the device's key or a token.
func TestL85TargetPinsTheChartAndCleansUp(t *testing.T) {
	mk := read(t, "Makefile")
	if !regexp.MustCompile(`(?m)^METALLB_CHART_SHA256 = [0-9a-f]{64}$`).MatchString(mk) {
		t.Error("METALLB_CHART_SHA256 is not a 64 hex digit pin")
	}
	if r := recipe(t, "bin/metallb-$(METALLB_VERSION).tgz"); !strings.Contains(r, `echo "$(METALLB_CHART_SHA256)  bin/metallb.dl" | sha256sum -c -`) {
		t.Errorf("the chart is not checked against its pin before it is moved into place:\n%s", r)
	}
	r := recipe(t, "lab-l85")
	goTest := strings.Index(r, "go test -tags lab")
	for _, after := range []string{"delete cluster --name port49l85", "docker rm -f port49l85-frr port49l85-client", "docker network rm port49l85dev"} {
		if i := strings.Index(r, after); goTest < 0 || i < goTest {
			t.Errorf("lab-l85 does not run %q after go test:\n%s", after, r)
		}
	}
	if !strings.Contains(r, "|| rc=$$?") || !strings.Contains(r, "exit $$rc") || !strings.Contains(r, "-run '^TestL85$$'") ||
		!strings.Contains(r, "docker build --target setup -t port49-setup:dev .") || !strings.Contains(r, "bin/metallb-$(METALLB_VERSION).tgz") {
		t.Errorf("lab-l85 keeps no exit status, is not anchored, builds no setup image or lacks the chart:\n%s", r)
	}
	src := read(t, "tests", "lab", "l85_test.go")
	if !regexp.MustCompile(`quay\.io/frrouting/frr:[0-9.]+@sha256:[0-9a-f]{64}`).MatchString(src) {
		t.Error("l85_test.go does not pin FRR's image by digest")
	}
	for _, bad := range []string{"--from-literal", `"get", "secret"`, "get secret", "-o yaml", "labOccupyForRun", "labGuardAt", "docker inspect", "--privileged"} {
		if strings.Contains(src, bad) {
			t.Errorf("l85_test.go contains %q", bad)
		}
	}
	for i, ln := range strings.Split(src, "\n") {
		if regexp.MustCompile(`(Logf|Errorf|Fatalf|Printf|Println|Sprintf)\(.*\b(r\.key|r\.creds\(\)|r\.mint\(\))`).MatchString(ln) {
			t.Errorf("l85_test.go:%d prints the key or a token: %s", i+1, ln)
		}
	}
	if !strings.Contains(src, "shapetest.RefuseOnKeyHost(t)") {
		t.Error("l85_test.go does not refuse on a key host before it makes a container")
	}
}

// On a fresh runner the docker network named kind does not exist until kind creates the cluster:
// bringUp reads it only after kindtest.Up, and nothing uses the subnet or gateway before that.
func TestBringUpReadsTheKindNetworkAfterTheClusterIsUp(t *testing.T) {
	src := read(t, "tests", "kind", "stack.go")
	i := strings.Index(src, "func bringUp(")
	if i < 0 {
		t.Fatal("no bringUp")
	}
	body := src[i:]
	up := strings.Index(body, "kindtest.UpWith(")
	net := strings.Index(body, "dockerKindNetwork(t)")
	if up < 0 || net < 0 || net < up {
		t.Errorf("bringUp reads the kind network (at %d) before kindtest.Up (at %d)", net, up)
	}
	for _, field := range []string{"s.subnet", "s.gateway"} {
		if f := strings.Index(body, field); f >= 0 && f < up {
			t.Errorf("bringUp uses %s before kindtest.Up", field)
		}
	}
}

// store-roles refuses two components with one CN, and both rendered configs name the same client
// certificate path: the bring-up's pod must read the broker's config with its own Secret's path.
func TestStoreRolesReadsTheBrokersOwnCertificate(t *testing.T) {
	src := read(t, "tests", "kind", "stack.go")
	for _, want := range []string{`{"name":"eb","mountPath":"/etc/port49/etcd-broker"}`, `"secretName":"port49-etcd-broker"`, `"name":"store-roles-broker"`, "s.c.PodReport(ns, \"store-roles\")"} {
		if !strings.Contains(src, want) {
			t.Errorf("stack.go lacks %s", want)
		}
	}
}

// The chart's root init adds DAC_READ_SEARCH, which Pod Security baseline refuses (tests/helm's
// TestTheReadmeNamesThePodSecurityLevelTheCapabilitiesNeed): a stack that labels its namespace
// baseline never gets a pod.
func TestTheStackLabelsItsNamespaceWithTheLevelTheChartNeeds(t *testing.T) {
	src := read(t, "tests", "kind", "stack.go")
	if !strings.Contains(src, "pod-security.kubernetes.io/enforce=privileged") || strings.Contains(src, "enforce=baseline") {
		t.Error("stack.go does not enforce the privileged Pod Security level on the namespace")
	}
}
