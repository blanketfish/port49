//go:build lab

package lab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/tests/lab/labcreds"
)

// L69 (plan 10; spec §13 decision 49; §15 L69): a Kubernetes cluster's service
// account tokens as port49's k8s verifier meets them, on two kind clusters and
// a local bin/port49d with a broker, no device. The harness drives the kind and
// kubectl binaries; every token it reads stays in memory and in a 0600 file
// under t.TempDir(), is registered as a secret, and reaches the evidence and
// the note only as decoded claims and a sha256.
const (
	// l69Claim is spec §15's L69 row, word for word (a unit test holds it).
	l69Claim = "A Kubernetes cluster's service account tokens as port49's `k8s` verifier meets them (plan 10), on " +
		"kind: (a) a projected token's claims for `audience: port49-lab`, `expirationSeconds: 600` (`iss`, " +
		"`aud`, `exp` − `iat`, `nbf`, `sub`, `kubernetes.io` with `namespace`, `serviceaccount`, `pod`, " +
		"`node`, `jti`; the header's `alg`, `kid` and `typ`); (b) when the kubelet rewrites the file, as a " +
		"fraction of `expirationSeconds`; (c) the issuer discovery document and `/openid/v1/jwks` read " +
		"anonymously before and after binding `system:service-account-issuer-discovery` to " +
		"`system:unauthenticated`, and discovery's `issuer` and `jwks_uri` against the API server's flags; " +
		"(d) a signing key rotated at the API server, and whether port49 mints with the new key's token " +
		"without a restart; (e) a token after its pod, then its service account, is deleted: what " +
		"TokenReview answers and what port49 does; (f) a second cluster's token at a broker that lists only " +
		"the first, for a namespace only the first lists, and for a namespace both list; (g) a token for " +
		"another audience, an unbound `kubectl create token`, a Secret-bound and a Node-bound `kubectl " +
		"create token`, and a legacy Secret token; (h) the default `kube-api-access` token's `aud` and " +
		"lifetime."

	l69KindVersion = "v0.29.0"
	l69NodeImage   = "kindest/node:v1.33.1"
	l69Audience    = "port49-lab"
	l69IssuerA     = "https://l69-a.port49.lab"
	l69IssuerB     = "https://l69-b.port49.lab"
	l69PortA       = 16443
	l69PortB       = 16444
	// l69DiskFloorMB is the lab's floor (project rules): two kind node images,
	// their containers and the clusters' etcd want several GB, and the lab host
	// is shared with the other labs' images.
	l69DiskFloorMB = 67584
	l69SA          = "system:serviceaccount:netops:oxidized"
	l69TokenPath   = "/var/run/secrets/port49/token"
	l69DefaultPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

// tokenFactsT is what the evidence keeps of a token: its decoded header and
// claims (neither is a credential without the signature) and its sha256.
type tokenFactsT struct {
	Header   map[string]any `json:"header"`
	Claims   map[string]any `json:"claims"`
	Lifetime int64          `json:"lifetime_seconds"`
	SHA256   string         `json:"sha256"`
}

// tokenFacts decodes raw's header and claims. It keeps neither raw nor its
// signature.
func tokenFacts(raw string) (tokenFactsT, error) {
	parts := strings.Split(strings.TrimSpace(raw), ".")
	if len(parts) != 3 {
		return tokenFactsT{}, errors.New("not a compact JWS")
	}
	var f tokenFactsT
	for i, dst := range []*map[string]any{&f.Header, &f.Claims} {
		b, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil {
			return tokenFactsT{}, fmt.Errorf("part %d: %v", i, err)
		}
		if err := json.Unmarshal(b, dst); err != nil {
			return tokenFactsT{}, fmt.Errorf("part %d: %v", i, err)
		}
	}
	exp, _ := f.Claims["exp"].(float64)
	iat, _ := f.Claims["iat"].(float64)
	f.Lifetime = int64(exp - iat)
	f.SHA256 = sha256Hex(strings.TrimSpace(raw))
	return f, nil
}

// iat is the token's issued-at.
func (f tokenFactsT) iat() time.Time {
	v, _ := f.Claims["iat"].(float64)
	return time.Unix(int64(v), 0)
}

// rotationFraction is when the file changed, as a fraction of the lifetime of
// the token it replaced, to two places: measured against that token's iat,
// never against when polling began.
func rotationFraction(iat time.Time, life time.Duration, changedAt time.Time) float64 {
	return math.Round(changedAt.Sub(iat).Seconds()/life.Seconds()*100) / 100
}

// kubeMember is claims["kubernetes.io"][key] as a map.
func (f tokenFactsT) kubeMember(key string) map[string]any {
	k, _ := f.Claims["kubernetes.io"].(map[string]any)
	m, _ := k[key].(map[string]any)
	return m
}

// l69Cell is one cell's result in the evidence.
type l69Cell struct {
	Name     string         `json:"name"`
	Observed map[string]any `json:"observed"`
	Pass     bool           `json:"pass"`
	Why      string         `json:"why"`
}

// kindCluster is one kind cluster of the run.
type kindCluster struct {
	r          *l69Run
	name       string // port49-l69-a: every cluster of the run starts port49-l69
	cfg        string // tests/lab/k8s/kind-<x>.yaml
	kubeconfig string
	issuer     string
	apiPort    int
	cluster    string // port49's name for it: l69_a
}

func (c *kindCluster) container() string { return c.name + "-control-plane" }

// l69Run is TestL69's state.
type l69Run struct {
	t       *testing.T
	repo    string
	tmp     string
	kind    string // the kind binary
	mu      sync.Mutex
	secrets []string
	cells   []l69Cell
	obs     strings.Builder
	meta    map[string]any
	live    []*kindCluster
	brokers []*localBroker
	seq     int
}

// secret registers v as a value no note, evidence or message may hold.
func (r *l69Run) secret(v string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v = strings.TrimSpace(v); v != "" {
		r.secrets = append(r.secrets, v)
	}
}

func (r *l69Run) allSecrets() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.secrets...)
}

// scrub is s without any registered secret or compact JWS, for a message.
func (r *l69Run) scrub(s string) string {
	for _, v := range r.allSecrets() {
		s = strings.ReplaceAll(s, v, "<token>")
	}
	return jwsShape.ReplaceAllString(s, "<jws>")
}

// run runs name with args, with stdin when it is not "", and returns stdout.
// An error carries the scrubbed tail of stderr, never stdout (stdout may be a
// token).
func (r *l69Run) run(timeout time.Duration, stdin, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("%s %s: %v: %s", filepath.Base(name), firstWord(args), err, tailOf(r.scrub(strings.TrimSpace(errb.String())), 400))
	}
	return out.String(), nil
}

func firstWord(args []string) string {
	if len(args) > 2 && args[0] == "--kubeconfig" {
		args = args[2:]
	}
	if len(args) == 0 {
		return ""
	}
	return args[0]
}

// guard is the lab's stop: the sentinel, and the disk floor.
func (r *l69Run) guard() {
	r.t.Helper()
	if err := labGuardAt(l66StopSentinel, "/", l69DiskFloorMB); err != nil {
		r.t.Fatalf("L69 stops (no note is written): %v", err)
	}
}

// kubectl is kubectl against c, stdout only.
func (c *kindCluster) kubectl(args ...string) (string, error) {
	return c.r.run(5*time.Minute, "", "kubectl", append([]string{"--kubeconfig", c.kubeconfig}, args...)...)
}

func (c *kindCluster) kubectlStdin(stdin string, args ...string) (string, error) {
	return c.r.run(5*time.Minute, stdin, "kubectl", append([]string{"--kubeconfig", c.kubeconfig}, args...)...)
}

// docker is docker exec on c's node.
func (c *kindCluster) nodeSh(script string) (string, error) {
	return c.r.run(2*time.Minute, "", "docker", "exec", c.container(), "sh", "-c", script)
}

// up creates c. Its deletion is registered before the create, so a cluster
// made halfway is deleted too.
func (r *l69Run) up(name, cfgFile, issuer, cluster string, port int) *kindCluster {
	t := r.t
	t.Helper()
	r.guard()
	c := &kindCluster{r: r, name: name, cfg: filepath.Join(r.repo, "tests", "lab", "k8s", cfgFile), issuer: issuer,
		cluster: cluster, apiPort: port, kubeconfig: filepath.Join(r.tmp, name+".kubeconfig")}
	if out, err := r.run(time.Minute, "", r.kind, "get", "clusters"); err != nil {
		t.Fatalf("kind get clusters: %v", err)
	} else if strings.Contains("\n"+out, "\n"+name+"\n") {
		t.Fatalf("a kind cluster %s exists already: a killed run's. Delete it by hand (kind delete cluster --name %s) and run again", name, name)
	}
	r.mu.Lock()
	r.live = append(r.live, c)
	r.mu.Unlock()
	t.Cleanup(c.down)
	if _, err := r.run(10*time.Minute, "", r.kind, "create", "cluster", "--config", c.cfg, "--kubeconfig", c.kubeconfig, "--wait", "180s"); err != nil {
		t.Fatalf("create cluster %s (a harness fault, INVALID): %v", name, err)
	}
	// Pre-flight M11: the issuer flag took.
	if _, err := c.nodeSh("grep -q -- '--service-account-issuer=" + issuer + "' /etc/kubernetes/manifests/kube-apiserver.yaml"); err != nil {
		t.Fatalf("cluster %s: the API server was not started with --service-account-issuer=%s (a harness fault, INVALID)", name, issuer)
	}
	return c
}

// down deletes c; safe to call more than once.
func (c *kindCluster) down() {
	_, _ = c.r.run(5*time.Minute, "", c.r.kind, "delete", "cluster", "--name", c.name)
}

// caFile writes the cluster's CA (the kubeconfig's) beside the run's files and
// returns its path.
func (c *kindCluster) caFile() string {
	out, err := c.kubectl("config", "view", "--raw", "-o", "jsonpath={.clusters[0].cluster.certificate-authority-data}")
	if err != nil {
		c.r.t.Fatalf("%s's CA: %v", c.name, err)
	}
	pem, err := base64.StdEncoding.DecodeString(strings.TrimSpace(out))
	if err != nil || len(pem) == 0 {
		c.r.t.Fatalf("%s's kubeconfig holds no CA", c.name)
	}
	p := filepath.Join(c.r.tmp, c.name+"-ca.pem")
	if err := os.WriteFile(p, pem, 0o600); err != nil {
		c.r.t.Fatal(err)
	}
	return p
}

func (c *kindCluster) jwksURL() string {
	return fmt.Sprintf("https://127.0.0.1:%d/openid/v1/jwks", c.apiPort)
}

// apply applies path (a file) and waits for netops' pods Ready.
func (c *kindCluster) apply(path string) error {
	_, err := c.kubectl("apply", "-f", path)
	return err
}

func (c *kindCluster) applyWorkload() {
	c.r.t.Helper()
	if err := c.apply(filepath.Join(c.r.repo, "tests", "lab", "k8s", "workload.yaml")); err != nil {
		c.r.t.Fatalf("%s: apply workload (a harness fault, INVALID): %v", c.name, err)
	}
	c.waitReady()
}

func (c *kindCluster) waitReady() {
	c.r.t.Helper()
	if _, err := c.kubectl("wait", "--for=condition=Ready", "pod", "--all", "-n", "netops", "--timeout=300s"); err != nil {
		c.r.t.Fatalf("%s: the pods are not Ready (a harness fault, INVALID): %v", c.name, err)
	}
}

// recreatePod deletes and re-creates netops/oxidized (and the service account,
// when it is gone), waiting for it Ready.
func (c *kindCluster) recreatePod() {
	c.r.t.Helper()
	if _, err := c.kubectl("delete", "pod", "oxidized", "-n", "netops", "--ignore-not-found", "--wait=true"); err != nil {
		c.r.t.Fatalf("%s: delete pod: %v", c.name, err)
	}
	c.applyWorkload()
}

// readToken is the token at path in pod, registered as a secret.
func (c *kindCluster) readToken(pod, path string) (string, error) {
	out, err := c.kubectl("exec", "-n", "netops", pod, "--", "cat", path)
	if err != nil {
		return "", err
	}
	c.r.secret(out)
	return strings.TrimSpace(out), nil
}

func (c *kindCluster) podToken() (string, error) { return c.readToken("oxidized", l69TokenPath) }

// tokenHash is the sha256 of the token file, read in the pod: the rotation
// poll never reads the token.
func (c *kindCluster) tokenHash() (string, error) {
	out, err := c.kubectl("exec", "-n", "netops", "oxidized", "--", "sha256sum", l69TokenPath)
	if err != nil {
		return "", err
	}
	f := strings.Fields(out)
	if len(f) == 0 {
		return "", errors.New("sha256sum printed nothing")
	}
	return f[0], nil
}

// createToken is kubectl create token for oxidized in netops.
func (c *kindCluster) createToken(args ...string) (string, error) {
	out, err := c.kubectl(append([]string{"create", "token", "oxidized", "-n", "netops"}, args...)...)
	if err != nil {
		return "", err
	}
	c.r.secret(out)
	return strings.TrimSpace(out), nil
}

// anonGet is an unauthenticated GET of path against the API server with the
// cluster's CA: its status and body.
func (c *kindCluster) anonGet(path string) (int, []byte, error) {
	pem, err := os.ReadFile(c.caFile())
	if err != nil {
		return 0, nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	hc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	resp, err := hc.Get(fmt.Sprintf("https://127.0.0.1:%d%s", c.apiPort, path))
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, b, err
}

// jwksKeys is the number of keys the cluster serves (read through kubectl,
// which authenticates, so it needs no binding).
func (c *kindCluster) jwksKeys() (int, error) {
	kids, err := c.jwksKids()
	return len(kids), err
}

// jwksKids is the kid of each key the cluster serves.
func (c *kindCluster) jwksKids() ([]string, error) {
	out, err := c.kubectl("get", "--raw", "/openid/v1/jwks")
	if err != nil {
		return nil, err
	}
	var d struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		return nil, err
	}
	var kids []string
	for _, k := range d.Keys {
		kids = append(kids, k.Kid)
	}
	return kids, nil
}

// k8sVerifier is one k8s entry of broker.identity.machines.
type k8sVerifier struct {
	Cluster, Issuer, JWKS, CAFile string
	Namespaces                    []string
}

func (r *l69Run) verifier(c *kindCluster, namespaces ...string) k8sVerifier {
	return k8sVerifier{Cluster: c.cluster, Issuer: c.issuer, JWKS: c.jwksURL(), CAFile: c.caFile(), Namespaces: namespaces}
}

// k8sBrokerFiles are port49d.yaml, policy.yaml and inventory.yaml for a broker
// whose machines are vs and whose admin socket is dir's admin.sock: L48's
// localBrokerFiles with its x509 verifier replaced (certificate_status is
// disabled, there is none). The policy's one subject, svc_backup, is
// l69SA.
func k8sBrokerFiles(dir, pki string, vs []k8sVerifier) (cfg, policy, inventory string) {
	var machines strings.Builder
	for _, v := range vs {
		fmt.Fprintf(&machines, "      - {type: k8s, cluster: %s, issuer: %s, jwks: %s, ca_file: %s, audience: %s, namespaces: [%s]}\n",
			v.Cluster, v.Issuer, v.JWKS, v.CAFile, l69Audience, strings.Join(v.Namespaces, ", "))
	}
	cfg = fmt.Sprintf(`listen: "127.0.0.1:0"
metrics_listen: "127.0.0.1:0"
inventory_file: %s
admin_socket: %s
keys:
  lab_key:
    current: {version: 1, secret_env: PORT49_LAB_KEY}
encryption:
  current: {id: lab1, secret_env: PORT49_LAB_ENC_KEY}
accounting: {spool_path: %s}
token: {candidate_cap: %d}
broker:
  listen: "127.0.0.1:0"
  tls_cert_file: %s
  tls_key_file: %s
  identity:
    humans:
      - {type: x509, trust_anchor_file: %s}
    machines:
%s  policy_file: %s
  revocations_file: %s
  policy_watch_interval: 1s
  certificate_status:
    disabled: true
`, filepath.Join(dir, "inventory.yaml"), filepath.Join(dir, "admin.sock"), filepath.Join(dir, "acct.jsonl"), l48CandidateCap,
		filepath.Join(pki, testpki.LabServerCert), filepath.Join(pki, testpki.LabServerKey),
		filepath.Join(pki, testpki.LabCA), machines.String(), filepath.Join(dir, "policy.yaml"),
		filepath.Join(dir, "revocations.json"))
	policy = fmt.Sprintf(`scopes:
  - {name: all_devices, match: {}}
roles:
  - {name: network_admin, privilege: admin, permit: ["**"]}
subjects:
  - {name: svc_backup, identity: ["%s"], username: svc-backup, token_ttl: 60s}
grants:
  - {subject: svc_backup, scope: all_devices, roles: [network_admin], max_privilege: admin}
key_groups:
  - {match: {cidr: 127.0.0.0/8}, key_ref: lab_key}
`, l69SA)
	inventory = fmt.Sprintf("devices:\n  - {name: %s, platform: arista_eos, addresses: [127.0.0.1]}\n", l48Device)
	return cfg, policy, inventory
}

// startK8sBroker runs bin/port49d with the verifiers vs. The directory is
// short: the admin socket's path has a length limit.
func (r *l69Run) startK8sBroker(vs ...k8sVerifier) *localBroker {
	t := r.t
	t.Helper()
	dir, err := os.MkdirTemp("", "l69b")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	pki := filepath.Join(dir, "pki")
	if err := testpki.WriteLab(pki, sliceEmail, time.Now()); err != nil {
		t.Fatal(err)
	}
	cfg, policy, inventory := k8sBrokerFiles(dir, pki, vs)
	for name, body := range map[string]string{"port49d.yaml": cfg, "policy.yaml": policy, "inventory.yaml": inventory} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := startBrokerProcess(t, r.repo, dir, pki, "")
	r.mu.Lock()
	r.brokers = append(r.brokers, b)
	r.mu.Unlock()
	return b
}

// revoke is port49 revoke against the broker's admin socket.
func (b *localBroker) revoke(args ...string) (string, bool) {
	return revokeCLI(filepath.Join(b.dir, "admin.sock"), args...)
}

// decisions is the broker's stdout, the decision log, as lines.
func (b *localBroker) decisions() []string {
	raw, _ := os.ReadFile(b.stdoutPath)
	return strings.Split(strings.TrimSpace(string(raw)), "\n")
}

// mintClusters is the auth.k8s.cluster of each permitted mint record so far.
func (b *localBroker) mintClusters() []string { return mintClustersOf(b.decisions()) }

// mintClustersOf is mintClusters over decision-log lines.
func mintClustersOf(lines []string) []string {
	var out []string
	for _, ln := range lines {
		var rec struct {
			Event   string `json:"event"`
			Verdict string `json:"verdict"`
			Auth    struct {
				K8s struct {
					Cluster string `json:"cluster"`
				} `json:"k8s"`
			} `json:"auth"`
		}
		if json.Unmarshal([]byte(ln), &rec) == nil && rec.Event == "mint" && rec.Auth.K8s.Cluster != "" {
			out = append(out, rec.Auth.K8s.Cluster)
		}
	}
	return out
}

// workloadTokenFile runs port49 workload token for leaf1 on the token file.
func (b *localBroker) workloadTokenFile(tokenFile string) (int, string, string) {
	cmd := exec.Command(filepath.Join(b.repo, "bin", "port49"), "workload", "token", "--broker", "https://"+b.addr,
		"--broker-ca", filepath.Join(b.pki, testpki.LabCA), "--token-file", tokenFile, l48Device)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, out.String(), errb.String()
	case errors.As(err, &ee):
		return ee.ExitCode(), out.String(), errb.String()
	}
	return -1, out.String(), errb.String() + strings.TrimSpace(err.Error())
}

// mintResult is what a mint attempt leaves in the evidence.
type mintResult struct {
	Exit   int    `json:"exit"`
	Stderr string `json:"stderr"`
}

// mint presents token to b. The minted token, on exit 0, is registered and
// dropped; only that one came is kept. Exit -2 is a mint that said success and
// printed nothing.
func (r *l69Run) mint(b *localBroker, token string) mintResult {
	r.t.Helper()
	r.seq++
	f := filepath.Join(r.tmp, fmt.Sprintf("token-%d", r.seq))
	if err := os.WriteFile(f, []byte(token+"\n"), 0o600); err != nil {
		r.t.Fatal(err)
	}
	exit, out, errs := b.workloadTokenFile(f)
	for _, fld := range strings.Fields(out) {
		if len(fld) >= 16 {
			r.secret(fld)
		}
	}
	if exit == 0 && strings.TrimSpace(out) == "" {
		exit = -2
	}
	return mintResult{Exit: exit, Stderr: oneLine(tailOf(r.scrub(strings.TrimSpace(errs)), 500))}
}

func (m mintResult) refused(code string, details ...string) bool {
	if m.Exit != 77 || !strings.Contains(m.Stderr, code) {
		return false
	}
	for _, d := range details {
		if !strings.Contains(m.Stderr, d) {
			return false
		}
	}
	return true
}

// cell runs one cell after the guard; a failed expectation is the cell's
// result, a harness fault inside it t.Fatal.
func (r *l69Run) cell(name string, f func(c *l69Cell)) {
	r.t.Helper()
	r.guard()
	c := &l69Cell{Name: name, Observed: map[string]any{}}
	f(c)
	r.cells = append(r.cells, *c)
	verdict := "PASS"
	if !c.Pass {
		verdict = "FAIL"
	}
	fmt.Fprintf(&r.obs, "### %s\n\n**%s.** %s\n\n", name, verdict, c.Why)
	r.t.Logf("%s: %s: %s", name, verdict, c.Why)
}

func (c *l69Cell) facts(key, raw string, r *l69Run) tokenFactsT {
	f, err := tokenFacts(raw)
	if err != nil {
		r.t.Fatalf("%s: %s is not a JWT (a harness fault, INVALID): %v", c.Name, key, err)
	}
	c.Observed[key] = f
	return f
}

// claimAny is a top-level claim, or the member of kubernetes.io of that name.
func (f tokenFactsT) claimAny(key string) any {
	if v, ok := f.Claims[key]; ok {
		return v
	}
	k, _ := f.Claims["kubernetes.io"].(map[string]any)
	return k[key]
}

func audOnly(f tokenFactsT, want string) bool {
	a, ok := f.Claims["aud"].([]any)
	return ok && len(a) == 1 && a[0] == want
}

func (f tokenFactsT) hdr(key string) string { s, _ := f.Header[key].(string); return s }

// podClaimsPresent is whether kubernetes.io names the namespace, the service
// account and the pod, each with a name and a uid.
func podClaimsPresent(f tokenFactsT) bool {
	k, _ := f.Claims["kubernetes.io"].(map[string]any)
	if k == nil || k["namespace"] == nil {
		return false
	}
	for _, m := range []string{"serviceaccount", "pod"} {
		o := f.kubeMember(m)
		if o == nil || o["name"] == nil || o["uid"] == nil {
			return false
		}
	}
	return true
}

// tokenReview is whether the cluster authenticates token for the lab's
// audience, and what it says when it does not. The request holds the token and
// is never logged.
func (c *kindCluster) tokenReview(token string) (bool, string, error) {
	body, _ := json.Marshal(map[string]any{"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
		"spec": map[string]any{"token": token, "audiences": []string{l69Audience}}})
	out, err := c.kubectlStdin(string(body), "create", "-f", "-", "-o", "json")
	if err != nil {
		return false, "", err
	}
	var d struct {
		Status struct {
			Authenticated bool   `json:"authenticated"`
			Error         string `json:"error"`
		} `json:"status"`
	}
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		return false, "", errors.New("the TokenReview answer is not JSON")
	}
	return d.Status.Authenticated, c.r.scrub(d.Status.Error), nil
}

// ---- the cells ----

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// kindBinary is kind on PATH, else go install's.
func (r *l69Run) kindBinary() string {
	if p, err := exec.LookPath("kind"); err == nil {
		return p
	}
	home, _ := os.UserHomeDir()
	p := filepath.Join(home, "go", "bin", "kind")
	if _, err := os.Stat(p); err != nil {
		r.t.Fatal("kind is not installed: go install sigs.k8s.io/kind@" + l69KindVersion)
	}
	return p
}

// checkKind refuses any kind but the pinned one, and records the node image's
// digest and the tools' versions.
func (r *l69Run) checkKind() {
	out, err := r.run(time.Minute, "", r.kind, "version")
	if err != nil || !strings.Contains(out, "kind "+l69KindVersion+" ") {
		r.t.Fatalf("kind is not %s (a harness fault, INVALID): %q %v", l69KindVersion, strings.TrimSpace(out), err)
	}
	r.meta["kind_version"] = l69KindVersion
	if _, err := r.run(10*time.Minute, "", "docker", "pull", l69NodeImage); err != nil {
		r.t.Fatalf("the node image %s will not pull (a harness fault, INVALID): %v", l69NodeImage, err)
	}
	dig, err := r.run(time.Minute, "", "docker", "image", "inspect", "--format", "{{index .RepoDigests 0}}", l69NodeImage)
	if err != nil {
		dig, err = r.run(time.Minute, "", "docker", "image", "inspect", "--format", "{{.Id}}", l69NodeImage)
		if err != nil {
			r.t.Fatalf("the node image's digest (a harness fault, INVALID): %v", err)
		}
	}
	r.meta["node_image"] = l69NodeImage
	r.meta["node_image_digest"] = strings.TrimSpace(dig)
}

// cellA reads a projected token's claims on cluster A.
func (r *l69Run) cellA() *kindCluster {
	a := r.up("port49-l69-a", "kind-a.yaml", l69IssuerA, "l69_a", l69PortA)
	a.applyWorkload()
	if out, err := a.kubectl("version", "-o", "json"); err == nil {
		var v struct {
			ServerVersion struct {
				GitVersion string `json:"gitVersion"`
			} `json:"serverVersion"`
		}
		if json.Unmarshal([]byte(out), &v) == nil {
			r.meta["server_version"] = v.ServerVersion.GitVersion
		}
	}
	r.cell("(a) claims", func(c *l69Cell) {
		raw, err := a.podToken()
		if err != nil {
			r.t.Fatalf("(a) read the pod's token (INVALID): %v", err)
		}
		f := c.facts("token", raw, r)
		for _, k := range []string{"node", "jti", "nbf", "warnafter"} {
			c.Observed["recorded_"+k] = f.claimAny(k)
		}
		c.Observed["recorded_typ"] = f.hdr("typ")
		c.Pass = f.Claims["iss"] == l69IssuerA && audOnly(f, l69Audience) && f.Lifetime == 600 &&
			f.Claims["sub"] == l69SA && podClaimsPresent(f) && f.hdr("alg") == "RS256" && f.hdr("kid") != ""
		c.Why = fmt.Sprintf("iss %v, aud %v, exp-iat %ds, sub %v, header alg %s kid %t, typ %q; "+
			"kubernetes.io %s; recorded nbf %s, jti %t, node %t, warnafter %s", f.Claims["iss"], f.Claims["aud"], f.Lifetime,
			f.Claims["sub"], f.hdr("alg"), f.hdr("kid") != "", f.hdr("typ"), kubeKeys(f), numStr(f.claimAny("nbf")),
			f.claimAny("jti") != nil, f.claimAny("node") != nil, numStr(f.claimAny("warnafter")))
	})
	return a
}

// numStr is a JSON number claim as an integer, or "absent".
func numStr(v any) string {
	if n, ok := v.(float64); ok {
		return fmt.Sprintf("%.0f", n)
	}
	return "absent"
}

func kubeKeys(f tokenFactsT) string {
	k, _ := f.Claims["kubernetes.io"].(map[string]any)
	var ks []string
	for key := range k {
		ks = append(ks, key)
	}
	sort.Strings(ks)
	return "{" + strings.Join(ks, ", ") + "}"
}

// discoveryDoc is the issuer and jwks_uri members of a discovery body.
func discoveryDoc(body []byte) (issuer, jwksURI string) {
	var d struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	_ = json.Unmarshal(body, &d)
	return d.Issuer, d.JWKSURI
}

// cellC reads discovery anonymously before and after the binding, then runs a
// broker on each cluster's verifier. It returns cluster B, up and bound.
func (r *l69Run) cellC(a *kindCluster) *kindCluster {
	binding := filepath.Join(r.repo, "examples", "kubernetes", "issuer-discovery.yaml")
	var b *kindCluster
	r.cell("(c) discovery", func(c *l69Cell) {
		paths := []string{"/.well-known/openid-configuration", "/openid/v1/jwks"}
		status := func(c *kindCluster) (st [2]int, body0 []byte) {
			for i, p := range paths {
				code, body, err := c.anonGet(p)
				if err != nil {
					r.t.Fatalf("(c) anonymous GET %s on %s (INVALID): %v", p, c.name, err)
				}
				st[i] = code
				if i == 0 {
					body0 = body
				}
			}
			return st, body0
		}
		before, _ := status(a)
		if err := a.apply(binding); err != nil {
			r.t.Fatalf("(c) bind discovery on A (INVALID): %v", err)
		}
		after, doc := status(a)
		iss, juri := discoveryDoc(doc)
		c.Observed["before_binding_status"] = before
		c.Observed["after_binding_status"] = after
		c.Observed["discovery_issuer"] = iss
		c.Observed["discovery_jwks_uri"] = juri
		ok := after == [2]int{200, 200} && iss == l69IssuerA

		ta, err := a.podToken()
		if err != nil {
			r.t.Fatalf("(c) A's token (INVALID): %v", err)
		}
		// The positive control: a verifier whose issuer is wrong for A's
		// keys must say that discovery names another issuer. The note is
		// said after the fetch, on its own goroutine, so the channel is
		// waited on; a silent control means silence below proves nothing.
		wrong := r.verifier(a, "netops")
		wrong.Issuer = l69IssuerB
		ctl := r.startK8sBroker(wrong)
		r.mint(ctl, ta)
		if !ctl.saidWithin(discoveryNoteWait, "names issuer") {
			r.t.Fatalf("(c) the control broker (a wrong issuer) never said \"names issuer\": the discovery check cannot be " +
				"observed, so silence proves nothing (INVALID)")
		}
		c.Observed["control_said_names_issuer"] = true

		// A's correct verifier is silent about discovery. jwks_uri is not
		// checked: no k8s path says it, the broker does not compare it
		// (internal/oidc/keyset.go discoveryNote).
		brokerA := r.startK8sBroker(r.verifier(a, "netops"))
		mA := r.mint(brokerA, ta)
		time.Sleep(discoveryNoteWait)
		silentA := mA.Exit == 0 && !strings.Contains(brokerA.said(), "names issuer")
		c.Observed["a_mint"] = mA
		c.Observed["a_broker_silent_about_discovery"] = silentA

		// B: a jwks_uri that differs from the configured jwks is not compared.
		b = r.up("port49-l69-b", "kind-b.yaml", l69IssuerB, "l69_b", l69PortB)
		b.applyWorkload()
		if err := b.apply(binding); err != nil {
			r.t.Fatalf("(c) bind discovery on B (INVALID): %v", err)
		}
		_, bdoc := status(b)
		_, bjuri := discoveryDoc(bdoc)
		c.Observed["b_discovery_jwks_uri"] = bjuri
		brokerB := r.startK8sBroker(r.verifier(b, "netops"))
		tb, err := b.podToken()
		if err != nil {
			r.t.Fatalf("(c) B's token (INVALID): %v", err)
		}
		mB := r.mint(brokerB, tb)
		time.Sleep(discoveryNoteWait)
		quietB := mB.Exit == 0 && !strings.Contains(brokerB.said(), "names issuer")
		c.Observed["b_mint"] = mB
		c.Observed["b_broker_quiet_about_discovery"] = quietB
		c.Pass = ok && silentA && quietB && bjuri == "https://l69-b.invalid/openid/v1/jwks"
		c.Why = fmt.Sprintf("anonymous discovery/jwks before the binding %v, after %v; discovery issuer %q, jwks_uri %q; "+
			"A's broker silent %t (mint exit %d); B's discovery jwks_uri %q, B's broker mint exit %d, quiet %t",
			before, after, iss, juri, silentA, mA.Exit, bjuri, mB.Exit, quietB)
	})
	return b
}

// discoveryNoteWait is longer than the 3s the broker gives the discovery read
// it makes after a fetch.
const discoveryNoteWait = 5 * time.Second

// saidWithin polls the broker's stderr for sub until wait has passed.
func (b *localBroker) saidWithin(wait time.Duration, sub string) bool {
	for end := time.Now().Add(wait); ; time.Sleep(250 * time.Millisecond) {
		if strings.Contains(b.said(), sub) {
			return true
		}
		if time.Now().After(end) {
			return false
		}
	}
}

// cellMints is the precondition of b, d, e, f and g: a broker with A's
// verifier mints with A's token. It returns that broker, which d and e keep.
func (r *l69Run) cellMints(a *kindCluster) *localBroker {
	var br *localBroker
	r.cell("port49 mints", func(c *l69Cell) {
		br = r.startK8sBroker(r.verifier(a, "netops"))
		raw, err := a.podToken()
		if err != nil {
			r.t.Fatalf("A's token (INVALID): %v", err)
		}
		m := r.mint(br, raw)
		c.Observed["mint"] = m
		c.Pass = m.Exit == 0
		c.Why = fmt.Sprintf("A's pod token minted exit %d", m.Exit)
	})
	return br
}

// cellB measures when the kubelet rewrites the token file.
func (r *l69Run) cellB(a *kindCluster, br *localBroker) {
	r.cell("(b) rotation", func(c *l69Cell) {
		old, err := a.podToken()
		if err != nil {
			r.t.Fatalf("(b) read the token (INVALID): %v", err)
		}
		of := c.facts("token_before", old, r)
		h0, err := a.tokenHash()
		if err != nil {
			r.t.Fatalf("(b) hash (INVALID): %v", err)
		}
		deadline := time.Now().Add(660 * time.Second)
		for time.Now().Before(deadline) {
			time.Sleep(10 * time.Second)
			r.guard()
			h, err := a.tokenHash()
			if err != nil {
				continue
			}
			if h == h0 {
				continue
			}
			changed := time.Now()
			frac := rotationFraction(of.iat(), 600*time.Second, changed)
			c.Observed["fraction"] = frac
			raw, err := a.podToken()
			if err != nil {
				r.t.Fatalf("(b) read the new token (INVALID): %v", err)
			}
			nf := c.facts("token_after", raw, r)
			c.Observed["new_token_differs"] = nf.SHA256 != of.SHA256
			m := r.mint(br, raw)
			c.Observed["mint"] = m
			c.Pass = m.Exit == 0 && frac >= 0.75 && frac <= 0.97
			bound := "outside [0.75, 0.97], so the docs' \"about 80%%\" does not hold"
			if c.Pass {
				bound = "inside [0.75, 0.97], so the docs' \"about 80%%\" stands"
			}
			c.Why = fmt.Sprintf("the file changed at %.2f of expirationSeconds (measured from the old token's iat; "+
				bound+"); the new token minted exit %d", frac, m.Exit)
			return
		}
		c.Why = "the token file did not change within 660s"
	})
}

// cellD rotates A's signing key and mints with the new key's token on the
// broker that was already running.
func (r *l69Run) cellD(a *kindCluster, br *localBroker) {
	r.cell("(d) key rotation", func(c *l69Cell) {
		before, err := a.jwksKeys()
		if err != nil {
			r.t.Fatalf("(d) JWKS before (INVALID): %v", err)
		}
		oldTok, _ := a.podToken()
		of := c.facts("token_before", oldTok, r)
		script := `set -e
cd /etc/kubernetes/pki
openssl genrsa -out sa2.key 2048 2>/dev/null
openssl rsa -in sa2.key -pubout -out sa2.pub 2>/dev/null
cp /etc/kubernetes/manifests/kube-apiserver.yaml /tmp/kas.yaml
sed -i -e 's|^\( *\)- --service-account-key-file=/etc/kubernetes/pki/sa.pub$|&\n\1- --service-account-key-file=/etc/kubernetes/pki/sa2.pub|' \
  -e 's|--service-account-signing-key-file=/etc/kubernetes/pki/sa.key|--service-account-signing-key-file=/etc/kubernetes/pki/sa2.key|' /tmp/kas.yaml
grep -c 'service-account-key-file' /tmp/kas.yaml | grep -qx 2
grep -q -- '--service-account-signing-key-file=/etc/kubernetes/pki/sa2.key' /tmp/kas.yaml
cp /tmp/kas.yaml /etc/kubernetes/manifests/kube-apiserver.yaml`
		if _, err := a.nodeSh(script); err != nil {
			r.t.Fatalf("(d) rotate the signing key on A's control plane (INVALID): %v", err)
		}
		after := before
		deadline := time.Now().Add(240 * time.Second)
		for time.Now().Before(deadline) && after < 2 {
			time.Sleep(5 * time.Second)
			if n, err := a.jwksKeys(); err == nil {
				after = n
			}
		}
		if after < 2 {
			r.t.Fatal("(d) the API server did not come back with a second key within 240s (INVALID)")
		}
		a.recreatePod()
		raw, err := a.podToken()
		if err != nil {
			r.t.Fatalf("(d) read the new token (INVALID): %v", err)
		}
		nf := c.facts("token_after", raw, r)
		if nf.hdr("kid") == "" || nf.hdr("kid") == of.hdr("kid") {
			r.t.Fatal("(d) the new token carries the old kid: the signing key did not change (INVALID)")
		}
		if kids, err := a.jwksKids(); err != nil || !slices.Contains(kids, nf.hdr("kid")) {
			r.t.Fatal("(d) the API server's JWKS does not serve the new token's kid (INVALID)")
		}
		start := time.Now()
		var m mintResult
		first := -1
		attempts := 0
		for time.Since(start) < 70*time.Second {
			attempts++
			m = r.mint(br, raw)
			if first < 0 {
				first = m.Exit
			}
			if m.Exit == 0 {
				break
			}
			time.Sleep(5 * time.Second)
		}
		took := time.Since(start).Round(time.Second)
		c.Observed["jwks_keys_before"], c.Observed["jwks_keys_after"] = before, after
		c.Observed["kid_before"], c.Observed["kid_after"] = of.hdr("kid"), nf.hdr("kid")
		c.Observed["first_mint_exit"], c.Observed["last_mint"] = first, m
		c.Observed["mint_attempts"], c.Observed["seconds_to_mint"] = attempts, took.Seconds()
		c.Pass = m.Exit == 0 && took <= 75*time.Second && before == 1 && after == 2 && of.hdr("kid") != nf.hdr("kid")
		c.Why = fmt.Sprintf("JWKS keys %d then %d; kid %q then %q (differs %t); the new key's token minted on the running broker "+
			"after %s (first attempt exit %d, %d attempts), last exit %d", before, after, of.hdr("kid"), nf.hdr("kid"),
			of.hdr("kid") != nf.hdr("kid"), took, first, attempts, m.Exit)
	})
}

// cellE deletes the pod, then the service account, and asks TokenReview and
// port49 about each token.
func (r *l69Run) cellE(a *kindCluster, br *localBroker) {
	r.cell("(e) deletion", func(c *l69Cell) {
		t1, err := a.podToken()
		if err != nil {
			r.t.Fatalf("(e) T1 (INVALID): %v", err)
		}
		c.facts("t1", t1, r)
		if _, err := a.kubectl("delete", "pod", "oxidized", "-n", "netops", "--wait=true"); err != nil {
			r.t.Fatalf("(e) delete the pod (INVALID): %v", err)
		}
		auth1, err1, err := a.tokenReview(t1)
		if err != nil {
			r.t.Fatalf("(e) TokenReview T1 (INVALID): %v", err)
		}
		m1 := r.mint(br, t1)
		a.applyWorkload()
		t2, err := a.podToken()
		if err != nil {
			r.t.Fatalf("(e) T2 (INVALID): %v", err)
		}
		c.facts("t2", t2, r)
		if _, err := a.kubectl("delete", "serviceaccount", "oxidized", "-n", "netops"); err != nil {
			r.t.Fatalf("(e) delete the service account (INVALID): %v", err)
		}
		auth2, err2, err := a.tokenReview(t2)
		if err != nil {
			r.t.Fatalf("(e) TokenReview T2 (INVALID): %v", err)
		}
		m2 := r.mint(br, t2)
		said, ran := br.revoke("--principal", l69SA)
		m3 := r.mint(br, t2)
		c.Observed["pod_deleted"] = map[string]any{"tokenreview_authenticated": auth1, "tokenreview_error": err1, "mint": m1}
		c.Observed["serviceaccount_deleted"] = map[string]any{"tokenreview_authenticated": auth2, "tokenreview_error": err2, "mint": m2}
		c.Observed["revoke"] = map[string]any{"ran": ran, "answer": oneLine(r.scrub(said)), "mint_after": m3}
		c.Pass = !auth1 && !auth2 && m1.Exit == 0 && m2.Exit == 0 && ran && m3.refused("credential_revoked")
		c.Why = fmt.Sprintf("after the pod was deleted TokenReview answered authenticated=%t (%q) and port49 minted exit %d; "+
			"after the service account was deleted authenticated=%t (%q), port49 exit %d; after port49 revoke %s (ran %t) "+
			"the same token exited %d: %s", auth1, err1, m1.Exit, auth2, err2, m2.Exit, l69SA, ran, m3.Exit, m3.Stderr)
	})
}

// cellF presents B's tokens at brokers that list A, B, or both.
func (r *l69Run) cellF(a, b *kindCluster) {
	r.cell("(f) another cluster", func(c *l69Cell) {
		// A's service account and pod were deleted in (e).
		a.recreatePod()
		tb, err := b.podToken()
		if err != nil {
			r.t.Fatalf("(f) B's token (INVALID): %v", err)
		}
		ta, err := a.podToken()
		if err != nil {
			r.t.Fatalf("(f) A's token (INVALID): %v", err)
		}
		// 1. A alone.
		m1 := r.mint(r.startK8sBroker(r.verifier(a, "netops")), tb)
		// 2. A for netops, B for backup only.
		m2 := r.mint(r.startK8sBroker(r.verifier(a, "netops"), r.verifier(b, "backup")), tb)
		// 3. Both list netops (decision 49 ruling 4).
		both := r.startK8sBroker(r.verifier(a, "netops"), r.verifier(b, "netops"))
		startLine := strings.Contains(both.said(), "identity: k8s namespaces: netops: l69_a, l69_b")
		m3a := r.mint(both, ta)
		m3b := r.mint(both, tb)
		clusters := both.mintClusters()
		recA, recB := count(clusters, "l69_a") >= 1, count(clusters, "l69_b") >= 1
		c.Observed["a_alone"], c.Observed["b_lists_backup"] = m1, m2
		c.Observed["both_list_netops"] = map[string]any{"start_line": startLine, "a_mint": m3a, "b_mint": m3b,
			"mint_record_clusters": clusters}
		c.Pass = m1.refused("trust_domain_unresolved", "no configured verifier accepts its issuer") &&
			m2.refused("identity_unmapped", "its namespace netops is not one cluster l69_b ("+l69IssuerB+") lists in namespaces") &&
			startLine && m3a.Exit == 0 && m3b.Exit == 0 && recA && recB
		c.Why = fmt.Sprintf("B's token at a broker listing A alone: exit %d; at A (netops) and B (backup): exit %d; at A and B "+
			"both listing netops: the start says the overlap %t, A's token exit %d, B's exit %d, mint records name clusters %v",
			m1.Exit, m2.Exit, startLine, m3a.Exit, m3b.Exit, clusters)
	})
}

func count(ss []string, v string) int {
	n := 0
	for _, s := range ss {
		if s == v {
			n++
		}
	}
	return n
}

// cellG presents the shapes port49 refuses.
func (r *l69Run) cellG(a *kindCluster) {
	r.cell("(g) shapes refused", func(c *l69Cell) {
		br := r.startK8sBroker(r.verifier(a, "netops"))
		mustToken := func(what string, raw string, err error) string {
			if err != nil {
				r.t.Fatalf("(g) %s (INVALID): %v", what, err)
			}
			return raw
		}
		wrong, err := a.createToken("--audience", "other", "--bound-object-kind", "Pod", "--bound-object-name", "oxidized")
		wrong = mustToken("wrong audience", wrong, err)
		unbound, err := a.createToken("--audience", l69Audience)
		unbound = mustToken("unbound", unbound, err)
		if _, err := a.kubectl("create", "secret", "generic", "l69-bound", "-n", "netops", "--from-literal=k=fake"); err != nil {
			r.t.Fatalf("(g) the bound Secret (INVALID): %v", err)
		}
		secretBound, err := a.createToken("--audience", l69Audience, "--bound-object-kind", "Secret", "--bound-object-name", "l69-bound")
		secretBound = mustToken("Secret-bound", secretBound, err)
		nodeBound, err := a.createToken("--audience", l69Audience, "--bound-object-kind", "Node", "--bound-object-name", a.container())
		nodeBound = mustToken("Node-bound", nodeBound, err)
		legacyYAML := "apiVersion: v1\nkind: Secret\nmetadata:\n  name: l69-legacy\n  namespace: netops\n  annotations:\n" +
			"    kubernetes.io/service-account.name: oxidized\ntype: kubernetes.io/service-account-token\n"
		if _, err := a.kubectlStdin(legacyYAML, "apply", "-f", "-"); err != nil {
			r.t.Fatalf("(g) the legacy Secret (INVALID): %v", err)
		}
		var legacy string
		for i := 0; i < 30 && legacy == ""; i++ {
			out, err := a.kubectl("get", "secret", "l69-legacy", "-n", "netops", "-o", "jsonpath={.data.token}")
			if err == nil && strings.TrimSpace(out) != "" {
				dec, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(out))
				if derr == nil {
					legacy = string(dec)
					r.secret(legacy)
				}
			}
			if legacy == "" {
				time.Sleep(2 * time.Second)
			}
		}
		if legacy == "" {
			r.t.Fatal("(g) the cluster populated no legacy token within 60s (INVALID)")
		}
		type shape struct {
			name, raw, code string
			details         []string
		}
		shapes := []shape{
			{"wrong_audience", wrong, "trust_domain_unresolved", []string{"its aud is not exactly"}},
			{"unbound", unbound, "trust_domain_unresolved", []string{"it is not bound to a pod"}},
			{"secret_bound", secretBound, "trust_domain_unresolved", []string{"it is bound to a Secret"}},
			{"node_bound", nodeBound, "trust_domain_unresolved", []string{"it is not bound to a pod"}},
			{"legacy_secret", legacy, "trust_domain_unresolved", []string{"no configured verifier accepts its issuer"}},
		}
		pass := true
		var said []string
		for _, s := range shapes {
			f := c.facts(s.name+"_token", s.raw, r)
			m := r.mint(br, s.raw)
			c.Observed[s.name+"_mint"] = m
			switch s.name {
			case "secret_bound":
				c.Observed["secret_bound_kubernetes.io.secret"] = f.kubeMember("secret")
			case "node_bound":
				c.Observed["node_bound_kubernetes.io.node"] = f.kubeMember("node")
			case "legacy_secret":
				c.Observed["legacy_iss"] = f.Claims["iss"]
			}
			ok := m.refused(s.code, s.details...)
			pass = pass && ok
			said = append(said, fmt.Sprintf("%s exit %d (%t)", s.name, m.Exit, ok))
		}
		c.Pass = pass
		c.Why = "each of the five shapes was refused with trust_domain_unresolved and its own reason: " + strings.Join(said, ", ")
	})
}

// cellH is the default kube-api-access token.
func (r *l69Run) cellH(a *kindCluster) {
	r.cell("(h) the default token", func(c *l69Cell) {
		raw, err := a.readToken("defaulted", l69DefaultPath)
		if err != nil {
			r.t.Fatalf("(h) the default token (INVALID): %v", err)
		}
		f := c.facts("token", raw, r)
		c.Observed["recorded_warnafter"] = f.claimAny("warnafter")
		m := r.mint(r.startK8sBroker(r.verifier(a, "netops")), raw)
		c.Observed["mint"] = m
		c.Pass = m.refused("trust_domain_unresolved", "its aud is not exactly")
		c.Why = fmt.Sprintf("the default token's aud is %v, exp-iat %ds, warnafter %s; port49 exit %d: %s", f.Claims["aud"],
			f.Lifetime, numStr(f.claimAny("warnafter")), m.Exit, m.Stderr)
	})
}

// l69Evidence is tests/lab/evidence/L69-kind.json.
type l69Evidence struct {
	Platform        string    `json:"platform"`
	KindVersion     string    `json:"kind_version"`
	NodeImage       string    `json:"node_image"`
	NodeImageDigest string    `json:"node_image_digest"`
	ServerVersion   string    `json:"server_version"`
	Cells           []l69Cell `json:"cells"`
}

// finish writes the evidence and the note, after checking each for a token.
func (r *l69Run) finish() {
	t := r.t
	t.Helper()
	str := func(k string) string { s, _ := r.meta[k].(string); return s }
	ev := l69Evidence{Platform: "kind", KindVersion: str("kind_version"), NodeImage: str("node_image"),
		NodeImageDigest: str("node_image_digest"), ServerVersion: str("server_version"), Cells: r.cells}
	if ev.ServerVersion == "" {
		t.Fatal("the cluster's server version was not read (a harness fault, INVALID)")
	}
	body, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	body = append(body, '\n')
	out, err := directoryOut()
	if err != nil {
		t.Fatal(err)
	}
	evPath := filepath.Join("tests", "lab", "evidence", "L69-kind.json")
	version := fmt.Sprintf("kind %s, node image `%s` (%s), Kubernetes %s", ev.KindVersion, ev.NodeImage, ev.NodeImageDigest, ev.ServerVersion)
	runLine := fmt.Sprintf("commit `%s`, `make lab-k8s` (`-run TestL69`)", gitHead(out))
	note := workloadNote("L69", "kind", l69Claim, r.obs.String(), evPath, runLine, version)
	for what, text := range map[string]string{"the evidence": string(body), "the note": note} {
		if hits := labcreds.Contains([]byte(text), r.allSecrets()); len(hits) > 0 {
			t.Fatalf("%s holds a token the run read (INVALID, nothing is written)", what)
		}
		if lerr := leakIn(text, r.allSecrets()); lerr != nil {
			t.Fatalf("%s is not written: %v (INVALID)", what, lerr)
		}
	}
	for _, d := range []string{"evidence", "results"} {
		if err := os.MkdirAll(filepath.Join(out, "tests", "lab", d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(out, evPath), body, 0o644); err != nil {
		t.Fatal(err)
	}
	notePath := filepath.Join(out, "tests", "lab", "results", "L69-kind.md")
	if err := os.WriteFile(notePath, []byte(labcreds.RedactNote(note)), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s and %s", notePath, filepath.Join(out, evPath))
}

func gitHead(repo string) string {
	if out, err := exec.Command("git", "-C", repo, "rev-parse", "HEAD").Output(); err == nil {
		return strings.TrimSpace(string(out))
	}
	return "unknown"
}

// TestL69 runs the cells in order: a, c, the mint precondition, b, d, e, f, g,
// h. The sentinel and the disk floor are checked before each (and before each
// cluster is made); the clusters are deleted when it ends, however it ends.
func TestL69(t *testing.T) {
	if os.Getenv("PORT49_LAB_K8S") != "1" {
		t.Skip("PORT49_LAB_K8S=1 runs L69 on two kind clusters (make lab-k8s)")
	}
	repo, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	if root == "" {
		root = repo
		t.Cleanup(func() { root = "" })
	}
	for _, bin := range []string{"port49d", "port49"} {
		if _, err := os.Stat(filepath.Join(repo, "bin", bin)); err != nil {
			t.Fatalf("bin/%s is missing: run `make build` first", bin)
		}
	}
	r := &l69Run{t: t, repo: repo, tmp: t.TempDir(), meta: map[string]any{}}
	r.kind = r.kindBinary()
	r.checkKind()
	// A killed run leaves no cluster behind: a signal deletes this run's.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	t.Cleanup(func() { signal.Stop(sig) })
	go func() {
		if s, ok := <-sig; ok {
			r.mu.Lock()
			live := append([]*kindCluster(nil), r.live...)
			brokers := append([]*localBroker(nil), r.brokers...)
			r.mu.Unlock()
			for _, b := range brokers {
				b.stop()
			}
			for _, c := range live {
				c.down()
			}
			if s == syscall.SIGINT {
				os.Exit(130)
			}
			os.Exit(143)
		}
	}()

	a := r.cellA()
	b := r.cellC(a)
	brokerA := r.cellMints(a)
	r.cellB(a, brokerA)
	r.cellD(a, brokerA)
	r.cellE(a, brokerA)
	r.cellF(a, b)
	r.cellG(a)
	r.cellH(a)

	r.finish()
	for _, c := range r.cells {
		if !c.Pass {
			t.Errorf("cell %s FAILED (the note records it): %s", c.Name, c.Why)
		}
	}
}
