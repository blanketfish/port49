//go:build lab

package lab

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/testpki"
)

// The pure helpers of the workload CA and Oxidized harnesses (plan 8, Task 13;
// L48 and L49). Nothing here starts a container.

const caJSONSample = `{
  "root": "/home/step/certs/root_ca.crt",
  "address": ":9000",
  "db": {"type": "badgerv2", "dataSource": "/home/step/db"},
  "authority": {
    "provisioners": [
      {"type": "JWK", "name": "admin", "key": {"kty": "EC"}},
      {"type": "JWK", "name": "lab", "key": {"kty": "EC"}, "options": {"x509": {"templateFile": "t.tpl", "allow": {"dns": ["old.example"]}}}}
    ],
    "claims": {"maxTLSCertDuration": "2160h"}
  },
  "tls": {"minVersion": 1.2, "renegotiation": false}
}`

func decodeJSONObject(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("not a JSON object: %v\n%s", err, raw)
	}
	return m
}

// enabling the CRL keeps every other key, floats included, and sets crl.
func TestCAJSONWithCRLKeepsEveryOtherKey(t *testing.T) {
	out, err := caJSONWithCRL([]byte(caJSONSample))
	if err != nil {
		t.Fatal(err)
	}
	got, want := decodeJSONObject(t, out), decodeJSONObject(t, []byte(caJSONSample))
	crl, ok := got["crl"].(map[string]any)
	if !ok || crl["enabled"] != true || crl["generateOnRevoke"] != true {
		t.Fatalf("crl = %v", got["crl"])
	}
	delete(got, "crl")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("another key changed:\n got %v\nwant %v", got, want)
	}
	if !strings.Contains(string(out), `"minVersion": 1.2`) {
		t.Errorf("a number was rewritten:\n%s", out)
	}
	if _, err := caJSONWithCRL([]byte(`[1]`)); err == nil {
		t.Error("a ca.json that is not an object was accepted")
	}
}

// a ca.json that already has a crl block gets ours, not a merge.
func TestCAJSONWithCRLReplacesAnExistingBlock(t *testing.T) {
	out, err := caJSONWithCRL([]byte(`{"crl": {"enabled": false, "cacheDuration": "1h"}, "a": 1}`))
	if err != nil {
		t.Fatal(err)
	}
	crl := decodeJSONObject(t, out)["crl"].(map[string]any)
	if crl["enabled"] != true || crl["generateOnRevoke"] != true || len(crl) != 2 {
		t.Errorf("crl = %v", crl)
	}
}

// the allow list is the one URI, on the named provisioner alone; its other
// options and every other provisioner are kept.
func TestCAJSONAllowingURISetsOneProvisionersAllowList(t *testing.T) {
	const id = "spiffe://port49.lab/host/oxidized-01"
	out, err := caJSONAllowingURI([]byte(caJSONSample), "lab", id)
	if err != nil {
		t.Fatal(err)
	}
	got := decodeJSONObject(t, out)
	provs := got["authority"].(map[string]any)["provisioners"].([]any)
	lab := provs[1].(map[string]any)
	x509 := lab["options"].(map[string]any)["x509"].(map[string]any)
	if !reflect.DeepEqual(x509["allow"], map[string]any{"uri": []any{id}}) {
		t.Errorf("allow = %v, want the one URI alone", x509["allow"])
	}
	if x509["templateFile"] != "t.tpl" {
		t.Errorf("the provisioner's other x509 option was lost: %v", x509)
	}
	if _, has := provs[0].(map[string]any)["options"]; has {
		t.Errorf("another provisioner gained options: %v", provs[0])
	}
	if got["tls"] == nil || got["db"] == nil {
		t.Errorf("a top-level key was lost: %v", got)
	}
}

// a provisioner with no options gets the block made; an unknown one is an error.
func TestCAJSONAllowingURINeedsTheProvisioner(t *testing.T) {
	out, err := caJSONAllowingURI([]byte(caJSONSample), "admin", "spiffe://port49.lab/host/x")
	if err != nil {
		t.Fatal(err)
	}
	admin := decodeJSONObject(t, out)["authority"].(map[string]any)["provisioners"].([]any)[0].(map[string]any)
	if admin["options"].(map[string]any)["x509"].(map[string]any)["allow"] == nil {
		t.Errorf("no allow list made: %v", admin)
	}
	if _, err := caJSONAllowingURI([]byte(caJSONSample), "nobody", "spiffe://port49.lab/host/x"); err == nil {
		t.Error("a provisioner that is not in ca.json was accepted")
	}
	if _, err := caJSONAllowingURI([]byte(`{"authority": {}}`), "lab", "spiffe://port49.lab/host/x"); err == nil {
		t.Error("a ca.json with no provisioners was accepted")
	}
}

func TestRenewFraction(t *testing.T) {
	nb := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	na := nb.Add(10 * time.Hour)
	for _, tc := range []struct {
		name string
		at   time.Time
		want float64
	}{
		{"at issue", nb, 0},
		{"two thirds", nb.Add(10 * time.Hour * 2 / 3), 2.0 / 3},
		{"half", nb.Add(5 * time.Hour), 0.5},
		{"at expiry", na, 1},
		{"after expiry", na.Add(5 * time.Hour), 1.5},
	} {
		if got := renewFraction(nb, na, tc.at); got < tc.want-1e-9 || got > tc.want+1e-9 {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
	if got := renewFraction(nb, nb, nb); got != 0 {
		t.Errorf("a zero lifetime: %v, want 0", got)
	}
}

// the commands the daemon authorized for one user, in order, once each.
func TestOxidizedCommandsAreTheUsersOwnInOrderOnceEach(t *testing.T) {
	rec := func(event, user string, vector ...string) map[string]any {
		v := make([]any, len(vector))
		for i, w := range vector {
			v[i] = w
		}
		return map[string]any{"event": event, "session": map[string]any{"username": user},
			"request": map[string]any{"vector": v}}
	}
	recs := []map[string]any{
		rec("authorize_command", "svc-oxidized", "terminal", "length", "0"),
		rec("authorize_command", "svc-oxidized", "show", "version"),
		rec("authorize_command", "someone-else", "show", "clock"),
		rec("authorize_command", "svc-oxidized", "show", "version"),
		rec("login", "svc-oxidized", "show", "never"),
		rec("authorize_command", "svc-oxidized", "show", "running-config"),
		{"event": "authorize_command", "request": map[string]any{"vector": []any{"show", "bare"}}},
	}
	want := []string{"terminal length 0", "show version", "show running-config"}
	if got := oxidizedCommands(recs, "svc-oxidized", ""); !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := oxidizedCommands(recs, "nobody", ""); len(got) != 0 {
		t.Errorf("a user with no records: %q", got)
	}
}

// a verdict narrows the commands to the permits or the denials alone.
func TestOxidizedCommandsFilterOnVerdict(t *testing.T) {
	rec := func(verdict string, vector ...string) map[string]any {
		v := make([]any, len(vector))
		for i, w := range vector {
			v[i] = w
		}
		return map[string]any{"event": "authorize_command", "verdict": verdict,
			"session": map[string]any{"username": "svc-oxidized"}, "request": map[string]any{"vector": v}}
	}
	recs := []map[string]any{rec("permit", "show", "version"), rec("deny", "configure", "terminal"),
		rec("permit", "show", "inventory")}
	if got, want := oxidizedCommands(recs, "svc-oxidized", "permit"), []string{"show version", "show inventory"}; !reflect.DeepEqual(got, want) {
		t.Errorf("permit: got %q, want %q", got, want)
	}
	if got, want := oxidizedCommands(recs, "svc-oxidized", "deny"), []string{"configure terminal"}; !reflect.DeepEqual(got, want) {
		t.Errorf("deny: got %q, want %q", got, want)
	}
	if got := oxidizedCommands(recs, "svc-oxidized", ""); len(got) != 3 {
		t.Errorf("no verdict is every command: %q", got)
	}
}

// the container's log is kept only with its password lines dropped and no
// secret left: the image's first start prints the CA's administrative password.
func TestScrubStepLogDropsPasswordLines(t *testing.T) {
	const secret = "lab-only-generated-secret-value"
	raw := "badger info\n👉 Your CA administrative password is: " + secret + "\nlistening on :9000\nPASSWORD file read\n"
	got, err := scrubStepLog(raw, []string{secret})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, secret) || strings.Contains(strings.ToLower(got), "password") ||
		!strings.Contains(got, "badger info") || !strings.Contains(got, "listening on :9000") {
		t.Errorf("scrubbed log = %q", got)
	}
	// a secret on a line that does not say "password" is refused, not kept
	if _, err := scrubStepLog("token "+secret+"\n", []string{secret}); err == nil {
		t.Error("a log that still holds the secret was kept")
	}
	if _, err := scrubStepLog("-----BEGIN EC PRIVATE KEY-----\n", nil); err == nil {
		t.Error("a log that holds a private key was kept")
	}
}

// a log file with a leak in it is replaced, not kept.
func TestWithholdLeakyLog(t *testing.T) {
	dir := t.TempDir()
	clean, dirty := filepath.Join(dir, "clean.log"), filepath.Join(dir, "dirty.log")
	if err := os.WriteFile(clean, []byte("renewed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dirty, []byte("-----BEGIN EC PRIVATE KEY-----\nAAAA\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{clean, dirty} {
		if err := withholdLeakyLog(p, nil); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
	}
	if b, _ := os.ReadFile(clean); string(b) != "renewed\n" {
		t.Errorf("a clean log was changed: %q", b)
	}
	if b, _ := os.ReadFile(dirty); strings.Contains(string(b), "PRIVATE KEY") || !strings.Contains(string(b), "withheld") {
		t.Errorf("a leaky log was kept: %q", b)
	}
}

// router.db's password column is the token and is registered as a secret; the
// username column is the account name, which every note names, and is not.
func TestRouterDBSecretsAreTheTokenColumnAlone(t *testing.T) {
	raw := "leaf1\t172.100.100.11\teos\tsvc-oxidized\ttok-pass-bbbb\nleaf2\t172.100.100.12\tios\tsvc-oxidized\ttok-pass-dddd\n\nshort\tline\n"
	want := []string{"tok-pass-bbbb", "tok-pass-dddd"}
	if got := routerDBSecrets(raw); !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := routerDBSecrets(""); len(got) != 0 {
		t.Errorf("an empty router.db: %q", got)
	}
}

// the node list names the node, by name or full_name.
func TestNodeListed(t *testing.T) {
	list := []byte(`[{"name":"leaf1","full_name":"leaf1","ip":"172.100.100.11","model":"eos"},{"name":"leaf2"}]`)
	if !nodeListed(list, "leaf1") || !nodeListed(list, "leaf2") {
		t.Error("a listed node was not found")
	}
	if nodeListed(list, "leaf3") || nodeListed([]byte(`[]`), "leaf1") || nodeListed([]byte(`<html>`), "leaf1") {
		t.Error("an unlisted node, an empty list or a non-JSON answer found the node")
	}
}

// WriteWorkloadLab's CA is a public certificate the broker container (uid
// 65532) must read; its key stays 0600.
func TestWriteWorkloadPKIMakesTheCAReadable(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "workload")
	if err := writeWorkloadPKI(dir, l48ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	mode := func(name string) os.FileMode {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return fi.Mode().Perm()
	}
	if m := mode(testpki.WorkloadCA); m != 0o644 {
		t.Errorf("workload-ca.pem is %o, want 644", m)
	}
	for _, key := range []string{testpki.WorkloadKey, testpki.WorkloadCAKey} {
		if m := mode(key); m != 0o600 {
			t.Errorf("%s is %o, want 600", key, m)
		}
	}
}

// the two compose files and the Go constants name one reference each, by digest.
func TestTheWorkloadImagesArePinnedOnce(t *testing.T) {
	for _, tc := range []struct{ name, image, file string }{
		{"stepCAImage", stepCAImage, filepath.Join("workload", "compose.yaml")},
		{"oxidizedImage", oxidizedImage, filepath.Join("compose", "oxidized.yaml")},
	} {
		if !strings.Contains(tc.image, "@sha256:") {
			t.Errorf("%s is not pinned by digest: %s", tc.name, tc.image)
		}
		b, err := os.ReadFile(tc.file)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), "image: "+tc.image+"\n") {
			t.Errorf("%s's image is not %s %s", tc.file, tc.name, tc.image)
		}
	}
}

// step-ca's compose file holds no password value, reads the harness's generated
// file (so the CA key's and the provisioner's passwords are equal), and binds the
// CA to loopback alone.
func TestStepCAComposeHoldsNoPasswordAndBindsLoopback(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("workload", "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Contains(s, "DOCKER_STEPCA_INIT_PASSWORD:") {
		t.Error("the compose file sets the password itself")
	}
	if !strings.Contains(s, "DOCKER_STEPCA_INIT_PASSWORD_FILE: "+stepCAPassword+"\n") ||
		!strings.Contains(s, "../logs/workload/pw/password:"+stepCAPassword+":ro") {
		t.Errorf("the compose file does not read the generated password file at %s", stepCAPassword)
	}
	if !strings.Contains(s, `"127.0.0.1:19000:9000"`) {
		t.Error("step-ca is not published on loopback alone")
	}
	if !strings.Contains(s, "name: port49labstepca") {
		t.Error("the project is not port49labstepca")
	}
}

// the Oxidized overlay runs on the host network and mounts the stack's local directory.
func TestOxidizedOverlayIsHostNetworked(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("compose", "oxidized.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	// The container runs as the host user: the image's own run script would
	// chown the directory to uid 30000 and lock the host-side wrapper out.
	for _, want := range []string{"network_mode: host", "${PORT49_COMPOSE_LOCAL}/oxidized:/oxhome/.config/oxidized",
		"${PORT49_COMPOSE_LOCAL}/oxidized/known_hosts:/oxhome/.ssh/known_hosts:ro", `user: "${PORT49_LAB_UID:?}:${PORT49_LAB_GID:?}"`,
		`command: ["oxidized"]`, "HOME: /oxhome", "/etc/port49-workload/workload-ca.pem:ro",
		// Oxidized exits on an empty router.db: it starts only after a wrapper run wrote one
		"profiles: [oxidized]"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("the overlay lacks %q", want)
		}
	}
	// the image reloads in a loop when CONFIG_RELOAD_INTERVAL is set at all
	for _, line := range strings.Split(string(b), "\n") {
		if strings.Contains(line, "CONFIG_RELOAD_INTERVAL:") {
			t.Errorf("the overlay sets CONFIG_RELOAD_INTERVAL: %s", line)
		}
	}
}

// the local broker's three files load as port49d's config, with the workload
// anchor the machines verifier names and the humans' anchor another file, and
// the policy compiles.
func TestLocalBrokerFilesLoad(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PORT49_LAB_KEY", "labsecret")
	t.Setenv("PORT49_LAB_ENC_KEY", labEncKeyDefault)
	pki, wl := filepath.Join(dir, "pki"), filepath.Join(dir, "wl")
	now := time.Now()
	if err := testpki.WriteLab(pki, sliceEmail, now); err != nil {
		t.Fatal(err)
	}
	if err := testpki.WriteWorkloadLab(wl, l48ID, now); err != nil {
		t.Fatal(err)
	}
	anchor := filepath.Join(wl, testpki.WorkloadCA)
	for _, crl := range []bool{false, true} {
		url, issuer := "", ""
		if crl {
			url, issuer = "https://127.0.0.1:19000/1.0/crl", anchor
		}
		cfg, pol, inv := localBrokerFiles(dir, pki, anchor, url, issuer)
		for name, body := range map[string]string{"port49d.yaml": cfg, "policy.yaml": pol, "inventory.yaml": inv} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		c, err := config.Load(filepath.Join(dir, "port49d.yaml"))
		if err != nil {
			t.Fatalf("crl=%v: the config does not load: %v\n%s", crl, err, cfg)
		}
		if c.Broker == nil || c.Broker.Identity == nil || c.Broker.Identity.X509AnchorFile != filepath.Join(pki, testpki.LabCA) {
			t.Errorf("crl=%v: the humans' anchor resolved to %+v", crl, c.Broker)
		}
		if crl != (len(c.Broker.CertificateStatus.CRLs) == 1) {
			t.Errorf("crl=%v: certificate_status resolved to %+v", crl, c.Broker.CertificateStatus)
		}
		if _, err := policy.Parse([]byte(pol), policy.Env{}); err != nil {
			t.Errorf("the policy does not compile: %v", err)
		}
	}
}

// the compose stack's broker config and policy, with the workload edits, load
// for both roles.
func TestWorkloadE2EFilesLoadForBothRoles(t *testing.T) {
	read := func(name string) string {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	example := read(filepath.Join("..", "..", "examples", "oxidized", "policy.yaml"))
	exBlock, exName, err := exampleRole(example)
	if err != nil {
		t.Fatal(err)
	}
	if exName != "config_backup" || !strings.Contains(exBlock, "show running-config **") || strings.Contains(exBlock, "#") {
		t.Errorf("exampleRole = %q, %q", exName, exBlock)
	}
	for _, tc := range []struct{ block, name string }{{allRole, "oxidized_all"}, {exBlock, exName}} {
		files, err := composeLabFiles(read("port49d-lab.yaml"), read(filepath.Join("slice", "broker.yaml")),
			read(filepath.Join("slice", "policy.yaml")), read("inventory-lab.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		if err := workloadE2EFiles(files, tc.block, tc.name); err != nil {
			t.Fatal(err)
		}
		// phase B's stack (the example's role) also shortens the receipt window (L49).
		restricted := tc.name == exName
		if restricted {
			if err := withReceiptIdleTTL(files, "2m"); err != nil {
				t.Fatal(err)
			}
		}
		dir := t.TempDir()
		t.Setenv("PORT49_LAB_KEY", "labsecret")
		t.Setenv("PORT49_LAB_ENC_KEY", labEncKeyDefault)
		for _, d := range []string{"etc/etcd", "etc/broker", "etc/wl", "run", "state", "spool"} {
			if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		for _, f := range []string{"etc/etcd/ca.pem", "etc/etcd/port49d.pem", "etc/etcd/port49d-key.pem", "etc/etcd/port49-broker.pem",
			"etc/etcd/port49-broker-key.pem", "etc/broker/broker.pem", "etc/broker/broker-key.pem", "etc/broker/broker-ca.pem",
			"etc/wl/workload-ca.pem"} {
			if err := os.WriteFile(filepath.Join(dir, f), []byte("x\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		moved := func(s string) string {
			s = strings.ReplaceAll(s, "/etc/port49-workload", filepath.Join(dir, "etc", "wl"))
			s = strings.ReplaceAll(s, "/etc/port49", filepath.Join(dir, "etc"))
			s = strings.ReplaceAll(s, "/var/lib/port49-broker", filepath.Join(dir, "state"))
			s = strings.ReplaceAll(s, "/var/spool/port49d", filepath.Join(dir, "spool"))
			return strings.ReplaceAll(s, "/run/port49", filepath.Join(dir, "run"))
		}
		for name, body := range files {
			if strings.HasSuffix(name, ".yaml") {
				if err := os.WriteFile(filepath.Join(dir, "etc", name), []byte(moved(body)), 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
		b, err := config.LoadBroker(filepath.Join(dir, "etc", "port49-broker.yaml"))
		if err != nil {
			t.Fatalf("%s: the broker's config does not load: %v\n%s", tc.name, err, moved(files["port49-broker.yaml"]))
		}
		id := b.Broker.Identity
		if id == nil || id.X509AnchorFile != filepath.Join(dir, "etc", "broker", "broker-ca.pem") {
			t.Errorf("%s: the identity block resolved to %+v", tc.name, id)
		}
		if !strings.Contains(files["port49-broker.yaml"], "trust_anchor_file: "+oxidizedAnchor+", spiffe_trust_domains: [port49.lab]") {
			t.Errorf("%s: the machines verifier is not the workload anchor:\n%s", tc.name, files["port49-broker.yaml"])
		}
		d, err := config.Load(filepath.Join(dir, "etc", "port49d.yaml"))
		if err != nil {
			t.Fatalf("%s: port49d's config does not load: %v", tc.name, err)
		}
		if want := map[bool]time.Duration{false: 15 * time.Minute, true: 2 * time.Minute}[restricted]; d.ReceiptIdleTTL != want {
			t.Errorf("%s: receipt_idle_ttl = %s, want %s", tc.name, d.ReceiptIdleTTL, want)
		}
		if _, err := policy.Parse([]byte(files["policy.yaml"]), policy.Env{}); err != nil {
			t.Fatalf("%s: the lab policy does not compile: %v\n%s", tc.name, err, files["policy.yaml"])
		}
		if !strings.Contains(files["policy.yaml"], l48ID) || !strings.Contains(files["policy.yaml"], "roles: ["+tc.name+"]") {
			t.Errorf("%s: the policy does not grant the workload the role:\n%s", tc.name, files["policy.yaml"])
		}
	}
	if err := workloadE2EFiles(map[string]string{"port49-broker.yaml": "broker: {}\n", "policy.yaml": "roles:\n"}, allRole,
		"oxidized_all"); err == nil {
		t.Error("a broker config with no client_ca_file was edited")
	}
}

func TestExampleRoleNeedsItsBlocks(t *testing.T) {
	if _, _, err := exampleRole("subjects:\n"); err == nil {
		t.Error("no roles block accepted")
	}
	if _, _, err := exampleRole("\nroles:\n  - name: x\n"); err == nil {
		t.Error("no subjects block accepted")
	}
}

// Oxidized's node/show: the last run's status and end time; no last run is the zero time.
func TestLastRunReadsOxidizedsShow(t *testing.T) {
	st, end, err := lastRun([]byte(`{"name":"leaf1","last":{"start":"2026-10-08 01:00:00 UTC","end":"2026-10-08 01:00:07 UTC","status":"success","time":"2026-10-08 01:00:07 UTC"}}`))
	if err != nil || st != "success" || !end.Equal(time.Date(2026, 10, 8, 1, 0, 7, 0, time.UTC)) {
		t.Errorf("got %q, %v, %v", st, end, err)
	}
	st, end, err = lastRun([]byte(`{"name":"leaf1","last":null}`))
	if err != nil || st != "" || !end.IsZero() {
		t.Errorf("never run: %q, %v, %v", st, end, err)
	}
	if _, _, err := lastRun([]byte(`<html>`)); err == nil {
		t.Error("a non-JSON answer was read")
	}
	if _, _, err := lastRun([]byte(`{"last":{"status":"x","end":"yesterday"}}`)); err == nil {
		t.Error("an unreadable end time was read")
	}
}

func TestWorkloadNoteHasRule3sFields(t *testing.T) {
	note := workloadNote("L48", "step_ca", "the claim", "the observation", "tests/lab/evidence/x.jsonl", "abc123 run 1",
		"Smallstep CA/0.30.2")
	for _, want := range []string{"# L48 — step_ca\n", "- **Date measured:** 20", "- **Run:** abc123 run 1",
		"- **Platform:** step_ca", "- **Image version:** Smallstep CA/0.30.2", "- **Capture:** `tests/lab/evidence/x.jsonl`",
		"- **Credentials:** none", "## Claim\n\nthe claim", "## Observation\n\nthe observation"} {
		if !strings.Contains(note, want) {
			t.Errorf("the note lacks %q:\n%s", want, note)
		}
	}
}

// a step command's output is kept only when it holds no key material or token.
func TestStepOutputWithKeyMaterialIsNotKept(t *testing.T) {
	if err := stepLeak("Your certificate has been saved in w/w.pem.\n", nil); err != nil {
		t.Errorf("a clean output: %v", err)
	}
	if err := stepLeak("-----BEGIN EC PRIVATE KEY-----\nAAAA\n", nil); err == nil {
		t.Error("a private key was kept")
	}
	if err := stepLeak("-----BEGIN ENCRYPTED PRIVATE KEY-----\n", nil); err == nil {
		t.Error("an encrypted private key was kept")
	}
	if err := stepLeak("provisioner password is hunter2-hunter2\n", []string{"hunter2-hunter2"}); err == nil {
		t.Error("a registered secret was kept")
	}
	if err := stepLeak("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln\n", nil); err == nil {
		t.Error("a compact JWS was kept")
	}
}
