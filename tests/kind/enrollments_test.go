//go:build kind

package kind

// TestEnrollmentsExportRuns is plan 12c's Task 17 (ruling 13): the chart's enrollments export CronJob
// (backup.enrollments), run for real on kind against a directory, in CI only (`make kind-enrollments`,
// the enrollments job of .github/workflows/kind.yml). The earlier smoke could not run it: the export
// reads the sealed enrollment store of a directory_password verifier, and a directory refuses the smoke's
// human usernames, so this stack has a directory (the L67 OpenLDAP image) and a policy that declares no
// human username.
//
// The directory's bind password is generated for the run, put in Kubernetes Secrets from files in a 0700
// temp directory, and never committed, put on a command line or printed. UNVERIFIED until the first CI run.

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/blanketfish/port49/internal/testpki"
	"github.com/blanketfish/port49/tests/kind/kindtest"
	"github.com/blanketfish/port49/tests/shapes/shapetest"
)

const (
	enrollCluster  = "port49enroll"
	ldapImage      = "port49lab/openldap:bookworm"
	directoryCreds = "port49-directory" // the Secret the chart mounts at /etc/port49/directory (broker.directory.keytabSecret)
	backupsPVC     = "port49-backups"
	exportCron     = release + "-enrollments-export"
)

// enrollValues is the chart values the stack installs with in addition to its own: the directory, a
// directory_password verifier beside the x509 one (a list replaces the stack's, so the x509 line is
// written again), and the export CronJob onto the test's PVC.
const enrollValues = `broker:
  directory: {keytabSecret: ` + directoryCreds + `}
backup:
  enrollments: {enabled: true, claimName: ` + backupsPVC + `}
config:
  broker:
    broker:
      identity:
        humans:
          - {type: x509, trust_anchor_file: /etc/port49/broker/ca.crt}
          - {type: directory_password, principal_domains: [corp.example.com], second_factor: totp}
      directory:
        servers:
          - {uri: "ldaps://openldap.` + ns + `.svc:636", priority: 100, site: lab}
        site: lab
        ca_file: /etc/port49/directory/ca.pem
        bind:
          mechanism: simple
          bind_dn: "cn=port49,ou=Svc,dc=corp,dc=example,dc=com"
          password_secret_ref: file:/etc/port49/directory/bind_password
        base_dn: "dc=corp,dc=example,dc=com"
        groups_base_dn: "ou=G,dc=corp,dc=example,dc=com"
        user_filter: "(objectClass=inetOrgPerson)"
        group_filter: "(objectClass=groupOfNames)"
        principal_attribute: mail
        username_attribute: uid
        certificate_mapping:
          kind: san_email
          allow_weak: true
          issuers: ["CN=port49 lab slice CA"]
        nested_groups: direct
        grace: 4h
`

// enrollPolicy is a policy for a broker with a directory: no human subject declares a username (the
// directory supplies them, and policy load refuses both), so the only subject is the machine one.
func enrollPolicy(deviceNet string) string {
	return `scopes: [{name: all_devices, match: {}}]
roles: [{name: network_admin, privilege: admin, permit: ["**"]}]
subjects:
  - {name: svc_backup, identity: ["system:serviceaccount:` + ns + `:oxidized"], username: svc-backup, token_ttl: 900s}
grants:
  - {subject: svc_backup, scope: all_devices, roles: [network_admin]}
key_groups: [{match: {cidr: ` + deviceNet + `}, key_ref: k}]
keys:
  k:
    current: {version: 1, secret_ref: file:/run/port49/keys/tacacs_v1}
`
}

// ldapPod and ldapService are the L67 OpenLDAP image as a pod and its Service. The bind password reaches
// the container by a secretKeyRef, never as a literal.
const ldapPod = `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"openldap","namespace":"` + ns + `","labels":{"app":"openldap"}},
"spec":{"containers":[{"name":"slapd","image":"` + ldapImage + `","imagePullPolicy":"Never",
"env":[{"name":"LAB_LDAP_PASSWORD","valueFrom":{"secretKeyRef":{"name":"openldap-env","key":"LAB_LDAP_PASSWORD"}}}],
"ports":[{"containerPort":636}],"volumeMounts":[{"name":"pki","mountPath":"/pki","readOnly":true}]}],
"volumes":[{"name":"pki","secret":{"secretName":"openldap-pki"}}]}}`

const ldapService = `{"apiVersion":"v1","kind":"Service","metadata":{"name":"openldap","namespace":"` + ns + `"},
"spec":{"selector":{"app":"openldap"},"ports":[{"port":636,"targetPort":636}]}}`

// dirFiles writes the directory's server certificate (the Service's names), the CA that signs it and
// the generated bind password into a 0700 directory, and returns it. Every file is 0600.
func dirFiles(t *testing.T) (dir string, password string) {
	t.Helper()
	dir = t.TempDir()
	now := time.Now()
	nb, na := now.Add(-time.Hour), now.Add(24*time.Hour)
	ca, err := testpki.NewCA("port49 kind directory CA", nb, na)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := ca.Issue(testpki.Leaf{CommonName: "port49 kind directory", NotBefore: nb, NotAfter: na,
		DNSNames: []string{"openldap", "openldap." + ns + ".svc", "openldap." + ns + ".svc.cluster.local"}})
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := testpki.PEMs(srv)
	if err != nil {
		t.Fatal(err)
	}
	// "Aa1+" first, as the lab's passwords: the four classes a directory's complexity rule may want.
	rnd, err := testpki.RandomSecret(28)
	if err != nil {
		t.Fatal(err)
	}
	password = "Aa1+" + rnd
	for name, body := range map[string][]byte{"ca.pem": ca.PEM(), "server.pem": certPEM, "server-key.pem": keyPEM,
		"LAB_LDAP_PASSWORD": []byte(password), "bind_password": []byte(password)} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir, password
}

// startDirectory is Options.Before: it builds the L67 OpenLDAP image, loads it into the cluster, makes the
// Secrets (from files only) and the pod and its Service, and waits for the fixture.
func startDirectory(t *testing.T, files string) func(c *kindtest.Cluster, subnet, gateway string) {
	return func(c *kindtest.Cluster, _, _ string) {
		root := kindtest.Root()
		build := exec.Command("docker", "build", "-t", ldapImage, filepath.Join(root, "tests", "lab", "directory", "openldap"))
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("docker build %s: %v\n%s", ldapImage, err, kindtest.Filter(string(out)))
		}
		if out, err := exec.Command(kindtest.Bin(t, "KIND_BIN"), "load", "docker-image", ldapImage, "--name", c.Name).CombinedOutput(); err != nil {
			t.Fatalf("kind load %s: %v\n%s", ldapImage, err, kindtest.Filter(string(out)))
		}
		f := func(n string) string { return filepath.Join(files, n) }
		for _, sec := range []struct {
			name  string
			files []string
		}{
			{"openldap-pki", []string{"ca.pem", "server.pem", "server-key.pem"}},
			{"openldap-env", []string{"LAB_LDAP_PASSWORD"}},
			{directoryCreds, []string{"ca.pem", "bind_password"}},
		} {
			args := []string{"-n", ns, "create", "secret", "generic", sec.name}
			for _, n := range sec.files {
				args = append(args, "--from-file="+n+"="+f(n))
			}
			c.Kubectl(args...)
		}
		c.Apply(ldapPod)
		c.Apply(ldapService)
		shapetest.WaitFor(t, "the OpenLDAP fixture to load", 5*time.Minute, func() bool {
			logs, err := c.KubectlTry("", "-n", ns, "logs", "openldap")
			return err == nil && strings.Contains(logs, "lab: openldap fixture loaded")
		})
	}
}

// exportName is the dated name the finish step gives a file: enrollments-YYYYMMDDTHHMMSSZ.json.
var exportName = regexp.MustCompile(`^/v/enrollments-(\d{8})T\d{6}Z\.json$`)

// secretShaped is what no log of the job may hold: the words of a credential, outside the verifier's
// own name, or a token's or a key's shape.
var secretShaped = regexp.MustCompile(`(?i)password|token|secret|credential|eyJ[A-Za-z0-9_-]{8,}|-----BEGIN`)

func TestEnrollmentsExportRuns(t *testing.T) {
	shapetest.RefuseOnKeyHost(t) // kind's nodes are privileged containers
	files, password := dirFiles(t)
	s := bringUp(t, enrollCluster, Options{
		Before:           startDirectory(t, files),
		Values:           enrollValues,
		Policy:           enrollPolicy,
		StoreRolesSecret: directoryCreds,
	})
	// The brokers, then the install step: init-enrollments creates the sealed store in etcd, as the
	// README's one-off run does. A port49d pod is not needed, and its policy has no human username.
	s.copyIssuer()
	for _, p := range []string{"t-broker-0", "t-broker-1"} {
		s.c.WaitReady(ns, p, 4*time.Minute)
	}
	out, err := s.c.KubectlTry("", "-n", ns, "exec", "t-broker-0", "-c", "port49-broker", "--",
		"/usr/local/bin/port49-broker", "init-enrollments", "--config", "/etc/port49/config/port49-broker.yaml")
	if err != nil || !strings.Contains(out, "created the enrollment store") {
		t.Fatalf("init-enrollments: %v\n%s", err, kindtest.Filter(out))
	}

	s.c.Apply(`apiVersion: v1
kind: PersistentVolumeClaim
metadata: {name: ` + backupsPVC + `, namespace: ` + ns + `}
spec:
  accessModes: [ReadWriteOnce]
  storageClassName: ` + scName + `
  resources: {requests: {storage: 1Gi}}
`)

	// listing is the backups volume's enrollments files, one stat line each, and whether a .new is left.
	listing := func(name string) []kindtest.Stat {
		t.Helper()
		out := s.debugPod(name, backupsPVC, "stat -c '%a %u %g %n' /v/enrollments-*.json; ! ls /v/enrollments.new 2>/dev/null", true)
		st, err := kindtest.ParseStat(out)
		if err != nil {
			t.Fatalf("%s: %v\n%s", name, err, shapetest.Filtered(s.root, out))
		}
		return st
	}

	// Run 1: the Job succeeds and the volume holds one dated, 0600, 65532-owned file named for today.
	dayBefore := time.Now().UTC().Format("20060102")
	if got := s.backup(exportCron, "enroll-run1"); got != "succeeded" {
		t.Fatalf("the first run %s:\n%s", got, shapetest.Filtered(s.root, s.c.PodReport(ns, jobPod(s, "enroll-run1"))))
	}
	dayAfter := time.Now().UTC().Format("20060102")
	first := listing("ls-run1")
	if len(first) != 1 {
		t.Fatalf("want one dated file after the first run, got %d: %v", len(first), first)
	}
	if err := first[0].Want("600", 65532, 65532); err != nil {
		t.Error(err)
	}
	m := exportName.FindStringSubmatch(first[0].Path)
	if m == nil || (m[1] != dayBefore && m[1] != dayAfter) {
		t.Errorf("the file's name %q does not carry the run's date (%s)", first[0].Path, dayBefore)
	}
	sum1 := strings.TrimSpace(s.debugPod("sum-run1", backupsPVC, "sha256sum "+first[0].Path+" | cut -d' ' -f1", true))

	// The job's log holds no enrollment byte or credential. The password value itself, then the words and
	// shapes of one, checked on the raw log; what is printed on a failure has been through the filter.
	logs := s.c.Kubectl("-n", ns, "logs", "job/enroll-run1", "--all-containers", "--prefix")
	if strings.Contains(logs, password) {
		t.Error("the export job's log holds the directory's bind password (value withheld)")
	}
	if loc := secretShaped.FindString(strings.ReplaceAll(logs, "directory_password", "")); loc != "" {
		t.Errorf("the export job's log holds credential text (matched %q); its log, filtered:\n%s", strings.ToLower(loc[:min(len(loc), 8)]),
			shapetest.Filtered(s.root, logs))
	}
	if sum1 != "" && strings.Contains(logs, sum1) {
		t.Error("the export job's log holds the export's hash")
	}

	// Run 2, a later second: a second dated file, and the first is not touched.
	if got := s.backup(exportCron, "enroll-run2"); got != "succeeded" {
		t.Fatalf("the second run %s:\n%s", got, shapetest.Filtered(s.root, s.c.PodReport(ns, jobPod(s, "enroll-run2"))))
	}
	second := listing("ls-run2")
	if len(second) != 2 {
		t.Fatalf("want two dated files after the second run, got %d: %v", len(second), second)
	}
	for _, st := range second {
		if err := st.Want("600", 65532, 65532); err != nil {
			t.Error(err)
		}
	}
	if second[0].Path == second[1].Path {
		t.Errorf("the two runs wrote one file: %s", second[0].Path)
	}
	if after := strings.TrimSpace(s.debugPod("sum-run1-again", backupsPVC, "sha256sum "+first[0].Path+" | cut -d' ' -f1", true)); after != sum1 {
		t.Errorf("the second run changed %s", first[0].Path)
	}
	t.Logf("enrollments export: two runs, %d dated files, each 0600 65532:65532", len(second))
}

// jobPod is the name of a pod of the Job, for a failure's report.
func jobPod(s *smoke, job string) string {
	out, err := s.c.KubectlTry("", "-n", ns, "get", "pods", "-l", "job-name="+job, "-o", "jsonpath={.items[0].metadata.name}")
	if err != nil {
		return job
	}
	return strings.TrimSpace(out)
}

// The values and the policy are text the test cannot see until a cluster takes them: they at least parse,
// the policy names no human username and the directory's secrets are named as the chart mounts them.
func TestEnrollmentsValuesAndPolicyParse(t *testing.T) {
	var v map[string]any
	if err := yaml.Unmarshal([]byte(enrollValues), &v); err != nil {
		t.Fatalf("the values: %v", err)
	}
	var p map[string]any
	if err := yaml.Unmarshal([]byte(enrollPolicy("172.18.0.0/16")), &p); err != nil {
		t.Fatalf("the policy: %v", err)
	}
	if strings.Contains(enrollPolicy("x"), "user:") {
		t.Error("the policy has a human subject")
	}
	for _, want := range []string{"keytabSecret: " + directoryCreds, "file:/etc/port49/directory/bind_password", "ca_file: /etc/port49/directory/ca.pem"} {
		if !strings.Contains(enrollValues, want) {
			t.Errorf("the values lack %q", want)
		}
	}
}
