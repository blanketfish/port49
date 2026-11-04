// Package l89 holds the pure parts of lab entry L89 (spec §15): a Velero file-system backup (node
// agent) of a chart release's volumes, a deleted namespace and a restore, then a mint and a login. The
// verdicts, the files the harness hands to the object store and to Velero, and the results. The harness
// (tests/lab/l89_test.go, tag lab) measures and records; this package decides and renders, so a results
// file is built from the cells and never typed by hand.
//
// The backup holds the issuing CA's private key, and the results file is an uploaded CI artifact that
// will be public: Results refuses text that looks like a key, a PEM block or a credential, and the
// harness records only stat lines, versions, PASS or FAIL and the first characters of a fingerprint.
package l89

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/blanketfish/port49/tests/shapes/l82"
)

// Order is the cells' order in the results.
var Order = []string{"a", "b"}

func title(id string) string {
	return map[string]string{
		"a": "(a) back up both StatefulSets, delete the namespace, restore: ownership, mode, readiness, the CA",
		"b": "(b) after the restore, a mint and a login",
	}[id]
}

// Stat is one `stat -c '%a %u %g %n'` line of a volume.
type Stat struct {
	Path, Mode string
	UID, GID   int
}

func (s Stat) String() string { return fmt.Sprintf("%s %s %d:%d", s.Path, s.Mode, s.UID, s.GID) }

// Differences lists what changed between the stat lines taken before the backup and after the restore,
// one line each; a path in one list and not the other is a difference. Empty is "unchanged".
func Differences(before, after []Stat) []string {
	was := map[string]Stat{}
	for _, s := range before {
		was[s.Path] = s
	}
	var out []string
	seen := map[string]bool{}
	for _, s := range after {
		seen[s.Path] = true
		b, ok := was[s.Path]
		switch {
		case !ok:
			out = append(out, s.Path+" is new after the restore")
		case b != s:
			out = append(out, fmt.Sprintf("%s was %s %d:%d, is %s %d:%d", s.Path, b.Mode, b.UID, b.GID, s.Mode, s.UID, s.GID))
		}
	}
	for _, s := range before {
		if !seen[s.Path] {
			out = append(out, s.Path+" is gone after the restore")
		}
	}
	return out
}

// A is cell (a)'s measurements.
type A struct {
	Ready             bool   // both StatefulSets became ready after the restore
	FenceRefusal      bool   // a pod's log holds the fence's refusal of its data directory
	FingerprintBefore string // the sha256 of the issuing CA certificate before the backup
	FingerprintAfter  string // and after the restore
	LogBefore         string // the fingerprint the broker's "issuing as" line printed before; "" when it printed none
	LogAfter          string // and after the restore
}

// JudgeA is PASS iff both StatefulSets became ready with no fence refusal and the issuing CA is the one
// it was. A fingerprint not read is a FAIL, never an equal pair of empty ones.
//
// When the broker printed a fingerprint before the backup, it must print the same one after the restore.
func JudgeA(a A) string {
	if a.LogBefore != "" && a.LogBefore != a.LogAfter {
		return l82.Fail
	}
	if a.Ready && !a.FenceRefusal && a.FingerprintBefore != "" && a.FingerprintBefore == a.FingerprintAfter {
		return l82.Pass
	}
	return l82.Fail
}

var issuingAs = regexp.MustCompile(`issuing as .* \(([^()\s]+)\), valid until `)

// LogFingerprint is the fingerprint in the last "issuing as <subject> (<fingerprint>), valid until"
// line of a broker's log, or "" when it printed none (internal/issuer).
func LogFingerprint(logs string) string {
	got := ""
	for _, ln := range strings.Split(logs, "\n") {
		if m := issuingAs.FindStringSubmatch(ln); m != nil {
			got = m[1]
		}
	}
	return got
}

var longRun = regexp.MustCompile(`[A-Za-z0-9_+/=.-]{24,}`)
var credWords = regexp.MustCompile(`(?i)password|token|secret|eyJ`)

// Scrub is the filter every piece of diagnosis passes before it is kept: it drops each line with a
// credential word or a JWT, and replaces each run of 24 or more key characters with <LONG>.
func Scrub(s string) string {
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		if credWords.MatchString(ln) {
			continue
		}
		out = append(out, longRun.ReplaceAllString(ln, "<LONG>"))
	}
	return strings.Join(out, "\n")
}

// The shipped example names the release's namespace and etcd's (examples/etcd); the kind lab runs both in
// one namespace (tests/kind applyExample). LabSchedule is the example with the etcd namespace folded
// into the release's, so the lab applies the file as shipped but for that. It fails on a file without
// the line it rewrites, so a changed example cannot go untested.
const shippedNamespaces = "includedNamespaces: [port49, port49-etcd]"

func LabSchedule(example string) (string, error) {
	if strings.Count(example, shippedNamespaces) != 1 {
		return "", fmt.Errorf("l89: the example does not hold %q exactly once", shippedNamespaces)
	}
	return strings.Replace(example, shippedNamespaces, "includedNamespaces: [port49]", 1), nil
}

// JudgeB is PASS iff both a mint and a login succeeded after the restore.
func JudgeB(mint, login bool) string {
	if mint && login {
		return l82.Pass
	}
	return l82.Fail
}

// Short is the first characters of a fingerprint, enough to compare and too short to be a key.
func Short(fp string) string {
	if len(fp) < 12 {
		return "not read"
	}
	return fp[:12]
}

// Random is n random bytes as hex: a per-run credential, never printed.
func Random(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

var hexOnly = regexp.MustCompile(`^[0-9a-f]{16,128}$`)

func checkCred(id, secret string) error {
	if !hexOnly.MatchString(id) || !hexOnly.MatchString(secret) {
		return fmt.Errorf("l89: a credential is not lowercase hex of 16 to 128 characters")
	}
	return nil
}

// AWSCredentials is the credentials file Velero's AWS plugin reads (velero install --secret-file). The
// harness writes it 0600 and never prints it.
func AWSCredentials(id, secret string) (string, error) {
	if err := checkCred(id, secret); err != nil {
		return "", err
	}
	return "[default]\naws_access_key_id=" + id + "\naws_secret_access_key=" + secret + "\n", nil
}

// StoreConfig is the object store's identity file: one identity with the credentials, all actions.
func StoreConfig(id, secret string) (string, error) {
	if err := checkCred(id, secret); err != nil {
		return "", err
	}
	return `{"identities":[{"name":"velero","credentials":[{"accessKey":"` + id + `","secretKey":"` + secret +
		`"}],"actions":["Admin","Read","Write","List","Tagging"]}]}` + "\n", nil
}

// CurlConfig is a curl config file (curl -K) that makes the bucket with a signed request, so the
// credentials are in a 0600 file and never in curl's arguments.
func CurlConfig(id, secret, url, region string) (string, error) {
	if err := checkCred(id, secret); err != nil {
		return "", err
	}
	if !regexp.MustCompile(`^http://127\.0\.0\.1:[0-9]+/[a-z0-9-]+$`).MatchString(url) || !regexp.MustCompile(`^[a-z0-9-]+$`).MatchString(region) {
		return "", fmt.Errorf("l89: the bucket URL or region")
	}
	return "silent\nfail\nrequest = \"PUT\"\nurl = \"" + url + "\"\nuser = \"" + id + ":" + secret + "\"\naws-sigv4 = \"aws:amz:" + region + ":s3\"\n", nil
}

// Env is what the results record about the run.
type Env struct {
	Date, Runner, Run, Docker, Kernel, Kind, NodeImage, Kubectl, Helm string
	Velero, VeleroImage, AWSPlugin, ObjectStore, VolumeBackups        string
}

func nz(s string) string {
	if strings.TrimSpace(s) == "" {
		return "not recorded"
	}
	return s
}

// img renders an image reference with its path separators spaced: "velero/velero-plugin-for-aws" is a
// run of 28 key characters to Leak, and the digest after it is replaced by Leak, not shortened.
func img(s string) string { return strings.ReplaceAll(s, "/", " / ") }

func cell(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "|", "\\|"), "\n", " ")
}

func verdict(cells []l82.Cell, id string) string {
	for _, c := range cells {
		if c.ID == id && c.Verdict != "" {
			return c.Verdict
		}
	}
	return l82.NotRun
}

// Leak is why text must not be written: what l82.Leak refuses (24 or more key characters, a JWT, the
// words for a credential), and a PEM block. Empty when the text is clean.
func Leak(s string) string {
	if strings.Contains(s, "-----BEGIN") {
		return "a PEM block"
	}
	return l82.Leak(s)
}

// Results is the results file for the CI artifact, built from cells and nothing else. It fails,
// writing nothing, on a cell it does not know or if any text in it looks like a key. A cell never run
// is NOT RUN, which the harness fails on.
func Results(env Env, cells []l82.Cell) (string, error) {
	known := map[string]bool{}
	for _, id := range Order {
		known[id] = true
	}
	for _, c := range cells {
		if !known[c.ID] {
			return "", fmt.Errorf("l89: a cell %q that is not one of the entry's", c.ID)
		}
	}
	var b strings.Builder
	b.WriteString("# L89: a Velero file-system backup of a chart release's volumes, restored (kind)\n\n")
	b.WriteString("Generated by `make lab-l89` (tests/lab/l89_test.go) from the cells below; edit the harness, not this file.\n\n")
	b.WriteString("The backup holds `state/issuing-ca.key` (the issuing CA's private key), each broker's state and each port49d's accounting spool. The bucket alone also holds the namespaces' Secrets as Velero reads them, in the clear: the TACACS+ keys, the store's encryption key, the etcd client identities and the TLS key. The repository key protects only the volumes.\n\nThe lab's etcd shares the release's namespace; the example Schedule names the release's namespace and the shipped etcd example's.\n\n")
	fmt.Fprintf(&b, "- Date: %s\n- Platform: %s\n- Run: %s\n- Docker: %s\n- Kernel: %s\n- kind: %s\n- Node image: %s\n- kubectl: %s\n- helm: %s\n- Velero client: %s\n- Velero server and node agent image: %s\n- Velero AWS plugin image: %s\n- Object store image: %s\n- Pod volume backups completed: %s\n\n",
		nz(env.Date), nz(env.Runner), nz(env.Run), nz(env.Docker), nz(env.Kernel), nz(env.Kind), nz(env.NodeImage), nz(env.Kubectl), nz(env.Helm),
		nz(env.Velero), nz(img(env.VeleroImage)), nz(img(env.AWSPlugin)), nz(img(env.ObjectStore)), nz(env.VolumeBackups))
	b.WriteString("## Verdicts\n\n| Cell | Verdict |\n|---|---|\n")
	for _, id := range Order {
		fmt.Fprintf(&b, "| %s | %s |\n", title(id), verdict(cells, id))
	}
	b.WriteString("\n")
	for _, id := range Order {
		fmt.Fprintf(&b, "## %s: %s\n\n", title(id), verdict(cells, id))
		var rows []l82.Row
		for _, c := range cells {
			if c.ID == id {
				rows = c.Rows
			}
		}
		if len(rows) == 0 {
			b.WriteString("No observation.\n\n")
			continue
		}
		b.WriteString("| Case | Observation |\n|---|---|\n")
		for _, r := range rows {
			fmt.Fprintf(&b, "| %s | %s |\n", cell(r.Case), cell(r.Observation))
		}
		b.WriteString("\n")
	}
	b.WriteString("The register row closes only when both cells have a PASS or a FAIL; a FAIL is a measured answer.\n")
	out := b.String()
	if why := Leak(out); why != "" {
		return "", fmt.Errorf("l89: the results hold %s: nothing is written", why)
	}
	return out, nil
}
