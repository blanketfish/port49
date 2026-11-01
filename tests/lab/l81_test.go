//go:build lab

package lab

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/tests/lab/labcreds"
)

// TestL81IPv6ServerName runs spec §15 L81 cell (a) on the lab host: L72's
// port49d, with server_names listing an IPv6 address too, and openssl
// s_client sending IPv6 literals as SNI (Go's crypto/tls client sends no
// SNI for an address). Cell (b), an IPv6 vJunos-router, is not run here,
// and the row stays open until it is.
func TestL81IPv6ServerName(t *testing.T) {
	if err := labGuardAt(l66StopSentinel, "/", l66DiskFloorMB); err != nil {
		t.Fatal(err)
	}
	if root == "" {
		r, err := repoRoot()
		if err != nil {
			t.Fatalf("INVALID: repo root: %v", err)
		}
		root = r
		t.Cleanup(func() { root = "" })
	}
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Fatal("INVALID: no openssl on PATH")
	}
	osslVersion, _ := exec.Command("openssl", "version").Output()
	e := l72Prepare(t, "file")
	cfg, err := os.ReadFile(e.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	const names = "  server_names: [tacacs.l72.example]\n"
	if !strings.Contains(string(cfg), names) {
		t.Fatal("INVALID: L72's config no longer lists server_names as this harness expects")
	}
	e.write("port49d.yaml", []byte(strings.Replace(string(cfg), names,
		"  server_names: [tacacs.l72.example, \""+l81Listed+"\"]\n", 1)))
	e.build()
	e.start()

	tlsArgs := func(sni string) []string {
		return []string{"-brief", "-tls1_3", "-cert", e.certs["good"][0], "-key", e.certs["good"][1], "-CAfile", e.caFile,
			"-servername", sni}
	}
	records := func() int { return len(e.records(`"tls_outcome":"sni_mismatch"`)) }
	okHandshakes := func() float64 { return e.metric(`port49_tls_handshakes_total{outcome="ok"}`) }

	var o l81Obs
	okBefore, recBefore := okHandshakes(), records()
	accepted := e.openssl(1, tlsArgs(l81ListedSpelling)...)
	time.Sleep(time.Second)
	o.acceptedOK, o.acceptedRecords = okHandshakes()-okBefore, records()-recBefore

	time.Sleep(6 * time.Second) // past any window, as L72's settle
	declined, held := e.metric(connEvent("declined_refused")), e.metric(connEvent("held_refused"))
	// No stdin wait: the second connection goes at once, inside the 2s window.
	refused := e.openssl(0, tlsArgs(l81Unlisted)...)
	again := e.openssl(0, tlsArgs(l81Unlisted)...)
	time.Sleep(time.Second)
	rec := e.records(`"tls_outcome":"sni_mismatch"`)
	o.refused = len(rec) - recBefore - o.acceptedRecords
	o.refusedDetail = len(rec) > 0 && strings.Contains(rec[len(rec)-1], "asked for server name "+l81Unlisted)
	o.declinedRise = e.metric(connEvent("declined_refused")) - declined
	o.heldRise = e.metric(connEvent("held_refused")) - held
	e.checkAlive()

	e.write("openssl-accepted.txt", []byte(accepted))
	e.write("openssl-refused.txt", []byte(refused))
	e.write("openssl-again.txt", []byte(again))
	observed := fmt.Sprintf("server_names [tacacs.l72.example, %s]. openssl -servername %s: %v ok handshakes, %d "+
		"sni_mismatch records; first line %q (evidence/L81-reference/openssl-accepted.txt). -servername %s: %d "+
		"sni_mismatch records, detail names the spelling sent: %v; record: %s; alert: %s "+
		"(evidence/L81-reference/openssl-refused.txt). The next connection at once: declined_refused +%v, "+
		"held_refused +%v; alert: %s (evidence/L81-reference/openssl-again.txt)", l81Listed, l81ListedSpelling,
		o.acceptedOK, o.acceptedRecords, l72FirstLine(accepted, "Protocol version", "(no protocol line)"), l81Unlisted,
		o.refused, o.refusedDetail, strings.Join(rec, " "), l72AlertLine(refused), o.declinedRise, o.heldRise,
		l72AlertLine(again))
	l81Note(t, e, string(osslVersion), observed, l81AgreesA(o))
}

// l81Note writes the evidence and the note after checking that neither holds
// a secret, then fails the test if cell (a) disagreed. The row stays open:
// cell (b) is unmeasured.
func l81Note(t *testing.T, e *l72Env, osslVersion, observed string, ok bool) {
	t.Helper()
	files := map[string][]byte{"decisions.jsonl": l72RedactCredentialHash(e.logBytes())}
	for _, name := range []string{"openssl-accepted.txt", "openssl-refused.txt", "openssl-again.txt"} {
		b, err := os.ReadFile(filepath.Join(e.dir, name))
		if err != nil {
			t.Fatal(err)
		}
		files[name] = b
	}
	mark := "yes"
	if !ok {
		mark = "**no**"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# L81 — reference clients\n\n")
	fmt.Fprintf(&b, "- **Date measured:** %s\n", time.Now().UTC().Format("2006-01-02"))
	fmt.Fprintf(&b, "- **Platform:** reference clients on the lab host, no device (cell a only)\n")
	fmt.Fprintf(&b, "- **Image version:** %s; Go %s\n", strings.TrimSpace(osslVersion), runtime.Version())
	fmt.Fprintf(&b, "- **Capture:** tests/lab/evidence/L81-reference/\n")
	fmt.Fprintf(&b, "- **Run:** %s\n\n", runLine())
	fmt.Fprintf(&b, "## Claim\n\nspec §15 L81 (a). Cell (b), vJunos-router 26.2 over IPv6, is unmeasured here, so the "+
		"row stays open.\n\n## Observation\n\n")
	fmt.Fprintf(&b, "| cell | claim | observed | agrees with decision 50 |\n|---|---|---|---|\n")
	fmt.Fprintf(&b, "| a | %s | %s | %s |\n", l81ClaimA, strings.ReplaceAll(observed, "|", "\\|"), mark)
	note := string(l72RedactCredentialHash([]byte(labcreds.RedactNote(b.String()))))
	for name, body := range files {
		if hits := labcreds.Contains(body, e.secrets); len(hits) > 0 {
			t.Fatalf("INVALID: evidence %s holds a secret; nothing written", name)
		}
		if strings.HasPrefix(name, "openssl-") {
			if hits := l72TranscriptLeaks(string(body)); len(hits) > 0 {
				t.Fatalf("INVALID: transcript %s carries TLS session material (%v); nothing written", name, hits)
			}
		}
	}
	if hits := labcreds.Contains([]byte(note), e.secrets); len(hits) > 0 {
		t.Fatal("INVALID: the note holds a secret; nothing written")
	}
	evDir := filepath.Join(root, "tests", "lab", "evidence", "L81-reference")
	if err := os.MkdirAll(evDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(evDir, name), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(root, "tests", "lab", "results", "L81-reference.md")
	if err := os.WriteFile(path, []byte(note), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s", path)
	if !ok {
		t.Fatal("cell a disagrees with decision 50 ruling 10: the note records what was observed")
	}
}
