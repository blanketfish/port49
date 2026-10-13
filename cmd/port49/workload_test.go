package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/testpki"
)

// workloadBroker serves /v1/config and /v1/tokens as answer says, over TLS
// requiring a client certificate, and returns the flags that reach it.
func workloadBroker(t *testing.T, answer func(w http.ResponseWriter, req api.MintRequest)) []string {
	t.Helper()
	return workloadBrokerPaged(t, 100, answer)
}

// workloadBrokerPaged is workloadBroker with /v1/config's batch_max.
func workloadBrokerPaged(t *testing.T, batchMax int, answer func(w http.ResponseWriter, req api.MintRequest)) []string {
	t.Helper()
	return workloadBrokerWith(t, batchMax, answer, api.Identity{Principal: "spiffe://corp.example.com/host/oxidized-01",
		Method: "cert", Subject: "svc_oxidized"})
}

// workloadBrokerWith is workloadBrokerPaged with the identity /v1/identity answers.
func workloadBrokerWith(t *testing.T, batchMax int, answer func(w http.ResponseWriter, req api.MintRequest),
	identity api.Identity) []string {
	t.Helper()
	now := time.Now()
	dir := t.TempDir()
	ca, err := testpki.NewCA("workloads", now.Add(-time.Hour), now.Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	srvCert, _ := ca.Issue(testpki.Leaf{CommonName: "broker", IPs: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour)})
	u, _ := url.Parse("spiffe://corp.example.com/host/oxidized-01")
	cli, _ := ca.Issue(testpki.Leaf{CommonName: "w", URIs: []*url.URL{u}, Client: true,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)})
	certPEM, keyPEM, _ := testpki.PEMs(cli)
	for name, body := range map[string][]byte{"ca.pem": ca.PEM(), "w.pem": certPEM, "w-key.pem": keyPEM} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/config":
			_ = json.NewEncoder(w).Encode(api.Config{BatchMax: batchMax})
		case "/v1/tokens":
			var req api.MintRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			answer(w, req)
		case "/v1/identity":
			if identity.Method == "redirect" {
				w.Header().Set("Location", "https://elsewhere.example.com/v1/identity")
				w.WriteHeader(http.StatusTemporaryRedirect)
				return
			}
			if identity.Method == "html" { // a proxy's page in place of the broker's answer
				_, _ = w.Write([]byte("<html>sorry</html>"))
				return
			}
			_ = json.NewEncoder(w).Encode(identity)
		}
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{srvCert}, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: ca.Pool(), MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return []string{"--broker", srv.URL, "--broker-ca", filepath.Join(dir, "ca.pem"),
		"--cert", filepath.Join(dir, "w.pem"), "--key", filepath.Join(dir, "w-key.pem"), "--deadline", "1s"}
}

func mixed(w http.ResponseWriter, req api.MintRequest) {
	resp := api.MintResponse{Principal: "spiffe://corp.example.com/host/oxidized-01", Subject: "svc_oxidized"}
	for _, d := range req.Devices {
		if d == "fw1" {
			resp.Results = append(resp.Results, api.MintItem{Device: d, Verdict: "deny", Reason: "no_grants_matched"})
			continue
		}
		resp.Results = append(resp.Results, api.MintItem{Device: d, Verdict: "permit", Address: "10.0.0.1",
			Platform: "arista_eos", Username: "svc-oxidized", Login: "TOKEN-" + d, ExpiresAt: "2026-10-08T03:00:00Z"})
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func TestWorkloadTokenWritesTSV(t *testing.T) {
	flags := workloadBroker(t, mixed)
	var out, errb bytes.Buffer
	code := run(append(append([]string{"workload", "token"}, flags...), "leaf1", "leaf2"), &out, &errb)
	want := "leaf1\t10.0.0.1\tarista_eos\tsvc-oxidized\tTOKEN-leaf1\t2026-10-08T03:00:00Z\n" +
		"leaf2\t10.0.0.1\tarista_eos\tsvc-oxidized\tTOKEN-leaf2\t2026-10-08T03:00:00Z\n"
	if code != 0 || out.String() != want || errb.Len() != 0 {
		t.Fatalf("exit %d\nstdout %q\nstderr %q", code, out.String(), errb.String())
	}
}

// 0 all permitted; 1 one denied (the permitted still written, no token on
// stderr); 77 every device denied, or a final refusal before anything was
// minted, with nothing written; 75 nothing minted by the deadline; 2 usage
// (pre-flight I-1).
func TestExitCodesTellCronWhatHappened(t *testing.T) {
	flags := workloadBroker(t, mixed)
	var out, errb bytes.Buffer
	if code := run(append(append([]string{"workload", "token"}, flags...), "leaf1", "fw1"), &out, &errb); code != 1 ||
		!strings.Contains(out.String(), "TOKEN-leaf1") || !strings.Contains(errb.String(), "fw1: deny no_grants_matched") ||
		strings.Contains(errb.String(), "TOKEN") {
		t.Fatalf("one denied: exit %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	out.Reset()
	errb.Reset()
	if code := run(append(append([]string{"workload", "token"}, flags...), "fw1"), &out, &errb); code != exitFinal ||
		out.Len() != 0 || !strings.Contains(errb.String(), "fw1: deny no_grants_matched") {
		t.Fatalf("every device denied: exit %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	revoked := workloadBroker(t, func(w http.ResponseWriter, _ api.MintRequest) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(api.Error{Error: "credential_revoked", Detail: "this principal is revoked"})
	})
	out.Reset()
	errb.Reset()
	if code := run(append(append([]string{"workload", "token"}, revoked...), "leaf1", "leaf2"), &out, &errb); code != exitFinal ||
		out.Len() != 0 || !strings.Contains(errb.String(), "401 credential_revoked") ||
		!strings.Contains(errb.String(), "2 of 2 devices were not minted") {
		t.Fatalf("revoked: exit %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	busy := workloadBroker(t, func(w http.ResponseWriter, _ api.MintRequest) {
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(api.Error{Error: "store_unavailable", Detail: "the broker's store did not answer"})
	})
	out.Reset()
	errb.Reset()
	if code := run(append(append([]string{"workload", "token"}, busy...), "leaf1", "leaf2"), &out, &errb); code != exitTemporary ||
		out.Len() != 0 || !strings.Contains(errb.String(), "2 of 2 devices were not minted; run again") {
		t.Fatalf("busy: exit %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	if code := run([]string{"workload", "token", "leaf1"}, &out, &errb); code != 2 {
		t.Fatalf("no flags: exit %d", code)
	}
}

// A final refusal on page two after page one minted: page one is written and
// the run exits 1, so the wrapper still queues those nodes; a token never
// reaches stderr (pre-flight I-1).
func TestAFinalRefusalOnPageTwoWritesPageOne(t *testing.T) {
	flags := workloadBrokerPaged(t, 1, func(w http.ResponseWriter, req api.MintRequest) {
		if req.Devices[0] == "leaf2" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(api.Error{Error: "credential_revoked", Detail: "this principal is revoked"})
			return
		}
		mixed(w, req)
	})
	var out, errb bytes.Buffer
	code := run(append(append([]string{"workload", "token"}, flags...), "leaf1", "leaf2"), &out, &errb)
	if code != 1 || out.String() != "leaf1\t10.0.0.1\tarista_eos\tsvc-oxidized\tTOKEN-leaf1\t2026-10-08T03:00:00Z\n" ||
		!strings.Contains(errb.String(), "401 credential_revoked") ||
		!strings.Contains(errb.String(), "1 of 2 devices were not minted") || strings.Contains(errb.String(), "TOKEN") {
		t.Fatalf("exit %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

// An expired certificate is final: said before anything connects, nothing
// written, exit 77 (pre-flight I-1).
func TestAnExpiredCertificateIsFinal(t *testing.T) {
	flags := workloadBroker(t, mixed)
	now := time.Now()
	ca, err := testpki.NewCA("expired", now.Add(-72*time.Hour), now.Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	old, err := ca.Issue(testpki.Leaf{CommonName: "w", Client: true, NotBefore: now.Add(-48 * time.Hour),
		NotAfter: now.Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := testpki.PEMs(old)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, body := range map[string][]byte{"w.pem": certPEM, "w-key.pem": keyPEM} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A flag given twice takes its last value.
	flags = append(flags, "--cert", filepath.Join(dir, "w.pem"), "--key", filepath.Join(dir, "w-key.pem"))
	var out, errb bytes.Buffer
	if code := run(append(append([]string{"workload", "token"}, flags...), "leaf1"), &out, &errb); code != exitFinal ||
		out.Len() != 0 || !strings.Contains(errb.String(), "renew it against your CA") {
		t.Fatalf("exit %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

// A broker that is not an https URL is a usage error: nothing is read or sent.
func TestABrokerThatIsNotHTTPSIsUsage(t *testing.T) {
	flags := workloadBroker(t, mixed)
	flags = append(flags, "--broker", "http://127.0.0.1:9")
	var out, errb bytes.Buffer
	if code := run(append(append([]string{"workload", "token"}, flags...), "leaf1"), &out, &errb); code != 2 ||
		out.Len() != 0 || !strings.Contains(errb.String(), "https") {
		t.Fatalf("exit %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

// A redirect is final and never followed: before anything minted it is 77
// with nothing written; after page one it is 1 with page one written.
func TestARedirectIsFinal(t *testing.T) {
	redirect := func(w http.ResponseWriter, _ api.MintRequest) {
		w.Header().Set("Location", "https://elsewhere.example.com/v1/tokens")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}
	var out, errb bytes.Buffer
	flags := workloadBroker(t, redirect)
	if code := run(append(append([]string{"workload", "token"}, flags...), "leaf1"), &out, &errb); code != exitFinal ||
		out.Len() != 0 || !strings.Contains(errb.String(), "redirect") || !strings.Contains(errb.String(), "1 of 1 devices were not minted") {
		t.Fatalf("first page: exit %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	out.Reset()
	errb.Reset()
	flags = workloadBrokerPaged(t, 1, func(w http.ResponseWriter, req api.MintRequest) {
		if req.Devices[0] == "leaf2" {
			redirect(w, req)
			return
		}
		mixed(w, req)
	})
	if code := run(append(append([]string{"workload", "token"}, flags...), "leaf1", "leaf2"), &out, &errb); code != 1 ||
		!strings.Contains(out.String(), "TOKEN-leaf1") || !strings.Contains(errb.String(), "redirect") ||
		strings.Contains(errb.String(), "TOKEN") {
		t.Fatalf("page two: exit %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

// What the broker sends back is untrusted text: no control character reaches
// stderr, from an error's code and detail or from an item's own words, and no
// token does either.
func TestBrokerTextIsPrintSafeOnStderr(t *testing.T) {
	hostile := func(w http.ResponseWriter, req api.MintRequest) {
		_ = json.NewEncoder(w).Encode(api.MintResponse{Results: []api.MintItem{
			{Device: "fw\x1b[2J1", Verdict: "deny", Reason: "no\nforged: permit\x1b]0;x\a"},
			{Device: "fw2", Verdict: "error", Error: "boom\r\x00"},
		}})
	}
	flags := workloadBroker(t, hostile)
	var out, errb bytes.Buffer
	code := run(append(append([]string{"workload", "token"}, flags...), "fw1", "fw2"), &out, &errb)
	if code != exitFinal || out.Len() != 0 || strings.ContainsAny(errb.String(), "\x1b\r\x00\a") ||
		strings.Count(errb.String(), "\n") != 2 {
		t.Fatalf("items: exit %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	out.Reset()
	errb.Reset()
	refused := workloadBroker(t, func(w http.ResponseWriter, _ api.MintRequest) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(api.Error{Error: "bad\x1b[31m_code", Detail: "line one\nforged line\x1b[2J"})
	})
	code = run(append(append([]string{"workload", "token"}, refused...), "leaf1"), &out, &errb)
	if code != exitFinal || out.Len() != 0 || strings.ContainsAny(errb.String(), "\x1b\r\x00\a") ||
		strings.Count(errb.String(), "\n") != 1 {
		t.Fatalf("error: exit %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

// --out is 0600 and renamed into place; --devices-file reads one name a line,
// skipping blanks and # comments.
func TestWorkloadTokenWritesItsOutputPrivately(t *testing.T) {
	flags := workloadBroker(t, mixed)
	dir := t.TempDir()
	list := filepath.Join(dir, "nodes")
	if err := os.WriteFile(list, []byte("# backed up nightly\nleaf1\n\nleaf2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outFile := filepath.Join(dir, "tokens.tsv")
	if err := os.WriteFile(outFile, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	args := append(append([]string{"workload", "token"}, flags...), "--devices-file", list, "--out", outFile, "--format", "json")
	if code := run(args, &out, &errb); code != 0 || out.Len() != 0 {
		t.Fatalf("exit %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	fi, err := os.Stat(outFile)
	raw, _ := os.ReadFile(outFile)
	var resp api.MintResponse
	if err != nil || fi.Mode().Perm() != 0o600 || json.Unmarshal(raw, &resp) != nil || len(resp.Results) != 2 {
		// The body holds tokens: say its size, never its text.
		t.Fatalf("mode %v err %v body of %d bytes", fi.Mode(), err, len(raw))
	}
}

func TestWorkloadIdentityPrintsTheWorkload(t *testing.T) {
	flags := workloadBroker(t, mixed)
	var out, errb bytes.Buffer
	if code := run(append([]string{"workload", "identity"}, flags...), &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "spiffe://corp.example.com/host/oxidized-01") ||
		!strings.Contains(out.String(), "svc_oxidized") {
		t.Fatalf("exit %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	if code := run([]string{"workload", "identity"}, &out, &errb); code != 2 { // pre-flight M-6
		t.Fatalf("no flags: exit %d", code)
	}
}

// The identity's text is the broker's: printed as one safe line each.
func TestWorkloadIdentityPrintsSafeText(t *testing.T) {
	flags := workloadBrokerWith(t, 100, mixed, api.Identity{Principal: "spiffe://corp.example.com/host/a\x1b[2Jb",
		Method: "cert", Subject: "svc\nforged", Groups: []string{"g\x1b1"},
		Grants: []api.IdentityGrant{{Scope: "all\r", Roles: []string{"r\x07"}}}, AuthTime: "now\x1b"})
	var out, errb bytes.Buffer
	if code := run(append([]string{"workload", "identity"}, flags...), &out, &errb); code != 0 ||
		strings.ContainsAny(out.String(), "\x1b\r\a") || strings.Contains(out.String(), "svc\nforged") {
		t.Fatalf("exit %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

// identity treats a New error that is not a certificate's as usage, as token does.
func TestWorkloadIdentityWithANonHTTPSBrokerIsUsage(t *testing.T) {
	flags := append(workloadBroker(t, mixed), "--broker", "http://127.0.0.1:9")
	var out, errb bytes.Buffer
	if code := run(append([]string{"workload", "identity"}, flags...), &out, &errb); code != 2 {
		t.Fatalf("exit %d stderr %q", code, errb.String())
	}
}

// A redirect on identity is final.
func TestWorkloadIdentityRedirectIsFinal(t *testing.T) {
	flags := workloadBrokerWith(t, 100, mixed, api.Identity{Method: "redirect"})
	var out, errb bytes.Buffer
	if code := run(append([]string{"workload", "identity"}, flags...), &out, &errb); code != exitFinal ||
		out.Len() != 0 || !strings.Contains(errb.String(), "redirect") {
		t.Fatalf("exit %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

// A control character in a permitted item leaves that device out and says so;
// the others are written and the run exits 1.
func TestADeviceWithAControlCharacterIsLeftOut(t *testing.T) {
	flags := workloadBroker(t, func(w http.ResponseWriter, req api.MintRequest) {
		resp := api.MintResponse{}
		for _, d := range req.Devices {
			user := "svc"
			switch d {
			case "bad1":
				user = "sv\tc"
			case "bad2":
				user = "sv\rc"
			}
			resp.Results = append(resp.Results, api.MintItem{Device: d, Verdict: "permit", Address: "10.0.0.1",
				Platform: "arista_eos", Username: user, Login: "TOKEN-" + d, ExpiresAt: "2026-10-08T03:00:00Z"})
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	var out, errb bytes.Buffer
	code := run(append(append([]string{"workload", "token"}, flags...), "leaf1", "bad1", "bad2"), &out, &errb)
	if code != 1 || out.String() != "leaf1\t10.0.0.1\tarista_eos\tsvc\tTOKEN-leaf1\t2026-10-08T03:00:00Z\n" ||
		!strings.Contains(errb.String(), "bad1") || !strings.Contains(errb.String(), "bad2") ||
		strings.Contains(errb.String(), "TOKEN") || strings.ContainsAny(errb.String(), "\t\r") {
		t.Fatalf("exit %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	out.Reset()
	errb.Reset()
	if code := run(append(append([]string{"workload", "token"}, flags...), "bad1"), &out, &errb); code != exitFinal ||
		out.Len() != 0 || !strings.Contains(errb.String(), "bad1") {
		t.Fatalf("only bad: exit %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

// Tokens were minted but could not be written: temporary, the last output stands.
func TestAnUnwritableOutputIsTemporary(t *testing.T) {
	flags := workloadBroker(t, mixed)
	dir := t.TempDir()
	var out, errb bytes.Buffer
	missing := filepath.Join(dir, "nodir", "tokens.tsv")
	if code := run(append(append([]string{"workload", "token"}, flags...), "--out", missing, "leaf1"), &out, &errb); code != exitTemporary ||
		strings.Contains(errb.String(), "TOKEN") {
		t.Fatalf("missing dir: exit %d stderr %q", code, errb.String())
	}
	// A directory at the target: the rename fails, the target stands, no temp is left.
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	errb.Reset()
	if code := run(append(append([]string{"workload", "token"}, flags...), "--out", target, "leaf1"), &out, &errb); code != exitTemporary {
		t.Fatalf("directory target: exit %d stderr %q", code, errb.String())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != "target" {
		t.Fatalf("the parent holds %d entries, want target alone", len(entries))
	}
	if code := run(append(append([]string{"workload", "token"}, flags...), "leaf1"), failingWriter{}, &errb); code != exitTemporary {
		t.Fatalf("stdout write failed: exit %d", code)
	}
}

// A temporary failure on page two writes page one and exits 75.
func TestATemporaryFailureOnPageTwoWritesPageOne(t *testing.T) {
	flags := workloadBrokerPaged(t, 1, func(w http.ResponseWriter, req api.MintRequest) {
		if req.Devices[0] == "leaf2" {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(api.Error{Error: "store_unavailable", Detail: "down"})
			return
		}
		mixed(w, req)
	})
	var out, errb bytes.Buffer
	code := run(append(append([]string{"workload", "token"}, flags...), "leaf1", "leaf2"), &out, &errb)
	if code != exitTemporary || out.String() != "leaf1\t10.0.0.1\tarista_eos\tsvc-oxidized\tTOKEN-leaf1\t2026-10-08T03:00:00Z\n" ||
		!strings.Contains(errb.String(), "1 of 2 devices were not minted; run again") || strings.Contains(errb.String(), "TOKEN") {
		t.Fatalf("exit %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

// A fault line is "<device>: <verdict> <reason>: <detail>", with one space.
func TestAFaultLineCarriesTheDetail(t *testing.T) {
	flags := workloadBroker(t, func(w http.ResponseWriter, _ api.MintRequest) {
		_ = json.NewEncoder(w).Encode(api.MintResponse{Results: []api.MintItem{
			// The broker's own fault item: an error and a detail, no verdict.
			{Device: "fw2", Error: "broker_error", Detail: "why\x1b[2J"},
			{Device: "fw3", Detail: "only detail"},
		}})
	})
	var out, errb bytes.Buffer
	run(append(append([]string{"workload", "token"}, flags...), "fw2", "fw3"), &out, &errb)
	if !strings.Contains(errb.String(), "port49 workload token: fw2: broker_error: why?[2J\n") ||
		!strings.Contains(errb.String(), "port49 workload token: fw3: only detail\n") {
		t.Fatalf("stderr %q", errb.String())
	}
}

// withFlag is flags with the value after name replaced.
func withFlag(flags []string, name, value string) []string {
	out := append([]string(nil), flags...)
	for i := range out {
		if out[i] == name {
			out[i+1] = value
		}
	}
	return out
}

// A TLS trust failure either way is final, not a broker outage: 77 naming it
// (decision 40 ruling 10), where a refused connection stays 75.
func TestWorkloadTLSTrustFailureIsFinal(t *testing.T) {
	flags := workloadBroker(t, mixed)
	other, err := testpki.NewCA("other", time.Now().Add(-time.Hour), time.Now().Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	otherCA := filepath.Join(t.TempDir(), "other.pem")
	if err := os.WriteFile(otherCA, other.PEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	wrongCA := withFlag(flags, "--broker-ca", otherCA)
	for _, sub := range [][]string{{"token", "leaf1"}, {"identity"}} {
		var out, errb bytes.Buffer
		args := append(append([]string{"workload", sub[0]}, wrongCA...), sub[1:]...)
		if code := run(args, &out, &errb); code != exitFinal || out.Len() != 0 ||
			!strings.Contains(errb.String(), "--broker-ca") {
			t.Fatalf("%s, a broker outside --broker-ca: exit %d stdout %q stderr %q", sub[0], code, out.String(),
				errb.String())
		}
	}
	// The broker refuses the workload's certificate: its CA is another's.
	now := time.Now()
	u, _ := url.Parse("spiffe://corp.example.com/host/oxidized-01")
	cli, _ := other.Issue(testpki.Leaf{CommonName: "w", URIs: []*url.URL{u}, Client: true,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)})
	certPEM, keyPEM, _ := testpki.PEMs(cli)
	dir := t.TempDir()
	for name, body := range map[string][]byte{"w.pem": certPEM, "w-key.pem": keyPEM} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	refused := withFlag(withFlag(flags, "--cert", filepath.Join(dir, "w.pem")), "--key", filepath.Join(dir, "w-key.pem"))
	for _, sub := range [][]string{{"token", "leaf1"}, {"identity"}} {
		var out, errb bytes.Buffer
		args := append(append([]string{"workload", sub[0]}, refused...), sub[1:]...)
		if code := run(args, &out, &errb); code != exitFinal || out.Len() != 0 ||
			!strings.Contains(errb.String(), "refused") {
			t.Fatalf("%s, a refused certificate: exit %d stdout %q stderr %q", sub[0], code, out.String(), errb.String())
		}
	}
	// A refused connection is still a broker outage.
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	down := withFlag(flags, "--broker", "https://"+addr)
	var out, errb bytes.Buffer
	if code := run(append(append([]string{"workload", "token"}, down...), "leaf1"), &out, &errb); code != exitTemporary {
		t.Fatalf("refused connection: exit %d stderr %q", code, errb.String())
	}
}

// identity exits 77 like token for a 200 that does not decode (M-7).
func TestWorkloadIdentityUndecodableAnswerIsFinal(t *testing.T) {
	flags := workloadBrokerWith(t, 100, mixed, api.Identity{Method: "html"})
	var out, errb bytes.Buffer
	if code := run(append([]string{"workload", "identity"}, flags...), &out, &errb); code != exitFinal {
		t.Fatalf("exit %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

// The 3am case (decision 41 ruling 7): through a DC outage past grace the
// broker answers 503 directory_unavailable; port49 workload token retries to
// --deadline, writes nothing, and exits 75 so cron tries the next window.
func TestADirectoryOutageExitsTemporary(t *testing.T) {
	down := workloadBroker(t, func(w http.ResponseWriter, _ api.MintRequest) {
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(api.Error{Error: "directory_unavailable", Detail: "no directory server answered " +
			"and no membership verified within the grace window is held; the agent retries"})
	})
	var out, errb bytes.Buffer
	if code := run(append(append([]string{"workload", "token"}, down...), "leaf1"), &out, &errb); code != exitTemporary ||
		out.Len() != 0 || !strings.Contains(errb.String(), "503 directory_unavailable") ||
		!strings.Contains(errb.String(), "1 of 1 devices were not minted; run again") {
		t.Fatalf("exit %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

// --scope sweeps every page and writes one line per permitted device.
func TestWorkloadTokenSweepsAScope(t *testing.T) {
	flags := workloadBrokerPaged(t, 1, func(w http.ResponseWriter, req api.MintRequest) {
		resp := api.MintResponse{Principal: "spiffe://corp.example.com/host/oxidized-01"}
		item := func(d, tok string) api.MintItem {
			return api.MintItem{Device: d, Verdict: "permit", Address: "10.0.0.1", Platform: "arista_eos",
				Username: "svc", Login: tok, ExpiresAt: "2026-10-09T03:00:00Z"}
		}
		switch req.After {
		case "":
			resp.Results, resp.Next = []api.MintItem{item("leaf1", "T1")}, "leaf1"
		case "leaf1":
			resp.Results = []api.MintItem{item("leaf2", "T2")}
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	var out, errb bytes.Buffer
	code := run(append(append([]string{"workload", "token"}, flags...), "--scope", "backup_targets"), &out, &errb)
	if code != 0 || out.String() != "leaf1\t10.0.0.1\tarista_eos\tsvc\tT1\t2026-10-09T03:00:00Z\n"+
		"leaf2\t10.0.0.1\tarista_eos\tsvc\tT2\t2026-10-09T03:00:00Z\n" {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

// A sweep cut short by a broker that cannot answer page two writes page one,
// exits 75, and counts only the tokens minted (a denied item is not one).
func TestASweepCutShortByTheGateWritesPageOne(t *testing.T) {
	flags := workloadBrokerPaged(t, 2, func(w http.ResponseWriter, req api.MintRequest) {
		if req.After == "leaf2" {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(api.Error{Error: "store_unavailable", Detail: "the broker's store did not answer"})
			return
		}
		_ = json.NewEncoder(w).Encode(api.MintResponse{Principal: "spiffe://corp.example.com/host/oxidized-01",
			Results: []api.MintItem{
				{Device: "leaf1", Verdict: "permit", Address: "10.0.0.1", Platform: "arista_eos", Username: "svc",
					Login: "T1", ExpiresAt: "2026-10-09T03:00:00Z"},
				{Device: "leaf2", Verdict: "deny", Reason: "no_grants_matched"}}, Next: "leaf2"})
	})
	var out, errb bytes.Buffer
	code := run(append(append([]string{"workload", "token", "--deadline", "1ms"}, flags...), "--scope", "dc"), &out, &errb)
	if code != exitTemporary || out.String() != "leaf1\t10.0.0.1\tarista_eos\tsvc\tT1\t2026-10-09T03:00:00Z\n" ||
		!strings.Contains(errb.String(), "stopped after 1 tokens minted; run again") || strings.Contains(errb.String(), "T1") {
		t.Fatalf("exit %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

// A final refusal on page two of a sweep writes page one and exits 1.
func TestASweepRefusedOnPageTwoWritesPageOne(t *testing.T) {
	flags := workloadBrokerPaged(t, 1, func(w http.ResponseWriter, req api.MintRequest) {
		if req.After == "leaf1" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(api.Error{Error: "bad_request", Detail: "after is not a device"})
			return
		}
		_ = json.NewEncoder(w).Encode(api.MintResponse{Principal: "spiffe://corp.example.com/host/oxidized-01",
			Results: []api.MintItem{{Device: "leaf1", Verdict: "permit", Address: "10.0.0.1", Platform: "arista_eos",
				Username: "svc", Login: "T1", ExpiresAt: "2026-10-09T03:00:00Z"}}, Next: "leaf1"})
	})
	var out, errb bytes.Buffer
	code := run(append(append([]string{"workload", "token"}, flags...), "--scope", "dc"), &out, &errb)
	if code != 1 || out.String() != "leaf1\t10.0.0.1\tarista_eos\tsvc\tT1\t2026-10-09T03:00:00Z\n" ||
		!strings.Contains(errb.String(), "stopped after 1 tokens minted") || strings.Contains(errb.String(), "T1") {
		t.Fatalf("exit %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

// A sweep that selects nothing for the workload is final, exit 77, with one
// message whether the scope exists or not (decision 42 rulings 2 and 5).
func TestAnEmptySweepIsFinal(t *testing.T) {
	flags := workloadBroker(t, func(w http.ResponseWriter, req api.MintRequest) {
		_ = json.NewEncoder(w).Encode(api.MintResponse{Principal: "spiffe://corp.example.com/host/oxidized-01",
			Results: []api.MintItem{}})
	})
	var out, errb bytes.Buffer
	code := run(append(append([]string{"workload", "token"}, flags...), "--scope", "nope"), &out, &errb)
	if code != exitFinal || out.Len() != 0 || !strings.Contains(errb.String(),
		"port49 workload token: scope nope: no device it selects is one you hold a grant on, or no scope has that name") {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

// --scope with a device list is usage.
func TestAScopeAndDevicesTogetherIsUsage(t *testing.T) {
	flags := workloadBroker(t, mixed)
	var out, errb bytes.Buffer
	if code := run(append(append([]string{"workload", "token"}, flags...), "--scope", "dc", "leaf1"), &out, &errb); code != 2 {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
}

// mixedMFA is mixed, with core1 denied under a per-login requirement whose
// challenge must never be printed.
func mixedMFA(w http.ResponseWriter, req api.MintRequest) {
	resp := api.MintResponse{Principal: "spiffe://corp.example.com/host/oxidized-01", Subject: "svc_oxidized"}
	for _, d := range req.Devices {
		switch d {
		case "fw1":
			resp.Results = append(resp.Results, api.MintItem{Device: d, Verdict: "deny", Reason: "no_grants_matched"})
		case "core1":
			resp.Results = append(resp.Results, api.MintItem{Device: d, Verdict: "deny", Reason: "per_login_mfa_required",
				PerLoginMFA: &api.PerLoginMFA{Device: d, Challenge: "CHALLENGE", Accept: []string{"hardware_key_touch"},
					ReuseForSeconds: 900}})
		default:
			resp.Results = append(resp.Results, api.MintItem{Device: d, Verdict: "permit", Address: "10.0.0.1",
				Platform: "arista_eos", Username: "svc-oxidized", Login: "TOKEN-" + d, ExpiresAt: "2026-10-08T03:00:00Z"})
		}
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// --format json lists the refused beside the minted, with no token and no
// challenge, and exits 1 as before.
func TestWorkloadJSONListsTheRefused(t *testing.T) {
	flags := workloadBroker(t, mixedMFA)
	var out, errb bytes.Buffer
	code := run(append(append([]string{"workload", "token", "--format", "json"}, flags...), "leaf1", "fw1", "core1"),
		&out, &errb)
	var got workloadJSON
	if code != 1 || json.Unmarshal(out.Bytes(), &got) != nil || len(got.Results) != 1 || len(got.Refused) != 2 ||
		got.Refused[0].Reason != "no_grants_matched" || got.Refused[1].PerLoginMFA == nil ||
		got.Refused[1].PerLoginMFA.ReuseForSeconds != 900 {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	if strings.Contains(out.String(), "CHALLENGE") || strings.Count(out.String(), "TOKEN-") != 1 {
		t.Fatalf("stdout %q", out.String())
	}
}

// goldenJSON fails t unless stdout is the golden file the Python library's
// tests are fed (pre-flight I3): the two sides read the same bytes.
func goldenJSON(t *testing.T, name string, stdout []byte) {
	t.Helper()
	want, err := os.ReadFile(filepath.Join("..", "..", "clients", "python", "tests", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	if got := bytes.TrimSpace(stdout); !bytes.Equal(got, bytes.TrimSpace(want)) {
		t.Fatalf("stdout\n%s\nis not %s\n%s", got, name, want)
	}
}

// Every device denied: exit 77 as before, and stdout says which and why,
// with "results": [] (never null).
func TestWorkloadJSONOnEveryDeviceDenied(t *testing.T) {
	flags := workloadBroker(t, mixedMFA)
	var out, errb bytes.Buffer
	code := run(append(append([]string{"workload", "token", "--format", "json"}, flags...), "fw1"), &out, &errb)
	var got workloadJSON
	if code != 77 || json.Unmarshal(out.Bytes(), &got) != nil || len(got.Results) != 0 || len(got.Refused) != 1 {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	goldenJSON(t, "workload_every_device_denied.json", out.Bytes())
}

// A scope selecting nothing: exit 77 as before, and stdout says nothing was
// selected, told apart from a failure.
func TestWorkloadJSONOnAnEmptySweep(t *testing.T) {
	flags := workloadBroker(t, func(w http.ResponseWriter, req api.MintRequest) {
		_ = json.NewEncoder(w).Encode(api.MintResponse{Principal: "spiffe://corp.example.com/host/oxidized-01",
			Subject: "svc_oxidized"})
	})
	var out, errb bytes.Buffer
	code := run(append(append([]string{"workload", "token", "--format", "json"}, flags...), "--scope", "none"),
		&out, &errb)
	if code != 77 {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	goldenJSON(t, "workload_empty_sweep.json", out.Bytes())
}

// With --out, nothing is written when nothing was minted (decision 40 ruling
// 10), and stdout stays empty.
func TestWorkloadJSONOutStillWritesOnlyAPermit(t *testing.T) {
	flags := workloadBroker(t, mixedMFA)
	path := filepath.Join(t.TempDir(), "tokens.json")
	if err := os.WriteFile(path, []byte("LAST"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := run(append(append([]string{"workload", "token", "--format", "json", "--out", path}, flags...), "fw1"),
		&out, &errb)
	if b, _ := os.ReadFile(path); code != 77 || string(b) != "LAST" || out.Len() != 0 {
		t.Fatalf("code %d file %q stdout %q", code, b, out.String())
	}
}

// stopAt answers like mixedMFA, except that the page whose first device is
// bad gets status (a body of the broker's own words, never read back).
func stopAt(bad string, status int) func(w http.ResponseWriter, req api.MintRequest) {
	return func(w http.ResponseWriter, req api.MintRequest) {
		if len(req.Devices) > 0 && req.Devices[0] == bad {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"bad_request","detail":"BODY-WORDS"}`))
			return
		}
		mixedMFA(w, req)
	}
}

// refusedBy is got's refused entries as device -> error code.
func refusedBy(got workloadJSON) map[string]string {
	m := map[string]string{}
	for _, r := range got.Refused {
		m[r.Device] = r.Error
	}
	return m
}

// A run that stops early never looks like a finished one (review I1): a
// final error after a deny names the devices it left, and says it stopped.
func TestWorkloadJSONNamesWhatAFinalErrorLeftAfterADeny(t *testing.T) {
	flags := workloadBrokerPaged(t, 1, stopAt("leaf2", http.StatusBadRequest))
	var out, errb bytes.Buffer
	code := run(append(append([]string{"workload", "token", "--format", "json"}, flags...), "fw1", "leaf2", "leaf3"),
		&out, &errb)
	var got workloadJSON
	if code != 77 || json.Unmarshal(out.Bytes(), &got) != nil || len(got.Results) != 0 || got.Stopped != "broker_refused" ||
		len(got.Refused) != 3 || refusedBy(got)["leaf2"] != "broker_refused" || refusedBy(got)["leaf3"] != "broker_refused" ||
		got.Refused[0].Reason != "no_grants_matched" {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	if strings.Contains(out.String(), "BODY-WORDS") {
		t.Fatalf("an unvalidated body reached stdout: %q", out.String())
	}
}

// A final error after a permit: the token is there, the rest is named.
func TestWorkloadJSONNamesWhatAFinalErrorLeftAfterAPermit(t *testing.T) {
	flags := workloadBrokerPaged(t, 1, stopAt("leaf2", http.StatusBadRequest))
	var out, errb bytes.Buffer
	code := run(append(append([]string{"workload", "token", "--format", "json"}, flags...), "leaf1", "leaf2"), &out, &errb)
	var got workloadJSON
	if code != 1 || json.Unmarshal(out.Bytes(), &got) != nil || len(got.Results) != 1 || got.Stopped != "broker_refused" ||
		len(got.Refused) != 1 || refusedBy(got)["leaf2"] != "broker_refused" {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

// A 500 is agent_error, as the token command files it.
func TestWorkloadJSONFilesAServerFaultAsAgentError(t *testing.T) {
	flags := workloadBrokerPaged(t, 1, stopAt("leaf2", http.StatusInternalServerError))
	var out, errb bytes.Buffer
	code := run(append(append([]string{"workload", "token", "--format", "json"}, flags...), "leaf1", "leaf2"), &out, &errb)
	var got workloadJSON
	if code != 1 || json.Unmarshal(out.Bytes(), &got) != nil || got.Stopped != "agent_error" ||
		refusedBy(got)["leaf2"] != "agent_error" {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

// Exit 75 after a deny and a permit names the devices the deadline left (M1).
func TestWorkloadJSONOnExit75NamesTheUnminted(t *testing.T) {
	flags := workloadBrokerPaged(t, 1, stopAt("leaf2", http.StatusServiceUnavailable))
	var out, errb bytes.Buffer
	code := run(append(append([]string{"workload", "token", "--format", "json"}, flags...), "--deadline", "100ms",
		"fw1", "leaf1", "leaf2", "leaf3"), &out, &errb)
	var got workloadJSON
	if code != 75 || json.Unmarshal(out.Bytes(), &got) != nil || len(got.Results) != 1 || got.Stopped != "broker_unavailable" ||
		len(got.Refused) != 3 || got.Refused[0].Reason != "no_grants_matched" ||
		refusedBy(got)["leaf2"] != "broker_unavailable" || refusedBy(got)["leaf3"] != "broker_unavailable" {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

// A scope sweep that stops cannot name what it left, so it says it stopped.
func TestWorkloadJSONOnAScopeSweepThatStops(t *testing.T) {
	flags := workloadBroker(t, func(w http.ResponseWriter, req api.MintRequest) {
		if req.After != "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(api.MintResponse{Principal: "spiffe://corp.example.com/host/oxidized-01",
			Subject: "svc_oxidized", Next: "leaf1", Results: []api.MintItem{{Device: "leaf1", Verdict: "permit",
				Address: "10.0.0.1", Platform: "arista_eos", Username: "svc-oxidized", Login: "TOKEN-leaf1",
				ExpiresAt: "2026-10-08T03:00:00Z"}}})
	})
	var out, errb bytes.Buffer
	code := run(append(append([]string{"workload", "token", "--format", "json"}, flags...), "--scope", "dc"), &out, &errb)
	var got workloadJSON
	if code != 1 || json.Unmarshal(out.Bytes(), &got) != nil || len(got.Results) != 1 || got.Stopped != "broker_refused" ||
		len(got.Refused) != 0 || !strings.Contains(out.String(), `"refused":[]`) {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

// A finished run has no stopped key, however many were refused.
func TestWorkloadJSONOfAFinishedRunHasNoStopped(t *testing.T) {
	flags := workloadBroker(t, mixedMFA)
	var out, errb bytes.Buffer
	run(append(append([]string{"workload", "token", "--format", "json"}, flags...), "leaf1", "fw1"), &out, &errb)
	if strings.Contains(out.String(), "stopped") {
		t.Fatalf("stdout %q", out.String())
	}
}

// An item with an error and a detail, and a permit with no token, both land
// in refused, the detail made printable (M2).
func TestWorkloadJSONRefusesAnErroredItemAndATokenlessPermit(t *testing.T) {
	flags := workloadBroker(t, func(w http.ResponseWriter, req api.MintRequest) {
		_ = json.NewEncoder(w).Encode(api.MintResponse{Principal: "p", Subject: "s", Results: []api.MintItem{
			{Device: "brk", Error: "broker_error", Detail: "bad\x1bthing"},
			{Device: "nolog", Verdict: "permit", Address: "10.0.0.1"},
		}})
	})
	var out, errb bytes.Buffer
	code := run(append(append([]string{"workload", "token", "--format", "json"}, flags...), "brk", "nolog"), &out, &errb)
	var got workloadJSON
	if code != 77 || json.Unmarshal(out.Bytes(), &got) != nil || len(got.Refused) != 2 ||
		got.Refused[0].Error != "broker_error" || strings.ContainsRune(got.Refused[0].Detail, 0x1b) ||
		got.Refused[1].Device != "nolog" {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}
