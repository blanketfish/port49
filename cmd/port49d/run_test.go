package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/tacacs/wire"
	"github.com/rhwendt/port49/internal/testpki"
)

// tacacsClient is the smallest TACACS+ client that can log in and ask for
// authorization: one exchange per connection, as the lab's devices use.
type tacacsClient struct {
	t    *testing.T
	addr string
	key  []byte
}

func (c tacacsClient) exchange(typ wire.Type, body []byte) []byte {
	c.t.Helper()
	conn, err := net.Dial("tcp", c.addr)
	if err != nil {
		c.t.Fatal(err)
	}
	defer conn.Close()
	h := wire.Header{MajorVersion: 0xc, Type: typ, SeqNo: 1, SessionID: 0x5eed, Length: uint32(len(body))}
	if _, err := conn.Write(append(h.Encode(), wire.Obfuscate(h, c.key, body)...)); err != nil {
		c.t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	hb := make([]byte, wire.HeaderLen)
	if _, err := io.ReadFull(conn, hb); err != nil {
		c.t.Fatal(err)
	}
	rh, _ := wire.DecodeHeader(hb)
	rb := make([]byte, rh.Length)
	if _, err := io.ReadFull(conn, rb); err != nil {
		c.t.Fatal(err)
	}
	return wire.Obfuscate(rh, c.key, rb)
}

func (c tacacsClient) login(user, password string) uint8 {
	c.t.Helper()
	r, err := wire.DecodeAuthenReply(c.exchange(wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin,
		PrivLvl: 1, AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte(user),
		Port: []byte("ssh"), RemAddr: []byte("198.51.100.4"), Data: []byte(password)}.Encode()))
	if err != nil {
		c.t.Fatal(err)
	}
	return r.Status
}

// authorize asks for a session (no words) or a command. A session is asked at
// the login's priv-lvl 1 and a command at 15, as vEOS does once the session
// reply has granted 15 (tests/lab/results/L1-arista_eos.md).
func (c tacacsClient) authorize(user string, words ...string) wire.AuthorResponse {
	c.t.Helper()
	return c.authorizeAt(15, user, words...)
}

// authorizeAt is authorize with a command asked at priv.
func (c tacacsClient) authorizeAt(priv uint8, user string, words ...string) wire.AuthorResponse {
	c.t.Helper()
	args := [][]byte{[]byte("service=shell")}
	if len(words) == 0 {
		args = append(args, []byte("cmd="))
		priv = 1
	} else {
		args = append(args, []byte("cmd="+words[0]))
		for _, w := range words[1:] {
			args = append(args, []byte("cmd-arg="+w))
		}
		args = append(args, []byte("cmd-arg=<cr>"))
	}
	r, err := wire.DecodeAuthorResponse(c.exchange(wire.TypeAuthor, wire.AuthorRequest{
		AuthenMethod: wire.AuthenMethodTACACSPlus, PrivLvl: priv, AuthenType: wire.AuthenTypeASCII,
		Service: wire.AuthenServiceLogin, User: []byte(user), Port: []byte("vty1"), Args: args}.Encode()))
	if err != nil {
		c.t.Fatal(err)
	}
	return r
}

func (c tacacsClient) permits(user string, words ...string) bool {
	c.t.Helper()
	return c.permitsAt(15, user, words...)
}

func (c tacacsClient) permitsAt(priv uint8, user string, words ...string) bool {
	c.t.Helper()
	s := c.authorizeAt(priv, user, words...).Status
	return s == wire.AuthorStatusPassAdd || s == wire.AuthorStatusPassRepl
}

// mint asks the broker for alice's token on device, over mutual TLS with the
// lab client certificate testpki.WriteLab left beside the broker's.
func mint(t *testing.T, brokerAddr, pkiDir, device string) string {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(filepath.Join(pkiDir, testpki.LabClientCert), filepath.Join(pkiDir, testpki.LabClientKey))
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(filepath.Join(pkiDir, testpki.LabCA))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		Certificates: []tls.Certificate{cert}, RootCAs: roots, MinVersion: tls.VersionTLS13}}}
	resp, err := client.Post("https://"+brokerAddr+"/v1/tokens", "application/json",
		bytes.NewReader([]byte(`{"devices":["`+device+`"]}`)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out api.MintResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Results) != 1 || out.Results[0].Login == "" {
		t.Fatalf("mint: %+v", out)
	}
	return out.Results[0].Login
}

// waitFor polls buf until it holds want, or fails the test.
func waitFor(t *testing.T, buf *syncBuffer, want string) {
	t.Helper()
	waitForCount(t, buf, want, 1)
}

// waitForCount polls buf until it holds want n times, or fails the test.
func waitForCount(t *testing.T, buf *syncBuffer, want string, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for strings.Count(buf.String(), want) < n {
		if time.Now().After(deadline) {
			t.Fatalf("waited for %q; have %q", want, buf.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// records are the decision log's records of one event, in order.
func records(t *testing.T, log *syncBuffer, event string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(log.String()), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil && m["event"] == event {
			out = append(out, m)
		}
	}
	return out
}

func ctxID(m map[string]any) any {
	s, _ := m["session"].(map[string]any)
	return s["ctx_id"]
}

// port49d as it ships — no lab: block, the broker in the process — end to end
// through a live policy change (plan 4b; the end-to-end test plan 4 carried
// here). alice mints and logs in once. Narrowing her role takes her next
// `configure` away in the session she has; lowering her max_privilege lowers
// the level she holds, and her next command above it is denied
// privilege_exceeded; a policy that does not load leaves her as she was;
// withdrawing her grant revokes the context, and her next command is denied
// credential_revoked. She never logs in again, and every command is decided in
// the one context her login created.
func TestRunServesAPolicyEditToALiveSessionWithNoLogout(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log

	b := brokerConfig(t, minimalPolicy).Broker
	pkiDir := filepath.Dir(b.TLSCertFile)
	cfgPath := writeRunConfig(t, b)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfgPath) }()
	// Cleanups run last-registered first: run has returned before stderr and
	// stdout are put back, whether the test passed or failed.
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
		}
	})

	waitFor(t, &out, "port49d: broker listening on ")
	addrs := regexp.MustCompile(`listening on (127\.0\.0\.1:\d+)`).FindAllStringSubmatch(out.String(), -1)
	if len(addrs) != 2 {
		t.Fatalf("stderr: %q", out.String())
	}
	dev := tacacsClient{t: t, addr: addrs[0][1], key: []byte("run-test-secret")}

	if st := dev.login("alice", mint(t, addrs[1][1], pkiDir, "leaf1")); st != wire.AuthenStatusPass {
		t.Fatalf("login: status %d; decision log %s", st, log.String())
	}
	if r := dev.authorize("alice"); r.Status != wire.AuthorStatusPassAdd || len(r.Args) != 1 || string(r.Args[0]) != "priv-lvl=15" {
		t.Fatalf("session authorization: %+v", r)
	}
	if !dev.permits("alice", "configure") {
		t.Fatal("before the edit alice may configure")
	}

	// Narrow: show only. The watch reads the file within two intervals.
	if err := os.WriteFile(b.PolicyFile, []byte(showOnly), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, &out, "port49d: policy refresh: 1 live context(s) updated")
	if dev.permits("alice", "configure") || !dev.permits("alice", "show", "version") {
		t.Fatal("after the edit alice's configure is denied and show is permitted, in the same session")
	}

	// Lower the ceiling to readonly, priv-lvl 1 on EOS: the level alice holds
	// comes down to it, and a command asked at 15 is above it (spec §14).
	lowered := strings.Replace(showOnly, "roles: [r]}", "roles: [r], max_privilege: readonly}", 1)
	if err := os.WriteFile(b.PolicyFile, []byte(lowered), 0o600); err != nil {
		t.Fatal(err)
	}
	waitForCount(t, &out, "port49d: policy refresh: 1 live context(s) updated", 2)
	if dev.permits("alice", "show", "version") {
		t.Fatal("after the ceiling is lowered a command at 15 is above the level alice holds")
	}
	if cmds := records(t, &log, "authorize_command"); cmds[len(cmds)-1]["reason"] != "privilege_exceeded" {
		t.Fatalf("the command above the lowered level: %v", cmds[len(cmds)-1])
	}
	if !dev.permitsAt(1, "alice", "show", "version") {
		t.Fatal("at the lowered level alice's show is still permitted")
	}

	// A typo is refused and the policy in force keeps serving.
	if err := os.WriteFile(b.PolicyFile, []byte(strings.Replace(lowered, "privilege: readonly", "privilege: root", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, &out, "refused; still serving ")
	if !dev.permitsAt(1, "alice", "show", "version") {
		t.Fatal("a refused file changes nothing")
	}

	// Withdraw alice's grant, to carol: alice's context is revoked, not
	// deleted.
	withdrawn := strings.Replace(showOnly, "grants: [{subject: s,", "grants: [{subject: c,", 1)
	withdrawn = strings.Replace(withdrawn, "subjects: [", `subjects: [{name: c, identity: ["user:carol@example.com"], username: carol, token_ttl: 60s}, `, 1)
	if err := os.WriteFile(b.PolicyFile, []byte(withdrawn), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, &out, "1 revoked")
	r := dev.authorizeAt(1, "alice", "show", "version")
	if r.Status != wire.AuthorStatusFail || !strings.Contains(string(r.ServerMsg), "revoked") {
		t.Fatalf("after the grant is withdrawn: %+v", r)
	}

	// One login, one context: every command above was decided in it, and the
	// refresh records name it too.
	redeems := records(t, &log, "redeem")
	if len(redeems) != 1 {
		t.Fatalf("alice logged in %d times", len(redeems))
	}
	id := ctxID(redeems[0])
	for _, event := range []string{"authorize_command", "refresh"} {
		for _, rec := range records(t, &log, event) {
			if ctxID(rec) != id {
				t.Fatalf("a %s record names another context: %v", event, rec)
			}
		}
	}
	cmds := records(t, &log, "authorize_command")
	if last := cmds[len(cmds)-1]; last["reason"] != "credential_revoked" {
		t.Fatalf("the last command: %v", last)
	}
	// The revocation is on the record before the command it denied: a refresh
	// deny, no_grants_matched, then the credential_revoked command.
	revoked, denied := -1, -1
	for i, line := range strings.Split(strings.TrimSpace(log.String()), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) != nil {
			continue
		}
		switch {
		case m["event"] == "refresh" && m["verdict"] == "deny" && m["reason"] == "no_grants_matched":
			revoked = i
		case m["event"] == "authorize_command" && m["reason"] == "credential_revoked":
			denied = i
		}
	}
	if revoked < 0 || denied < revoked {
		t.Fatalf("no refresh deny before the credential_revoked command: %s", log.String())
	}

	cancel()
	select {
	case err := <-done:
		done <- err // for the cleanup
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return when its context ended")
	}
	if !strings.Contains(out.String(), "port49d: accounting spool drained, exiting") {
		t.Fatalf("stderr: %q", out.String())
	}
}
