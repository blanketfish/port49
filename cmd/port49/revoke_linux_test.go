//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/blanketfish/port49/internal/agent"
	"github.com/blanketfish/port49/internal/broker"
	"github.com/blanketfish/port49/internal/broker/api"
	"github.com/blanketfish/port49/internal/daemon/metrics"
	"github.com/blanketfish/port49/internal/decision"
	"github.com/blanketfish/port49/internal/policy"
	"github.com/blanketfish/port49/internal/session"
	"github.com/blanketfish/port49/internal/store"
	"github.com/blanketfish/port49/internal/store/memory"
	"github.com/blanketfish/port49/internal/testpki"
	"github.com/blanketfish/port49/internal/token"
)

// --cert takes one certificate, PEM or DER, and names its subject before
// anything is sent; a chain, an oversized file, or flags that conflict are
// refused before the dial.
func TestRevokeCertFileForms(t *testing.T) {
	stub := newAdminStub(t, func(agent.AdminRequest) (int, any) {
		return 200, api.RevokeResponse{By: "admin", Principal: "", Text: "revoked it"}
	})
	sent := func() []api.RevokeRequest {
		var ops []api.RevokeRequest
		for _, r := range stub.requests() {
			var op api.RevokeRequest
			_ = json.Unmarshal(r.Body, &op)
			ops = append(ops, op)
		}
		return ops
	}

	now := time.Now()
	ca, err := testpki.NewCA("Corp Issuing CA", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.Issue(testpki.Leaf{CommonName: "alice", Client: true, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := testpki.PEMs(leaf)
	if err != nil {
		t.Fatal(err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	dir := t.TempDir()
	write := func(name string, body []byte) string {
		f := filepath.Join(dir, name)
		if err := os.WriteFile(f, body, 0o600); err != nil {
			t.Fatal(err)
		}
		return f
	}

	// DER: the same issuer and serial as PEM, and the subject on stderr.
	var out, errb bytes.Buffer
	der := write("alice.der", leaf.Leaf.Raw)
	if code := run([]string{"revoke", "--cert", der}, &out, &errb); code != 0 ||
		!strings.Contains(errb.String(), `subject "CN=alice", issuer "CN=Corp Issuing CA", serial 0x`+leaf.Leaf.SerialNumber.Text(16)) {
		t.Fatalf("exit %d: %q", code, errb.String())
	}
	if ops := sent(); len(ops) != 1 || ops[0].CertIssuer != leaf.Leaf.Issuer.String() || ops[0].CertSerial != "0x"+leaf.Leaf.SerialNumber.Text(16) {
		t.Fatalf("%+v", ops)
	}

	for name, c := range map[string]struct {
		body []byte
		want string
	}{
		"chain.pem":     {append(append([]byte{}, certPEM...), ca.PEM()...), "holds 2 certificates; give the leaf alone"},
		"bundle.pem":    {append(append([]byte{}, ca.PEM()...), certPEM...), "holds 2 certificates; give the leaf alone"},
		"key.der":       {keyBlock.Bytes, "holds a private key"},
		"garbage.txt":   {[]byte("not a certificate\n"), "holds no certificate, PEM or DER"},
		"pubkey.pem":    {pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1}}), "holds no certificate"},
		"oversized.pem": {bytes.Repeat([]byte{'a'}, maxCertFile+1), "larger than 1 MiB"},
		"/dev/zero":     {nil, "larger than 1 MiB"},
	} {
		f := name
		if c.body != nil {
			f = write(name, c.body)
		}
		errb.Reset()
		if code := run([]string{"revoke", "--cert", f}, &out, &errb); code != 1 ||
			!strings.Contains(errb.String(), c.want) {
			t.Errorf("%s: exit %d: %q", name, code, errb.String())
		}
		if bytes.Contains(errb.Bytes(), keyBlock.Bytes) {
			t.Errorf("%s: key material printed", name)
		}
	}
	// A hostile certificate's names reach the terminal quoted, never as
	// escape sequences.
	evil, err := ca.Issue(testpki.Leaf{CommonName: "a\x1b[31mred\a", Client: true, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	errb.Reset()
	if code := run([]string{"revoke", "--cert", write("evil.der", evil.Leaf.Raw)}, &out, &errb); code != 0 ||
		strings.ContainsAny(errb.String(), "\x1b\a") || !strings.Contains(errb.String(), `subject "CN=a\x1b[31mred\a"`) {
		t.Fatalf("exit %d: %q", code, errb.String())
	}
	if n := len(sent()); n != 2 {
		t.Fatalf("a refused file sent a revocation: %d sent", n)
	}

	// A usage error is exit 2 whatever the file holds, or if it is missing.
	for _, bad := range [][]string{
		{"revoke", "--list", "--cert", filepath.Join(dir, "missing.pem")},
		{"revoke", "--list", "--cert", write("key.pem", keyPEM)},
		{"revoke", "--list", "--cert-issuer", "CN=x"},
		{"revoke", "--principal", "user:a@b", "--cert", filepath.Join(dir, "missing.pem")},
	} {
		if code := run(bad, &out, &errb); code != 2 {
			t.Errorf("%v: exit %d", bad, code)
		}
	}
}

// A certificate whose hex serial is digits alone (0x10, as a CA issuing
// sequential serials gives) is revoked by --cert without the broker's hint
// that a decimal serial was copied by hand: that hint ends in a lift, and
// lifting a correct revocation at 3am re-admits a stolen certificate (final
// review I1). The broker is real, so the hint is the one port49d prints.
func TestRevokeCertWithADigitsOnlySerialIsNotTakenForDecimal(t *testing.T) {
	policyFile := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(policyFile, []byte(`
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: admin, permit: ["**"]}]
subjects: [{name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Load(policyFile, policy.Env{})
	if err != nil {
		t.Fatal(err)
	}
	st := memory.New(time.Now)
	log := decision.NewJSONLines(io.Discard)
	brk := &broker.Broker{Policy: policy.NewLive(pol),
		Minter: token.NewMinter(st, log, rand.Reader, token.TagKey([]byte("k")), time.Now, 8),
		Store:  st, Log: log, Metrics: metrics.New(prometheus.NewRegistry()), Now: time.Now,
		MaxSessionAge: time.Hour, BatchMax: 4, Sessions: session.New(st, time.Now, time.Hour, time.Hour)}
	newAdminStub(t, func(req agent.AdminRequest) (int, any) {
		var op api.RevokeRequest
		_ = json.Unmarshal(req.Body, &op)
		rep, err := brk.Revoke(context.Background(), broker.RevokeRequest{Issuer: op.CertIssuer, Serial: op.CertSerial, Origin: "test"})
		if err != nil {
			return 409, api.Error{Error: "admin_operation_failed", Detail: err.Error()}
		}
		return 200, api.RevokeResponse{By: "admin", Standing: true, Text: rep.Text()}
	})

	now := time.Now()
	ca, err := testpki.NewCA("Corp Issuing CA", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.Issue(testpki.Leaf{CommonName: "alice", Client: true, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(time.Hour), Serial: big.NewInt(0x10)})
	if err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(t.TempDir(), "alice.der")
	if err := os.WriteFile(certFile, leaf.Leaf.Raw, 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"revoke", "--cert", certFile}, &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "serial=10 (as the broker compares it)") {
		t.Fatalf("exit %d: %q %q", code, out.String(), errb.String())
	}
	if strings.Contains(out.String()+errb.String(), "read as hexadecimal") {
		t.Fatalf("a --cert revocation was flagged as a decimal serial:\n%s", out.String())
	}
	if _, err := st.GetRevocation(context.Background(), store.RevocationCert, store.CertKey(leaf.Leaf.Issuer.String(), "10")); err != nil {
		t.Fatalf("the certificate's mark: %v", err)
	}
}

// hexSerial sends a serial as explicit hex, the sign kept in front of the
// 0x, which the broker strips after it.
func TestHexSerial(t *testing.T) {
	for n, want := range map[int64]string{0x10: "0x10", 0x1a: "0x1a", -0x10: "-0x10", 0: "0x0"} {
		if got := hexSerial(big.NewInt(n)); got != want {
			t.Errorf("%d: %q, want %q", n, got, want)
		}
	}
}

// The exit status follows the broker's answer: no saved and no incomplete is a revocation that worked
// (a standalone broker keeps no revocations_file, so it says nothing of saving), saved:false and an
// incomplete are exit 3.
func TestRevokeExitFollowsSavedAndIncomplete(t *testing.T) {
	yes, no := true, false
	var answer api.RevokeResponse
	newAdminStub(t, func(agent.AdminRequest) (int, any) { return 200, answer })
	for _, c := range []struct {
		name string
		resp api.RevokeResponse
		want int
	}{
		{"no saved", api.RevokeResponse{By: "principal", Standing: true, Text: "revoked it"}, 0},
		{"saved", api.RevokeResponse{By: "principal", Standing: true, Saved: &yes, Text: "revoked it"}, 0},
		{"not saved", api.RevokeResponse{By: "principal", Standing: true, Saved: &no, Text: "revoked it"}, 3},
		{"incomplete", api.RevokeResponse{By: "principal", Standing: true, Incomplete: "a step", Text: "revoked it"}, 3},
	} {
		answer = c.resp
		var out, errb bytes.Buffer
		if code := run([]string{"revoke", "--principal", "user:carol@example.com", "--yes"}, &out, &errb); code != c.want {
			t.Errorf("%s: exit %d, want %d: %q %q", c.name, code, c.want, out.String(), errb.String())
		}
	}
}

// A revocation or lift the broker could not confirm may still land: the CLI prints the broker's words,
// exits non-zero, and never says "nothing was done". A plain unavailable store still means it did not run.
func TestRevokeUnconfirmedIsNeverNothingWasDone(t *testing.T) {
	var answer func() (int, any)
	newAdminStub(t, func(agent.AdminRequest) (int, any) { return answer() })
	const detail = "the revocation may not have been recorded: a copy already sent can still land when the directory " +
		"answers again, and then stands everywhere, even over a lift made meanwhile; after the heal check `port49 revoke --list`"
	for _, args := range [][]string{
		{"revoke", "--principal", "user:carol@example.com", "--yes"},
		{"revoke", "--lift", "--principal", "user:carol@example.com"},
	} {
		answer = func() (int, any) { return 503, api.Error{Error: "revocation_unconfirmed", Detail: detail} }
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code == 0 || !strings.Contains(errb.String(), "port49 revoke: the broker could not confirm it: "+detail) ||
			!strings.Contains(errb.String(), "port49 revoke --list") ||
			!strings.Contains(errb.String(), "even over a lift made meanwhile") ||
			strings.Contains(errb.String(), "nothing was done") {
			t.Errorf("%v: exit %d: %q", args, code, errb.String())
		}
	}
	answer = func() (int, any) {
		return 503, api.Error{Error: "store_unavailable", Detail: "the revocations could not be read"}
	}
	var out, errb bytes.Buffer
	if code := run([]string{"revoke", "--list"}, &out, &errb); code == 0 || strings.Contains(errb.String(), "nothing was done") {
		t.Errorf("an unavailable store: exit %d: %q", code, errb.String())
	}
}

// A revocation the broker never sent to the store did not happen anywhere but on that broker: the CLI
// prints the broker's words as they are, with no "unavailable just now" and no "run it again shortly",
// while a lift or a list that finds the store down is still the plain outage.
func TestRevokeNotRecordedIsNotAPassingOutage(t *testing.T) {
	const detail = "the revocation was not recorded in the store and will not land later, but this port49d denies what it " +
		"names until a lift on this port49d or its restart; this region's session store: 1 token keys deleted and 0 " +
		"contexts marked revoked; other regions have not learned of it: run `port49 revoke` now against a broker in a " +
		"region that reaches the directory, or here once the store answers; cut access another way: remove the " +
		"principal's grants from broker.policy_file (live within two watch intervals)"
	newAdminStub(t, func(agent.AdminRequest) (int, any) {
		return 503, api.Error{Error: "store_unavailable", Detail: detail}
	})
	var out, errb bytes.Buffer
	code := run([]string{"revoke", "--principal", "user:carol@example.com", "--yes"}, &out, &errb)
	if want := "port49 revoke: the broker did not record it: " + detail + "\n"; code == 0 || errb.String() != want {
		t.Errorf("exit %d:\n got %q\nwant %q", code, errb.String(), want)
	}
	errb.Reset()
	if code := run([]string{"revoke", "--lift", "--principal", "user:carol@example.com"}, &out, &errb); code == 0 ||
		!strings.Contains(errb.String(), "unavailable just now") || !strings.Contains(errb.String(), "run it again shortly") {
		t.Errorf("a lift: exit %d: %q", code, errb.String())
	}
}
