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

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/session"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/internal/token"
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
