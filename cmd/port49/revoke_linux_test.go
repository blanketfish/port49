//go:build linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/daemon/admin"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/keyring"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/session"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/internal/token"
)

// port49 revoke sends one op to the admin socket and prints its answer;
// --cert reads the issuer and serial the broker compares from the file.
func TestRevokeAsksTheAdminSocket(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "port49d.sock")
	ln, err := admin.Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// got is written by the admin server's goroutine and read here; the
	// socket gives the race detector no happens-before edge (M4).
	var mu sync.Mutex
	var got []admin.RevokeOp
	last := func() admin.RevokeOp {
		mu.Lock()
		defer mu.Unlock()
		return got[len(got)-1]
	}
	partial := false
	srv := &admin.Server{Held: &keyring.Held{}, Now: time.Now,
		Revoke: func(_ context.Context, op admin.RevokeOp) (string, bool, error) {
			mu.Lock()
			defer mu.Unlock()
			got = append(got, op)
			return "revoked it", partial, nil
		},
		Revocations: func(context.Context) (string, error) { return "no revocation is in force", nil }}
	go srv.Serve(ctx, ln)

	var out, errb bytes.Buffer
	if code := run([]string{"revoke", "--socket", socket, "--principal", "user:alice@example.com"}, &out, &errb); code != 0 ||
		strings.TrimSpace(out.String()) != "revoked it" {
		t.Fatalf("exit %d: %q %q", code, out.String(), errb.String())
	}

	now := time.Now()
	ca, err := testpki.NewCA("Corp Issuing CA", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.Issue(testpki.Leaf{CommonName: "alice", Emails: []string{"alice@example.com"}, Client: true,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(t.TempDir(), "alice.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Leaf.Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := run([]string{"revoke", "--socket", socket, "--cert", certFile, "--lift"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %q", code, errb.String())
	}
	if op := last(); op.Issuer != leaf.Leaf.Issuer.String() || op.Serial != "0x"+leaf.Leaf.SerialNumber.Text(16) || !op.Lift {
		t.Fatalf("%+v", op)
	}

	out.Reset()
	if code := run([]string{"revoke", "--socket", socket, "--list"}, &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "no revocation is in force") {
		t.Fatalf("exit %d: %q", code, out.String())
	}
	mu.Lock()
	partial = true
	mu.Unlock()
	out.Reset()
	if code := run([]string{"revoke", "--socket", socket, "--principal", "user:alice@example.com"}, &out, &errb); code != 3 ||
		strings.TrimSpace(out.String()) != "revoked it" {
		t.Fatalf("a partial revocation must exit 3 and print the report, got %d: %q", code, out.String())
	}
	for _, bad := range [][]string{
		{"revoke", "--socket", socket},
		{"revoke", "--socket", socket, "--principal", "user:a@b", "--cert-serial", "1", "--cert-issuer", "CN=x"},
		{"revoke", "--socket", socket, "--cert", certFile, "--cert-serial", "1"},
		{"revoke", "--socket", socket, "--list", "--principal", "user:a@b"},
		{"revoke", "--socket", socket, "--cert-serial", "1"},
	} {
		if code := run(bad, &out, &errb); code != 2 {
			t.Errorf("%v: exit %d", bad, code)
		}
	}
	errb.Reset()
	if code := run([]string{"revoke", "--socket", socket + ".missing", "--principal", "user:a@b"}, &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "is admin_socket set") {
		t.Fatalf("exit %d: %q", code, errb.String())
	}

	// A file holding a private key is refused before anything is sent, and
	// no byte of the key is printed: a certificate is public, its key is not.
	certPEM, keyPEM, err := testpki.PEMs(leaf)
	if err != nil {
		t.Fatal(err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	for name, body := range map[string][]byte{
		"cert-then-key.pem": append(append([]byte{}, certPEM...), keyPEM...),
		"key-then-cert.pem": append(append([]byte{}, keyPEM...), certPEM...),
		"key-only.pem":      keyPEM,
	} {
		f := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(f, body, 0o600); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		sent := len(got)
		mu.Unlock()
		out.Reset()
		errb.Reset()
		if code := run([]string{"revoke", "--socket", socket, "--cert", f}, &out, &errb); code != 1 ||
			!strings.Contains(errb.String(), "private key") {
			t.Errorf("%s: exit %d: %q", name, code, errb.String())
		}
		mu.Lock()
		if len(got) != sent {
			t.Errorf("%s: a revocation was sent", name)
		}
		mu.Unlock()
		for _, s := range []string{out.String(), errb.String()} {
			if strings.Contains(s, "BEGIN") || bytes.Contains([]byte(s), keyBlock.Bytes) {
				t.Errorf("%s: key material printed: %q", name, s)
			}
		}
	}
}

// The client keeps its write side open until it has the answer: port49d
// reads a half-close as a hang-up and would end the op's ctx under it.
func TestRevokeDoesNotHangUpWhileTheOpRuns(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "port49d.sock")
	ln, err := admin.Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := &admin.Server{Held: &keyring.Held{}, Now: time.Now,
		Revoke: func(ctx context.Context, _ admin.RevokeOp) (string, bool, error) {
			select {
			case <-ctx.Done():
				return "", false, ctx.Err()
			case <-time.After(300 * time.Millisecond):
				return "revoked it", false, nil
			}
		},
		Revocations: func(context.Context) (string, error) { return "", nil }}
	go srv.Serve(ctx, ln)

	var out, errb bytes.Buffer
	if code := run([]string{"revoke", "--socket", socket, "--principal", "user:alice@example.com"}, &out, &errb); code != 0 ||
		strings.TrimSpace(out.String()) != "revoked it" {
		t.Fatalf("exit %d: %q %q", code, out.String(), errb.String())
	}
}

// A revocation whose answer never comes may still be in force: port49d
// marks first. The operator is told to look before retrying; a list that
// goes unanswered changed nothing and says only what failed.
func TestRevokeUnansweredMayBeInForce(t *testing.T) {
	if revokeWait <= admin.RevokeWait || listWait <= admin.ListWait {
		t.Fatalf("the client must outwait port49d: %v/%v, %v/%v", revokeWait, admin.RevokeWait, listWait, admin.ListWait)
	}
	socket := filepath.Join(t.TempDir(), "port49d.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	// port49d restarting mid-op: the request is read, the conn closed.
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = bufio.NewReader(c).ReadString('\n')
			c.Close()
		}
	}()
	var out, errb bytes.Buffer
	if code := run([]string{"revoke", "--socket", socket, "--principal", "user:alice@example.com"}, &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "port49d did not answer (EOF); the revocation may be in force") ||
		!strings.Contains(errb.String(), "port49 revoke --list") {
		t.Fatalf("exit %d: %q", code, errb.String())
	}
	errb.Reset()
	if code := run([]string{"revoke", "--socket", socket, "--principal", "user:alice@example.com", "--lift"}, &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "the lift may be in force") {
		t.Fatalf("exit %d: %q", code, errb.String())
	}
	errb.Reset()
	if code := run([]string{"revoke", "--socket", socket, "--list"}, &out, &errb); code != 1 ||
		strings.TrimSpace(errb.String()) != "port49 revoke: EOF" {
		t.Fatalf("exit %d: %q", code, errb.String())
	}
}

// --cert takes one certificate, PEM or DER, and names its subject before
// anything is sent; a chain, an oversized file, or flags that conflict are
// refused before the dial.
func TestRevokeCertFileForms(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "port49d.sock")
	ln, err := admin.Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	var got []admin.RevokeOp
	sent := func() []admin.RevokeOp {
		mu.Lock()
		defer mu.Unlock()
		return append([]admin.RevokeOp(nil), got...)
	}
	srv := &admin.Server{Held: &keyring.Held{}, Now: time.Now,
		Revoke: func(_ context.Context, op admin.RevokeOp) (string, bool, error) {
			mu.Lock()
			defer mu.Unlock()
			got = append(got, op)
			return "revoked it", false, nil
		},
		Revocations: func(context.Context) (string, error) { return "", nil }}
	go srv.Serve(ctx, ln)

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
	if code := run([]string{"revoke", "--socket", socket, "--cert", der}, &out, &errb); code != 0 ||
		!strings.Contains(errb.String(), `subject "CN=alice", issuer "CN=Corp Issuing CA", serial 0x`+leaf.Leaf.SerialNumber.Text(16)) {
		t.Fatalf("exit %d: %q", code, errb.String())
	}
	if ops := sent(); len(ops) != 1 || ops[0].Issuer != leaf.Leaf.Issuer.String() || ops[0].Serial != "0x"+leaf.Leaf.SerialNumber.Text(16) {
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
		if code := run([]string{"revoke", "--socket", socket, "--cert", f}, &out, &errb); code != 1 ||
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
	if code := run([]string{"revoke", "--socket", socket, "--cert", write("evil.der", evil.Leaf.Raw)}, &out, &errb); code != 0 ||
		strings.ContainsAny(errb.String(), "\x1b\a") || !strings.Contains(errb.String(), `subject "CN=a\x1b[31mred\a"`) {
		t.Fatalf("exit %d: %q", code, errb.String())
	}
	if n := len(sent()); n != 2 {
		t.Fatalf("a refused file sent a revocation: %d sent", n)
	}

	// A usage error is exit 2 whatever the file holds, or if it is missing.
	for _, bad := range [][]string{
		{"revoke", "--socket", socket, "--list", "--cert", filepath.Join(dir, "missing.pem")},
		{"revoke", "--socket", socket, "--list", "--cert", write("key.pem", keyPEM)},
		{"revoke", "--socket", socket, "--list", "--cert-issuer", "CN=x"},
		{"revoke", "--socket", socket, "--principal", "user:a@b", "--cert", filepath.Join(dir, "missing.pem")},
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
	socket := filepath.Join(t.TempDir(), "port49d.sock")
	ln, err := admin.Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := &admin.Server{Held: &keyring.Held{}, Now: time.Now,
		Revoke: func(ctx context.Context, op admin.RevokeOp) (string, bool, error) {
			rep, err := brk.Revoke(ctx, broker.RevokeRequest{Issuer: op.Issuer, Serial: op.Serial, Origin: "test"})
			return rep.Text(), rep.Partial(), err
		},
		Revocations: func(context.Context) (string, error) { return "", nil }}
	go srv.Serve(ctx, ln)

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
	if code := run([]string{"revoke", "--socket", socket, "--cert", certFile}, &out, &errb); code != 0 ||
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
