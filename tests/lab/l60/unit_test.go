package l60

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/agent"
	"github.com/blanketfish/port49/internal/mfatouch"
	"github.com/blanketfish/port49/internal/testpki"
)

// The key-free parts of the harness. None opens a token or runs port49.

func TestUnitParsePINTries(t *testing.T) {
	for out, want := range map[string][2]int{
		"PIV version: 5.4.3\nPIN tries remaining: 3/3\nPUK tries remaining: 3/3\n": {3, 3},
		"PIN tries remaining: 2\n":                             {2, 0},
		"  PIN tries remaining: 1 / 3\n":                       {1, 3},
		"PUK tries remaining: 3/3\nPIN tries remaining: 0/3\n": {0, 3},
	} {
		left, total, ok := parsePINTries(out)
		if !ok || left != want[0] || total != want[1] {
			t.Errorf("%q: %d/%d %v, want %v", out, left, total, ok, want)
		}
	}
	if _, _, ok := parsePINTries("Serial number: 123\n"); ok {
		t.Error("no PIN line parsed as one")
	}
}

func TestUnitRedactMasksTheSerial(t *testing.T) {
	in := `PIN for YubiKey PIV #12345678: token "YubiKey PIV #12345678" serial 12345678; ` +
		`pkcs11:token=YubiKey%20PIV%20%2312345678;id=%01; ends 2026-10-14T10:00:00Z`
	got := redact(in)
	if strings.Contains(got, "12345678") || !strings.Contains(got, "2026-10-14T10:00:00Z") {
		t.Fatalf("%q", got)
	}
}

func TestUnitParseAgentLine(t *testing.T) {
	out := "port49: logged in to https://127.0.0.1:4433; the session ends at 2026-10-14T18:00:00Z " +
		"(agent pid 4242, log /tmp/l60s1/agent.log)\nrefreshed at x\n"
	pid, log, ok := parseAgentLine(out)
	if !ok || pid != 4242 || log != "/tmp/l60s1/agent.log" {
		t.Fatalf("%d %q %v", pid, log, ok)
	}
	if _, _, ok := parseAgentLine("port49: already logged in to x; refreshing\n"); ok {
		t.Fatal("a refresh of a running agent read as a start")
	}
}

// pinWords reads port49's own words (cmd/port49/hwlogin.go pinRefusedWords).
func TestUnitPINWords(t *testing.T) {
	for in, want := range map[string]string{
		"port49 login: the token refused the PIN\n":                                                                                         "neither",
		"port49 login: the token refused the PIN; fewer tries are left\n":                                                                   "count_low set",
		"port49 login: the token refused the PIN; one try is left before the key locks: unlock it with your token's own tool if it locks\n": "final_try set",
		"port49 login: logged in": "no PIN refusal",
		"port49 login: the key's PIN is blocked; unblock it with its PUK (ykman piv access unblock-pin) before trying again\n": "blocked",
	} {
		if got := pinWords(in); !strings.HasPrefix(got, want) {
			t.Errorf("%q: %q, want %q…", in, got, want)
		}
	}
}

func TestUnitSummarize(t *testing.T) {
	var d []time.Duration
	for i := 1; i <= 20; i++ {
		d = append(d, time.Duration(i)*time.Millisecond)
	}
	got := summarize(d)
	if got != "n=20 min=1ms median=11ms p95=19ms max=20ms total=210ms" {
		t.Fatalf("%q", got)
	}
}

func TestUnitOneLine(t *testing.T) {
	if got := oneLine("a\n\n  b \n"); got != "a | b" {
		t.Fatalf("%q", got)
	}
	if oneLine("") != "(empty)" {
		t.Fatal("empty")
	}
}

// The lab CA round-trips through its files, and a certificate it issues for
// a key verifies to it as a client certificate for the lab identity.
func TestUnitLabCAIssuesForAKey(t *testing.T) {
	dir := t.TempDir()
	ca, err := writeClientCA(dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	back, err := loadClientCA(dir)
	if err != nil || !back.Cert.Equal(ca.Cert) || !back.Key.Equal(ca.Key) {
		t.Fatalf("%v", err)
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, err := issueFor(back, k.Public(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode(p)
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Verify(x509.VerifyOptions{Roots: ca.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatal(err)
	}
	if !k.PublicKey.Equal(c.PublicKey) || len(c.EmailAddresses) != 1 || c.EmailAddresses[0] != labEmail {
		t.Fatalf("%v %v", c.PublicKey, c.EmailAddresses)
	}
	if fi, err := os.Stat(filepath.Join(dir, fileCAKey)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("CA key mode %v %v", fi.Mode(), err)
	}
}

// The lab broker, with a file key and a test attestation root standing in
// for Yubico's: the agent connects, leaf1 mints with no second factor,
// leaf_touch asks for hardware_key_touch, and a refresh signs.
func TestUnitLabBrokerServesAFileKey(t *testing.T) {
	ca, err := writeClientCA(t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	piv, err := testpki.NewPIV(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b := startBroker(t, ca, piv.Anchors(), nil)
	certFile, keyFile := fileClient(t, ca)
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	srvCA, err := os.ReadFile(b.serverCA)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(srvCA)
	a := agent.New(agent.Config{BrokerURL: b.url, BrokerCA: pool, Cert: cert})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := a.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	item, err := a.Mint(ctx, leafPlain, false, 0, "")
	if err != nil || item.Verdict != "permit" || item.Login == "" {
		t.Fatalf("leaf1: verdict %q reason %q err %v", item.Verdict, item.Reason, err)
	}
	_, err = a.Mint(ctx, leafTouch, false, 0, "")
	var need *agent.MFARequiredError
	if !errors.As(err, &need) || len(need.Requirement.Accept) != 1 || need.Requirement.Accept[0] != "hardware_key_touch" ||
		need.Requirement.ReuseForSeconds != 0 {
		t.Fatalf("leaf_touch: %v", err)
	}
	out, err := a.Refresh(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Sessions) != 1 || out.Sessions[0].Device != leafPlain || out.Sessions[0].Outcome != "extended" {
		t.Fatalf("refresh: %+v", out.Sessions)
	}
}

// The c_order cell's chain check on a test attestation hierarchy: the
// session slot holds its lab certificate beside its attestation, and
// mfatouch.Chain picks the attestation, the same chain in the listed order
// and reversed; chainWords names each link.
func TestUnitCOrderChainWords(t *testing.T) {
	now := time.Now()
	piv, err := testpki.NewPIV(now)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := writeClientCA(t.TempDir(), now)
	if err != nil {
		t.Fatal(err)
	}
	session, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	touch, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sessionAtt, err := piv.Slot(session.Public(), 1)
	if err != nil {
		t.Fatal(err)
	}
	touchAtt, err := piv.Slot(touch.Public(), 2)
	if err != nil {
		t.Fatal(err)
	}
	labPEM, err := issueFor(ca, session.Public(), now)
	if err != nil {
		t.Fatal(err)
	}
	lab, err := parsePEMCert(labPEM)
	if err != nil {
		t.Fatal(err)
	}
	list := []*x509.Certificate{lab, sessionAtt, piv.Device, touchAtt}
	rev := slices.Clone(list)
	slices.Reverse(rev)
	fwd, err := mfatouch.Chain(list, touch.Public(), session.Public())
	if err != nil {
		t.Fatal(err)
	}
	back, err := mfatouch.Chain(rev, touch.Public(), session.Public())
	if err != nil || !slices.Equal(fwd, back) {
		t.Fatalf("reversed: %v, same %v", err, slices.Equal(fwd, back))
	}
	describe := func(c *x509.Certificate) string {
		if c.Equal(lab) {
			return "LAB"
		}
		if c.Equal(sessionAtt) {
			return "SESSION_ATT"
		}
		return c.Subject.CommonName
	}
	got := chainWords(fwd, nil, describe)
	if !strings.HasSuffix(got, "session SESSION_ATT") || strings.Contains(got, "LAB") {
		t.Fatalf("%q", got)
	}
	if got := chainWords(nil, mfatouch.ErrNoAttestation, describe); !strings.HasPrefix(got, "error: ") {
		t.Fatalf("%q", got)
	}
}

// Without attestation roots the touch device asks for nothing.
func TestUnitLabBrokerWithoutTouch(t *testing.T) {
	ca, err := writeClientCA(t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b := startBroker(t, ca, nil, nil)
	certFile, keyFile := fileClient(t, ca)
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	srvCA, _ := os.ReadFile(b.serverCA)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(srvCA)
	a := agent.New(agent.Config{BrokerURL: b.url, BrokerCA: pool, Cert: cert})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := a.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	if item, err := a.Mint(ctx, leafTouch, false, 0, ""); err != nil || item.Verdict != "permit" {
		t.Fatalf("%+v %v", item.Verdict, err)
	}
}
