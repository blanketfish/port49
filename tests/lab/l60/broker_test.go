package l60

import (
	"context"
	"crypto/rand"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/pivattest"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/session"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/internal/token"
)

// The lab's devices. leafPlain asks for no second factor (the control);
// leafTouch, when the broker verifies touches, asks hardware_key_touch at
// every mint (reuse_for: 0m), so each mint is one touch.
const (
	leafPlain = "leaf1"
	leafTouch = "leaf_touch"
)

// labBroker is a real broker served in-process on the loopback, as port49d
// wires it: its server certificate from a throwaway CA under t.TempDir, its
// client anchor the lab client CA.
type labBroker struct {
	url      string
	serverCA string // the throwaway CA's PEM file: --broker-ca
	mu       sync.Mutex
	skew     time.Duration
}

// now is the broker's clock: the wall clock plus skew, which stepPastPacing
// moves on.
func (b *labBroker) now() time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()
	return time.Now().Add(b.skew)
}

// refreshPacing is a little over the broker's one refresh per connection per
// 10s (internal/broker refreshEvery).
const refreshPacing = 11 * time.Second

// stepPastPacing moves the broker's clock past its refresh pacing, as
// cmd/port49's lab broker does, so a refresh right after a login's own is
// not refused refresh_too_soon and no one waits.
func (b *labBroker) stepPastPacing() {
	b.mu.Lock()
	b.skew += refreshPacing
	b.mu.Unlock()
}

// labPolicy is the policy: alice on every device, and with touch a
// hardware_key_touch requirement, never reused, on the devices whose role is
// touch.
func labPolicy(touch bool) string {
	scopes := "  - {name: all_devices, match: {}}\n"
	if touch {
		scopes += "  - {name: touch_devices, match: {role: touch}, on_missing: include, security_log: true, " +
			"per_login_mfa: {accept: [hardware_key_touch], reuse_for: 0m}}\n"
	}
	return "scopes:\n" + scopes + `roles: [{name: r, privilege: admin, permit: ["**"]}]
subjects: [{name: s, identity: ["user:` + labEmail + `"], username: alice, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}]
`
}

// labDevices are the inventory the policy is loaded against.
func labDevices() []admission.Device {
	return []admission.Device{
		{Name: leafPlain, Platform: "arista_eos", Addresses: []netip.Addr{netip.MustParseAddr("172.100.100.11")},
			Attributes: map[string]string{"role": "plain"}},
		{Name: leafTouch, Platform: "arista_eos", Addresses: []netip.Addr{netip.MustParseAddr("172.100.100.12")},
			Attributes: map[string]string{"role": "touch"}},
	}
}

// startBroker serves the broker until the test ends. pivRoots, when given,
// are the attestation anchors (Yubico's PIV root on the key; a testpki PIV
// root in the unit test), and the touch devices ask for a touch. logTo
// receives the decision log (no token, no credential in it).
func startBroker(t *testing.T, clientCA *testpki.CA, pivRoots []byte, logTo io.Writer) *labBroker {
	t.Helper()
	now := time.Now()
	dir := t.TempDir()
	srvCA, err := testpki.NewCA("port49 L60 throwaway broker CA", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	srvCert, err := srvCA.Issue(testpki.Leaf{CommonName: "port49 L60 broker", IPs: testpki.Loopback(),
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	b := &labBroker{serverCA: filepath.Join(dir, "broker-ca.pem")}
	if err := os.WriteFile(b.serverCA, srvCA.PEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	policyFile := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyFile, []byte(labPolicy(pivRoots != nil)), 0o600); err != nil {
		t.Fatal(err)
	}
	devices := labDevices()
	pol, err := policy.Load(policyFile, policy.Env{Devices: devices})
	if err != nil {
		t.Fatal(err)
	}
	if logTo == nil {
		logTo = io.Discard
	}
	st := memory.New(b.now)
	log := decision.NewJSONLines(logTo)
	br := &broker.Broker{Policy: policy.NewLive(pol),
		Minter: token.NewMinter(st, log, rand.Reader, token.TagKey([]byte("l60")), b.now, 64),
		Store:  st, Log: log, Metrics: metrics.New(prometheus.NewRegistry()), Now: b.now,
		MaxSessionAge: 8 * time.Hour, BatchMax: 4, Sessions: session.New(st, b.now, time.Hour, time.Hour),
		ContextIdleTTL: time.Hour, CeilingWarning: 30 * time.Minute, GraceWindow: 5 * time.Minute}
	if pivRoots != nil {
		anchors, err := pivattest.ParseAnchors(pivRoots)
		if err != nil {
			t.Fatal(err)
		}
		br.PerLoginMFA = &broker.MFAVerifiers{Anchors: &anchors}
	}

	// One live context for alice on leaf1, so a refresh has a session to
	// extend.
	ctx := context.Background()
	res, err := pol.Resolve("user:"+labEmail, devices[0], now)
	if err != nil {
		t.Fatal(err)
	}
	body, hash, err := engine.Encode(res.Blob)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutBlob(ctx, hash, body, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := st.PutContext(ctx, store.ContextKey{NAS: leafPlain, Username: "alice"}, store.Context{CtxID: "ctx_leaf1",
		Principal: "user:" + labEmail, Username: "alice", PrivLvl: 1, BlobHash: hash, AuthTime: now,
		SessionExpires: now.Add(time.Hour), RefreshedAt: now, LastTouchedAt: now}, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := st.IndexContext(ctx, "user:"+labEmail, "", "", store.ContextRef{NAS: leafPlain, Username: "alice"},
		24*time.Hour); err != nil {
		t.Fatal(err)
	}

	srv, err := br.Server("127.0.0.1:0", srvCert, clientCA.Pool())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	bl := broker.NewListener(broker.Limit(raw, broker.MaxConns), srv.TLSConfig, broker.DefaultListenerLimits,
		br.Metrics, br.Now, nil)
	bl.Refused = br.RefusedAtBind
	go func() { _ = srv.Serve(bl) }()
	t.Cleanup(func() { _ = srv.Close() })
	b.url = "https://" + raw.Addr().String()
	return b
}

// startLabBroker is startBroker for a cell: the decision log goes to
// decisions-<cell>.jsonl in the lab directory.
func (h *lab) startLabBroker(ca *testpki.CA, pivRoots []byte) *labBroker {
	h.t.Helper()
	f, err := os.OpenFile(filepath.Join(h.dir, "decisions-"+h.cell+".jsonl"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { f.Close() })
	b := startBroker(h.t, ca, pivRoots, f)
	h.broker = b
	h.obs("broker", b.url+" (in-process; touch devices: "+map[bool]string{true: "yes", false: "no"}[pivRoots != nil]+")")
	return b
}
