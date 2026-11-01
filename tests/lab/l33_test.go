//go:build lab

package lab

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/inventory"
)

// l33Record is one stack's L33 run.
type l33Record struct {
	Stack        string     `json:"stack"`
	At           time.Time  `json:"at"`
	Built        string     `json:"built"`
	WebhookCalls []string   `json:"webhook_calls"`
	Phases       []l33Phase `json:"phases"`
	// Refused is the run of two more webhooks on one change: one under the
	// wrong secret, its bad_signature deliveries counted in the 120s after
	// the change, so 1 is "not sent again"; and one to a stand-in listener
	// that answers every delivery 503, a stand-in for a service going away
	// (port49-inventory itself never answers a delivery 503: final review
	// M1), its deliveries counted and timed in the same 120s.
	RefusedChange string    `json:"refused_change"`
	BadSignature  int       `json:"bad_signature"`
	Unavailable   int       `json:"unavailable"`
	UnavailableAt []float64 `json:"unavailable_at"` // seconds from the API write
	Stale         int       `json:"stale"`
}

// l33Phase is one change in the source of truth and what followed it.
type l33Phase struct {
	Change    string  `json:"change"`
	Accepted  int     `json:"accepted"`
	Published bool    `json:"published"`
	Seconds   float64 `json:"seconds"` // the API write to the service's "sync (webhook): published" line
}

// l33Policy is the service's policy for L33: every device the stack's map
// puts at site dc1 is admitted, so a sync is never refused as admitting
// none.
const l33Policy = `scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: admin, permit: ["**"]}]
subjects: [{name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}]
key_groups: [{match: {attributes: {site: dc1}}, key_ref: lab_key}]
keys: {lab_key: {current: {version: 1, secret_ref: env:PORT49_KEY_LAB}}}
`

// l33Secret is a random webhook secret for one run: 48 of [A-Za-z0-9].
func l33Secret(t *testing.T) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 48)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			t.Fatal(err)
		}
		b[i] = alphabet[n.Int64()]
	}
	return string(b)
}

// l33SyncYAML is the sync: block and webhook keys for a stack as source
// l33, through the host proxy, read on a 24h interval so every publication
// after the first is a webhook's.
func l33SyncYAML(stack, product string) string {
	pki := os.Getenv("L33_PKI")
	var m []string
	for k, v := range l32Map(stack) {
		m = append(m, k+": "+v)
	}
	return fmt.Sprintf(`webhook_listen: %s
webhook_tls_cert_file: %s/webhook.pem
webhook_tls_key_file: %s/webhook-key.pem
sync:
  - name: l33
    type: %s
    url: %s
    ca_file: %s/ca.pem
    token_secret_ref: env:L27_TOKEN
    webhook_secret_ref: env:L33_WEBHOOK_SECRET
    interval: 24h
    map: {%s}
`, os.Getenv("L33_HOOK_BIND"), pki, pki, product, os.Getenv("L32_HOST_URL"), pki, strings.Join(m, ", "))
}

// l33UnavailablePort is the stand-in 503 listener's port, beside
// L33_HOOK_BIND's on the same address.
const l33UnavailablePort = "18445"

// l33Unavailable listens on host:l33UnavailablePort over TLS under the
// webhook certificate and answers every request 503 shutting_down, a
// stand-in for a service going away; port49-inventory's webhook listener
// never answers so (final review M1). arrivals is when
// each request came; nothing of a request is kept.
func l33Unavailable(t *testing.T, host string) (arrivals func() []time.Time) {
	t.Helper()
	pki := os.Getenv("L33_PKI")
	cert, err := tls.LoadX509KeyPair(filepath.Join(pki, "webhook.pem"), filepath.Join(pki, "webhook-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(host, l33UnavailablePort))
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var at []time.Time
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			at = append(at, time.Now())
			mu.Unlock()
			io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			io.WriteString(w, `{"error":"shutting_down"}`+"\n")
		})}
	go srv.ServeTLS(ln, "", "")
	t.Cleanup(func() { srv.Close() })
	return func() []time.Time {
		mu.Lock()
		defer mu.Unlock()
		return append([]time.Time(nil), at...)
	}
}

// l33Counts is port49_inventory_webhooks_total{source="l33"} by outcome.
func l33Counts(t *testing.T) map[string]int {
	t.Helper()
	resp, err := http.Get("http://" + inventoryMetricsAddr + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]int{}
	re := regexp.MustCompile(`port49_inventory_webhooks_total\{outcome="([a-z_]+)",source="l33"\} (\d+)`)
	for _, m := range re.FindAllStringSubmatch(string(raw), -1) {
		n, _ := strconv.Atoi(m[2])
		out[m[1]] = n
	}
	return out
}

// TestL33Webhooks runs one stack (run.sh <stack> l33) into port49-inventory
// with webhooks on, and writes tests/lab/sot/l33/<stack>/webhooks.json.
func TestL33Webhooks(t *testing.T) {
	stack := os.Getenv("L32_STACK")
	if stack == "" || os.Getenv("L33_HOOK_BIND") == "" {
		t.Skip("run by tests/lab/sot/run.sh <stack> l33")
	}
	// The harness sets root only when it brings a platform up; this test
	// brings none, and TestMain's evidence step acts on root, so it is put
	// back.
	if root == "" {
		r, err := repoRoot()
		if err != nil {
			t.Fatal(err)
		}
		root = r
		t.Cleanup(func() { root = "" })
	}
	a := newSoTAdmin(t)
	rec := l33Record{Stack: stack, At: time.Now().UTC(), Built: l29Built()}
	policy := filepath.Join(privateDir(t, "l33-"+stack), "policy.yaml")
	writeAtomic(t, policy, []byte(l33Policy), 0o600)
	secret := l33Secret(t)
	li := newLabInventory(t, "l33-"+stack)
	startInventoryWith(t, li, policy, l33SyncYAML(stack, a.product), []string{"L33_WEBHOOK_SECRET=" + secret})
	if err := a.removeWebhooks("l27"); err != nil {
		t.Fatal(err)
	}
	host, port, _ := net.SplitHostPort(os.Getenv("L33_HOOK_BIND"))
	payload := "https://port49-inventory.lab:" + port + "/v1/webhook/l33"
	arrivals := l33Unavailable(t, host)
	calls, err := a.webhook("port49-l33", payload, secret, "/etc/port49-lab/ca.pem")
	rec.WebhookCalls = calls
	if err != nil {
		t.Fatalf("creating the webhook: %v", err)
	}
	var created any
	for _, ch := range []struct {
		name string
		do   func() error
	}{
		{"update leaf-01's os_version", func() error {
			leaf, err := a.first("/api/dcim/devices/?name=leaf-01")
			if err != nil {
				return err
			}
			return a.patchDevice(leaf["id"], map[string]any{"custom_fields": map[string]any{"os_version": "4.33.0F"}})
		}},
		{"create leaf-200", func() (err error) { created, err = a.createDevice("leaf-200"); return err }},
		{"delete leaf-200", func() error { return a.deleteDevice(created) }},
	} {
		before, mark := l33Counts(t)[inventory.HookAccepted], li.mark()
		t0 := time.Now()
		if err := ch.do(); err != nil {
			t.Fatalf("%s: %v", ch.name, err)
		}
		at, ok := li.waitLine(t, mark, "sync (webhook): published bundle", 2*time.Minute)
		ph := l33Phase{Change: ch.name, Published: ok, Accepted: l33Counts(t)[inventory.HookAccepted] - before}
		if ok {
			ph.Seconds = at.Sub(t0).Seconds()
			if ph.Accepted < 1 {
				// The interval is 24h, so only a webhook publishes; a
				// publication with no accepted delivery is not one.
				t.Errorf("%s: published with no accepted delivery counted", ch.name)
			}
		} else {
			t.Errorf("%s: no publication through the webhook in 2m", ch.name)
		}
		rec.Phases = append(rec.Phases, ph)
		// Past the debouncer's 30s gap, so the next change's time is its own.
		time.Sleep(35 * time.Second)
	}
	// A webhook with the wrong secret, refused 401, and one answered 503,
	// on one change, counted for 120s to see whether the release sends
	// either again.
	if err := a.removeWebhooks("port49-l33"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.webhook("port49-l33-wrong", payload, l33Secret(t), "/etc/port49-lab/ca.pem"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.webhook("port49-l33-503", "https://port49-inventory.lab:"+l33UnavailablePort+"/v1/webhook/l33",
		l33Secret(t), "/etc/port49-lab/ca.pem"); err != nil {
		t.Fatal(err)
	}
	before := l33Counts(t)[inventory.HookBadSignature]
	rec.RefusedChange = "update leaf-01's os_version, under the wrong secret and to a listener answering 503"
	leaf, err := a.first("/api/dcim/devices/?name=leaf-01")
	t0 := time.Now()
	if err == nil {
		err = a.patchDevice(leaf["id"], map[string]any{"custom_fields": map[string]any{"os_version": "4.33.1F"}})
	}
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(120 * time.Second)
	counts := l33Counts(t)
	rec.BadSignature, rec.Stale = counts[inventory.HookBadSignature]-before, counts[inventory.HookStale]
	for _, at := range arrivals() {
		if at.After(t0) {
			rec.Unavailable++
			rec.UnavailableAt = append(rec.UnavailableAt, math.Round(at.Sub(t0).Seconds()*100)/100)
		}
	}
	if rec.BadSignature < 1 {
		t.Errorf("no bad_signature delivery arrived in 120s")
	}
	if rec.Unavailable < 1 {
		t.Errorf("no delivery reached the 503 listener in 120s")
	}
	a.removeWebhooks("port49-l33-wrong")
	a.removeWebhooks("port49-l33-503")
	logged, _ := os.ReadFile(li.errPath)
	if strings.Contains(string(logged), secret) {
		t.Fatal("the service's log holds the webhook secret")
	}
	// Final review M6: nor the API token the service reads the source with.
	if tok := os.Getenv("L27_TOKEN"); tok == "" || strings.Contains(string(logged), tok) {
		t.Fatal("the service's log holds the API token, or L27_TOKEN is unset")
	}
	dir := filepath.Join(root, "tests", "lab", "sot", "l33", stack)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.MarshalIndent(rec, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "webhooks.json"), append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
