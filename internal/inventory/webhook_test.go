package inventory

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/sot"
)

const hookSecret = "l33-unit-test-webhook-secret-0123456789"

type hookRig struct {
	h        *Webhooks
	now      time.Time
	notified []string
	out      *bytes.Buffer
}

func newHookRig(now time.Time) *hookRig {
	rig := &hookRig{now: now, out: &bytes.Buffer{}}
	rig.h = &Webhooks{Secrets: map[string]sot.Secret{"netbox_prod": sot.NewSecret(hookSecret)},
		Notify: func(s string) { rig.notified = append(rig.notified, s) }, Now: func() time.Time { return rig.now },
		Log: rig.out, Metrics: NewMetrics(prometheus.NewRegistry())}
	return rig
}

func sign(body []byte, secret string) string {
	mac := hmac.New(sha512.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func (rig *hookRig) deliver(path string, body []byte, sig, ctype string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.RemoteAddr = "10.0.0.9:51000"
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if sig != "" {
		req.Header.Set("X-Hook-Signature", sig)
	}
	w := httptest.NewRecorder()
	rig.h.Handler().ServeHTTP(w, req)
	return w
}

func (rig *hookRig) count(source, outcome string) float64 {
	return testutil.ToFloat64(rig.h.Metrics.Webhooks.WithLabelValues(source, outcome))
}

func body(ts string) []byte {
	return []byte(`{"event": "updated", "timestamp": "` + ts + `", "object_type": "dcim.device", "data": {"name": "leaf-01"}}`)
}

// L27, L30: every delivery recorded, re-signed with this test's secret and
// read at the instant it arrived, is taken — both timestamp spellings,
// NetBox's (T) and Nautobot's (space).
func TestTheRecordedDeliveriesAuthenticate(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("..", "..", "tests", "lab", "sot", "*", "*", "webhooks.json"))
	if len(files) < 6 {
		t.Fatalf("found %d recorded webhooks.json", len(files))
	}
	n := 0
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var rec struct {
			Deliveries []struct {
				At   time.Time       `json:"at"`
				Body json.RawMessage `json:"body"`
			} `json:"deliveries"`
		}
		if err := json.Unmarshal(raw, &rec); err != nil {
			t.Fatal(err)
		}
		for _, d := range rec.Deliveries {
			rig := newHookRig(d.At)
			if w := rig.deliver("/v1/webhook/netbox_prod", d.Body, sign(d.Body, hookSecret), "application/json"); w.Code !=
				http.StatusAccepted || len(rig.notified) != 1 {
				t.Fatalf("%s: %d %s", f, w.Code, w.Body)
			}
			n++
		}
	}
	if n < 15 {
		t.Fatalf("only %d deliveries read", n)
	}
}

// Decision 31: an unsigned or mis-signed delivery triggers nothing, is said
// once per source and outcome, and the log never holds the secret, the
// signature or the body.
func TestAnUnsignedOrMisSignedDeliveryTriggersNothing(t *testing.T) {
	now := time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC)
	rig := newHookRig(now)
	b := body("2026-10-01T02:00:00.000000+00:00")
	bad := sign(b, "a-different-secret-of-thirty-two-chars")
	for i := 0; i < 3; i++ {
		if w := rig.deliver("/v1/webhook/netbox_prod", b, "", "application/json"); w.Code != http.StatusUnauthorized {
			t.Fatalf("unsigned: %d", w.Code)
		}
		if w := rig.deliver("/v1/webhook/netbox_prod", b, bad, "application/json"); w.Code != http.StatusUnauthorized {
			t.Fatalf("mis-signed: %d", w.Code)
		}
		if w := rig.deliver("/v1/webhook/netbox_prod", b, "zz", "application/json"); w.Code != http.StatusUnauthorized {
			t.Fatalf("not hex: %d", w.Code)
		}
	}
	if len(rig.notified) != 0 || rig.count("netbox_prod", HookUnsigned) != 3 || rig.count("netbox_prod", HookBadSignature) != 6 {
		t.Fatalf("%v %v %v", rig.notified, rig.count("netbox_prod", HookUnsigned), rig.count("netbox_prod", HookBadSignature))
	}
	log := rig.out.String()
	if strings.Count(log, "(bad_signature)") != 1 || strings.Count(log, "(unsigned)") != 1 ||
		!strings.Contains(log, "port49-inventory: webhook: refused a delivery for source netbox_prod from 10.0.0.9 "+
			"(bad_signature): the webhook's secret in the source must be the value webhook_secret_env names") {
		t.Fatalf("%s", log)
	}
	for _, leak := range []string{hookSecret, bad, "leaf-01", "updated"} {
		if strings.Contains(log, leak) {
			t.Fatalf("the log holds %q: %s", leak, log)
		}
	}
}

func TestAStaleDeliveryTriggersNothing(t *testing.T) {
	b := body("2026-10-01 02:00:00.000000+00:00")
	for _, now := range []time.Time{time.Date(2026, 10, 1, 2, 5, 1, 0, time.UTC), time.Date(2026, 10, 1, 1, 54, 59, 0, time.UTC)} {
		rig := newHookRig(now)
		if w := rig.deliver("/v1/webhook/netbox_prod", b, sign(b, hookSecret), "application/json"); w.Code !=
			http.StatusBadRequest || len(rig.notified) != 0 || rig.count("netbox_prod", HookStale) != 1 {
			t.Fatalf("%s: %d", now, w.Code)
		}
	}
	rig := newHookRig(time.Date(2026, 10, 1, 2, 4, 59, 0, time.UTC))
	if w := rig.deliver("/v1/webhook/netbox_prod", b, sign(b, hookSecret), "application/json"); w.Code != http.StatusAccepted {
		t.Fatalf("inside the window: %d", w.Code)
	}
}

// A delivery taken once is not taken again inside the window: a replay, or
// a product's retry of one it did not see answered, triggers once.
func TestARepeatedDeliveryTriggersOnce(t *testing.T) {
	rig := newHookRig(time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC))
	b := body("2026-10-01T02:00:00.000000+00:00")
	for i := 0; i < 3; i++ {
		if w := rig.deliver("/v1/webhook/netbox_prod", b, sign(b, hookSecret), "application/json"); w.Code != http.StatusAccepted {
			t.Fatalf("%d", w.Code)
		}
	}
	if len(rig.notified) != 1 || rig.count("netbox_prod", HookDuplicate) != 2 || rig.count("netbox_prod", HookAccepted) != 1 {
		t.Fatalf("%v", rig.notified)
	}
}

func TestWhatIsNotADeliveryIsRefusedUnread(t *testing.T) {
	rig := newHookRig(time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC))
	b := body("2026-10-01T02:00:00.000000+00:00")
	big := append([]byte(`{"timestamp": "2026-10-01T02:00:00+00:00", "x": "`), bytes.Repeat([]byte("a"), maxWebhookBody)...)
	big = append(big, `"}`...)
	for name, c := range map[string]struct {
		path  string
		body  []byte
		sig   string
		ctype string
		code  int
		label string
	}{
		"too large":      {"/v1/webhook/netbox_prod", big, sign(big, hookSecret), "application/json", 413, HookTooLarge},
		"not json":       {"/v1/webhook/netbox_prod", b, sign(b, hookSecret), "text/plain", 415, HookBadContentType},
		"no timestamp":   {"/v1/webhook/netbox_prod", []byte(`{"event": "x"}`), sign([]byte(`{"event": "x"}`), hookSecret), "application/json", 400, HookBadBody},
		"unknown source": {"/v1/webhook/evil%1Bsource", b, sign(b, hookSecret), "application/json", 401, HookUnknownSource},
		"not a webhook":  {"/v1/bundle", b, sign(b, hookSecret), "application/json", 404, HookBadPath},
		"unclean path":   {"/v1/webhook/../webhook/netbox_prod", b, sign(b, hookSecret), "application/json", 404, HookBadPath},
	} {
		if w := rig.deliver(c.path, c.body, c.sig, c.ctype); w.Code != c.code {
			t.Errorf("%s: %d", name, w.Code)
		}
		src := "netbox_prod"
		if c.label == HookUnknownSource || c.label == HookBadPath {
			src = "" // the caller's text is never a label value
		}
		if rig.count(src, c.label) < 1 {
			t.Errorf("%s: not counted as %s", name, c.label)
		}
	}
	if len(rig.notified) != 0 {
		t.Fatalf("%v", rig.notified)
	}
	if strings.Contains(rig.out.String(), "evil") {
		t.Fatalf("echoed the path: %s", rig.out)
	}
}

// The first delivery a source authenticates is said, and so is the first
// after a refusal was said.
func TestAuthenticationIsSaidOnceAndAgainAfterARefusal(t *testing.T) {
	rig := newHookRig(time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC))
	for i, ts := range []string{"2026-10-01T02:00:00.1+00:00", "2026-10-01T02:00:00.2+00:00"} {
		b := body(ts)
		rig.deliver("/v1/webhook/netbox_prod", b, sign(b, hookSecret), "application/json")
		if n := strings.Count(rig.out.String(), "deliveries authenticate"); n != 1 {
			t.Fatalf("delivery %d: said %d times", i, n)
		}
	}
	b := body("2026-10-01T02:00:00.3+00:00")
	rig.deliver("/v1/webhook/netbox_prod", b, "", "application/json")
	b = body("2026-10-01T02:00:00.4+00:00")
	rig.deliver("/v1/webhook/netbox_prod", b, sign(b, hookSecret), "application/json")
	if !strings.Contains(rig.out.String(), "port49-inventory: webhook: source netbox_prod's deliveries authenticate "+
		"again (from 10.0.0.9)") {
		t.Fatalf("%s", rig.out)
	}
}

// Pre-flight M9: every 401 has one body, so a wrong name and a right one
// read alike.
func TestEvery401ReadsAlike(t *testing.T) {
	rig := newHookRig(time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC))
	b := body("2026-10-01T02:00:00.000000+00:00")
	for _, path := range []string{"/v1/webhook/netbox_prod", "/v1/webhook/not_a_source"} {
		w := rig.deliver(path, b, sign(b, "a-different-secret-of-thirty-two-chars"), "application/json")
		if w.Code != http.StatusUnauthorized || strings.TrimSpace(w.Body.String()) != `{"error":"unauthorized"}` {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
	}
}

// Pre-flight M11: a full cache still remembers the newest delivery.
func TestAFullReplayCacheRemembersTheNewest(t *testing.T) {
	now := time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC)
	h := &Webhooks{}
	for i := 0; i < maxSeen; i++ {
		h.remember(fmt.Sprintf("k%d", i), now.Add(time.Duration(i)*time.Millisecond), now)
	}
	if !h.remember("newest", now.Add(time.Second), now) || h.remember("newest", now.Add(time.Second), now) {
		t.Fatal("the newest delivery was not remembered")
	}
	if len(h.seen) != maxSeen {
		t.Fatalf("%d remembered", len(h.seen))
	}
}

// Pre-flight M10: a handshake error is counted and not logged; another line
// is said once.
func TestTheWebhookErrorLogCountsHandshakes(t *testing.T) {
	m := NewMetrics(prometheus.NewRegistry())
	var out bytes.Buffer
	l := WebhookErrorLog(m, &out)
	for i := 0; i < 3; i++ {
		l.Printf("http: TLS handshake error from 10.0.0.%d:5000: EOF", i)
		l.Printf("http: Accept error: too many open files")
	}
	if testutil.ToFloat64(m.Webhooks.WithLabelValues("", HookTLSHandshake)) != 3 ||
		strings.Count(out.String(), "Accept error") != 1 || strings.Contains(out.String(), "handshake") {
		t.Fatalf("%s", out.String())
	}
}

func TestBothRecordedTimestampSpellingsParse(t *testing.T) {
	for _, s := range []string{"2026-09-30T15:43:34.000898+00:00", "2026-09-30 15:52:04.757496+00:00",
		"2026-09-30T15:43:34+00:00"} {
		if _, err := parseHookTime(s); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	if _, err := parseHookTime("yesterday"); err == nil {
		t.Fatal("parsed nonsense")
	}
}

// endless streams a JSON-looking body that never ends, counting what was
// read: a sender still writing when the cap is reached.
type endless struct{ n int }

func (e *endless) Read(p []byte) (int, error) {
	if e.n == 0 && len(p) > 0 {
		p[0] = '{'
		e.n++
		return 1, nil
	}
	for i := range p {
		p[i] = 'a'
	}
	e.n += len(p)
	return len(p), nil
}

// A body still streaming when the cap is reached is refused 413 having read
// no more than the cap, and triggers nothing.
func TestAStreamingBodyIsCutAtTheCap(t *testing.T) {
	rig := newHookRig(time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC))
	src := &endless{}
	req := httptest.NewRequest(http.MethodPost, "/v1/webhook/netbox_prod", src)
	req.ContentLength = -1
	req.RemoteAddr = "10.0.0.9:51000"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Hook-Signature", sign([]byte("{}"), hookSecret))
	w := httptest.NewRecorder()
	rig.h.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge || rig.count("netbox_prod", HookTooLarge) != 1 || len(rig.notified) != 0 {
		t.Fatalf("%d %v", w.Code, rig.notified)
	}
	if src.n > maxWebhookBody+64<<10 {
		t.Fatalf("read %d bytes past a cap of %d", src.n, maxWebhookBody)
	}
}

// Decision 31: a delivery dated ahead of this host's clock past the window
// is refused like one behind it.
func TestAFutureDeliveryTriggersNothing(t *testing.T) {
	rig := newHookRig(time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC))
	b := body("2026-10-01T02:05:01+00:00")
	if w := rig.deliver("/v1/webhook/netbox_prod", b, sign(b, hookSecret), "application/json"); w.Code !=
		http.StatusBadRequest || len(rig.notified) != 0 || rig.count("netbox_prod", HookStale) != 1 {
		t.Fatalf("%d %v", w.Code, rig.notified)
	}
}

// Every outcome, said or not, leaves the secret, the signature and the body
// out of the log and out of the answer.
func TestNoOutcomeLeaksTheSecretTheSignatureOrTheBody(t *testing.T) {
	rig := newHookRig(time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC))
	rig.h.Secrets["nautobot_dc2"] = sot.NewSecret("second-source-webhook-secret-abcdef")
	good := body("2026-10-01T02:00:00.5+00:00")
	stale := body("2026-10-01T01:00:00+00:00")
	noTS := []byte(`{"event": "updated", "data": {"name": "leaf-01"}}`)
	notJSON := []byte(`event=updated&name=leaf-01`)
	var sigs []string
	send := func(path string, b []byte, sig, ctype string) {
		sigs = append(sigs, sig)
		w := rig.deliver(path, b, sig, ctype)
		for _, leak := range []string{hookSecret, "second-source-webhook-secret-abcdef", "leaf-01", "updated"} {
			if strings.Contains(w.Body.String(), leak) {
				t.Fatalf("%s answered %q: %s", path, leak, w.Body)
			}
		}
	}
	for _, src := range []string{"netbox_prod", "nautobot_dc2"} {
		p := "/v1/webhook/" + src
		secret := rig.h.Secrets[src].Reveal()
		send(p, good, sign(good, secret), "application/json")
		send(p, good, sign(good, secret), "application/json")
		send(p, good, sign(good, "a-different-secret-of-thirty-two-chars"), "application/json")
		send(p, good, "", "application/json")
		send(p, good, sign(good, secret), "text/plain")
		send(p, stale, sign(stale, secret), "application/json")
		send(p, noTS, sign(noTS, secret), "application/json")
		send(p, notJSON, sign(notJSON, secret), "application/json")
	}
	send("/v1/webhook/leaf-01", good, sign(good, hookSecret), "application/json")
	send("/v1/leaf-01", good, sign(good, hookSecret), "application/json")
	l := WebhookErrorLog(rig.h.Metrics, rig.out)
	l.Printf("http: TLS handshake error from 10.0.0.1:5000: tls: first record does not look like a TLS handshake")
	log := rig.out.String()
	if log == "" {
		t.Fatal("nothing was said")
	}
	leaks := []string{hookSecret, "second-source-webhook-secret-abcdef", "leaf-01", "updated", "event="}
	for _, s := range sigs {
		if s != "" {
			leaks = append(leaks, s, s[:32])
		}
	}
	for _, leak := range leaks {
		if strings.Contains(log, leak) {
			t.Fatalf("the log holds %q: %s", leak, log)
		}
	}
	if len(rig.notified) != 2 {
		t.Fatalf("%v", rig.notified)
	}
}

// Deliveries arriving at once from two sources are each taken once (run
// with -race).
func TestConcurrentDeliveriesAreTakenOnce(t *testing.T) {
	rig := newHookRig(time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC))
	var mu sync.Mutex
	rig.h.Notify = func(s string) { mu.Lock(); rig.notified = append(rig.notified, s); mu.Unlock() }
	rig.h.Log = &syncBuffer{}
	h := rig.h.Handler()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		for j := 0; j < 16; j++ {
			wg.Add(1)
			go func(i, j int) {
				defer wg.Done()
				b := body(fmt.Sprintf("2026-10-01T02:00:00.%02d+00:00", i))
				sig := sign(b, hookSecret)
				if j%4 == 3 {
					sig = ""
				}
				req := httptest.NewRequest(http.MethodPost, "/v1/webhook/netbox_prod", bytes.NewReader(b))
				req.RemoteAddr = "10.0.0.9:51000"
				req.Header.Set("Content-Type", "application/json")
				if sig != "" {
					req.Header.Set("X-Hook-Signature", sig)
				}
				h.ServeHTTP(httptest.NewRecorder(), req)
			}(i, j)
		}
	}
	wg.Wait()
	if len(rig.notified) != 8 || rig.count("netbox_prod", HookAccepted) != 8 || rig.count("netbox_prod", HookUnsigned) != 32 {
		t.Fatalf("%d notified, %v accepted", len(rig.notified), rig.count("netbox_prod", HookAccepted))
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

// Review I1, M5: until the signature is checked, a configured name and an
// unconfigured one are answered alike and read alike, so no answer before
// it says which names are configured.
func TestAnUnknownNameIsAnsweredLikeAKnownOneUntilTheSignature(t *testing.T) {
	b := body("2026-10-01T02:00:00+00:00")
	fake := strings.Repeat("ab", sha512.Size)
	big := bytes.Repeat([]byte("a"), maxWebhookBody+10)
	for name, c := range map[string]struct {
		body          []byte
		sig, ctype    string
		contentLength int64 // 0: as the body; -1: streamed
	}{
		"text/plain":         {b, fake, "text/plain", 0},
		"no content type":    {b, fake, "", 0},
		"unsigned":           {b, "", "application/json", 0},
		"not hex":            {b, "zz", "application/json", 0},
		"short signature":    {b, "abcd", "application/json", 0},
		"declared too large": {big, fake, "application/json", 0},
		"streamed too large": {big, fake, "application/json", -1},
		"forged":             {b, fake, "application/json", 0},
	} {
		var answers [2]string
		var read [2]int
		for i, path := range []string{"/v1/webhook/netbox_prod", "/v1/webhook/not_a_source"} {
			rig := newHookRig(time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC))
			src := &countingReader{r: bytes.NewReader(c.body)}
			req := httptest.NewRequest(http.MethodPost, path, src)
			req.ContentLength = int64(len(c.body))
			if c.contentLength != 0 {
				req.ContentLength = c.contentLength
			}
			if c.ctype != "" {
				req.Header.Set("Content-Type", c.ctype)
			}
			if c.sig != "" {
				req.Header.Set("X-Hook-Signature", c.sig)
			}
			w := httptest.NewRecorder()
			rig.h.Handler().ServeHTTP(w, req)
			answers[i] = fmt.Sprintf("%d %s %s", w.Code, w.Header().Get("Content-Type"), w.Body)
			read[i] = src.n
		}
		if answers[0] != answers[1] || read[0] != read[1] {
			t.Errorf("%s: known %q read %d, unknown %q read %d", name, answers[0], read[0], answers[1], read[1])
		}
	}
}

type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// Review M3: a declared length over the cap is refused before any read.
func TestADeclaredLengthOverTheCapIsNotRead(t *testing.T) {
	rig := newHookRig(time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC))
	src := &endless{}
	req := httptest.NewRequest(http.MethodPost, "/v1/webhook/netbox_prod", src)
	req.ContentLength = maxWebhookBody + 1
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Hook-Signature", strings.Repeat("ab", sha512.Size))
	w := httptest.NewRecorder()
	rig.h.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge || src.n != 0 || rig.count("netbox_prod", HookTooLarge) != 1 {
		t.Fatalf("%d, read %d", w.Code, src.n)
	}
}

// Review M2: an empty secret authenticates nothing, not even a delivery
// signed with the empty key.
func TestAnEmptySecretAuthenticatesNothing(t *testing.T) {
	rig := newHookRig(time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC))
	rig.h.Secrets["empty"] = sot.Secret{}
	b := body("2026-10-01T02:00:00+00:00")
	if w := rig.deliver("/v1/webhook/empty", b, sign(b, ""), "application/json"); w.Code != http.StatusUnauthorized ||
		len(rig.notified) != 0 || rig.count("", HookUnknownSource) != 1 {
		t.Fatalf("%d %v", w.Code, rig.notified)
	}
}

// Review M1: a delivery taken at the first instant it is fresh is still
// remembered at the last.
func TestADeliveryIsRememberedForAsLongAsItIsFresh(t *testing.T) {
	ts := time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC)
	rig := newHookRig(ts.Add(-webhookWindow))
	b := body("2026-10-01T02:00:00+00:00")
	for _, now := range []time.Time{ts.Add(-webhookWindow), ts, ts.Add(webhookWindow)} {
		rig.now = now
		if w := rig.deliver("/v1/webhook/netbox_prod", b, sign(b, hookSecret), "application/json"); w.Code != http.StatusAccepted {
			t.Fatalf("%s: %d", now, w.Code)
		}
	}
	if len(rig.notified) != 1 || rig.count("netbox_prod", HookDuplicate) != 2 {
		t.Fatalf("%v", rig.notified)
	}
	rig.now = ts.Add(webhookWindow + time.Nanosecond)
	if w := rig.deliver("/v1/webhook/netbox_prod", b, sign(b, hookSecret), "application/json"); w.Code !=
		http.StatusBadRequest || len(rig.notified) != 1 {
		t.Fatalf("past the window: %d", w.Code)
	}
}

// Review I2: a refusal that recurs between real deliveries is said again at
// most once a window, not once a delivery.
func TestARecurringRefusalIsSaidAgainAtMostOnceAWindow(t *testing.T) {
	start := time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC)
	rig := newHookRig(start)
	for i := 0; i < 10; i++ {
		rig.now = start.Add(time.Duration(i) * time.Second)
		b := body(rig.now.Format("2006-01-02T15:04:05.000000-07:00"))
		rig.deliver("/v1/webhook/netbox_prod", b, sign(b, hookSecret), "application/json")
		rig.deliver("/v1/webhook/netbox_prod", b, sign(b, "a-different-secret-of-thirty-two-chars"), "application/json")
	}
	log := rig.out.String()
	if n := strings.Count(log, "(bad_signature)"); n != 2 {
		t.Fatalf("bad_signature said %d times: %s", n, log)
	}
	if n := strings.Count(log, "authenticate again"); n != 1 {
		t.Fatalf("again said %d times: %s", n, log)
	}
	rig.now = start.Add(webhookWindow + 10*time.Second)
	b := body(rig.now.Format("2006-01-02T15:04:05.000000-07:00"))
	rig.deliver("/v1/webhook/netbox_prod", b, sign(b, hookSecret), "application/json")
	rig.deliver("/v1/webhook/netbox_prod", b, sign(b, "a-different-secret-of-thirty-two-chars"), "application/json")
	if n := strings.Count(rig.out.String(), "(bad_signature)"); n != 3 {
		t.Fatalf("a window on, bad_signature said %d times", n)
	}
}

// Review M4: the error log's lines are said again a window on, and the
// line that fills its memory says the rest go unsaid.
func TestTheWebhookErrorLogForgetsAfterAWindow(t *testing.T) {
	m := NewMetrics(prometheus.NewRegistry())
	var out bytes.Buffer
	now := time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC)
	l := webhookErrorLog(m, &out, func() time.Time { return now })
	for i := 0; i < maxTold+5; i++ {
		l.Printf("http: Accept error: too many open files; retrying in %dms", i)
	}
	if n := strings.Count(out.String(), "Accept error"); n != maxTold-1 ||
		strings.Count(out.String(), "further webhook server errors") != 1 {
		t.Fatalf("said %d: %s", n, out.String()[len(out.String())-300:])
	}
	now = now.Add(webhookWindow)
	l.Printf("http: Accept error: too many open files; retrying in 5ms")
	if n := strings.Count(out.String(), "retrying in 5ms"); n != 2 {
		t.Fatalf("a window on, said %d", n)
	}
}

// Re-review N1: a re-arm a real delivery could not take inside the window
// is owed, and the first refusal past the window takes it, so an outage
// that starts just after is said once — and only once.
func TestAnOutageAfterADeferredReArmIsSaidOnce(t *testing.T) {
	start := time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC)
	rig := newHookRig(start)
	stray := "a-different-secret-of-thirty-two-chars"
	at := func(d time.Duration, secret string) {
		rig.now = start.Add(d)
		b := body(rig.now.Format("2006-01-02T15:04:05.000000-07:00"))
		rig.deliver("/v1/webhook/netbox_prod", b, sign(b, secret), "application/json")
	}
	at(0, stray)
	at(time.Second, hookSecret)
	at(2*time.Second, stray)
	at(3*time.Second, hookSecret)
	before := strings.Count(rig.out.String(), "(bad_signature)")
	for d := 4 * time.Second; d < time.Hour; d += 30 * time.Second {
		at(d, stray)
	}
	if n := strings.Count(rig.out.String(), "(bad_signature)") - before; n != 1 {
		t.Fatalf("the outage was said %d times: %s", n, rig.out)
	}
	if len(rig.notified) != 2 {
		t.Fatalf("%v", rig.notified)
	}
}

// Final review M5: Webhooks printed whole, as a test failure or a panic dump
// would print it, holds no secret.
func TestWebhooksPrintedWholeHoldNoSecret(t *testing.T) {
	rig := newHookRig(time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC))
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if got := fmt.Sprintf(verb, rig.h); strings.Contains(got, hookSecret) {
			t.Fatalf("%s printed the secret", verb)
		}
	}
}
