package broker

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/bundle"
	"github.com/blanketfish/port49/internal/directory"
	"github.com/blanketfish/port49/internal/store"
)

// Every body the broker reads is one JSON object: a second value after it is refused 400 bad_request
// naming "trailing data", never dropped unread (identity M3).
func TestEveryBrokerBodyRefusesTrailingData(t *testing.T) {
	check := func(name string, code int, raw string) {
		t.Helper()
		if code != http.StatusBadRequest || !strings.Contains(raw, "bad_request") || !strings.Contains(raw, "trailing data") {
			t.Errorf("%s: %d %s", name, code, raw)
		}
	}
	f := newMFAFixture(t, withAllAdminRights())
	conn := f.alice.conn
	for _, c := range []struct{ name, path, body string }{
		{"mint", "/v1/tokens", `{"devices":["core-sw01"]}{}`},
		{"mfa", "/v1/mfa", `{"method":"idp_mfa"}{}`},
		{"refresh challenge", "/v1/refresh/challenge", `{}{}`},
		{"refresh", "/v1/refresh", `{}{}`},
	} {
		code, raw := conn.post(t, c.path, nil, c.body)
		check(c.name, code, string(raw))
	}

	// the admin proof header: a valid proof with a second object after it
	ch := f.adminAsk(t, conn, revokePath, bobBody)
	sig := f.adminSign(t, f.alice.touchKey, ch.Challenge, "POST", revokePath, bobBody, conn.adminExporter(t))
	one, err := base64.RawURLEncoding.DecodeString(adminHeader(t, ch.Challenge, sig, f.alice.atts))
	if err != nil {
		t.Fatal(err)
	}
	code, raw := f.adminSend(t, conn, revokePath, bobBody, base64.RawURLEncoding.EncodeToString(append(one, '{', '}')))
	if code == http.StatusOK || !strings.Contains(string(raw), "trailing data") {
		t.Errorf("admin proof header: %d %s", code, raw)
	}

	g := newFixture(t, 8)
	iss := g.withIssuance(t)
	key := newECKey(t)
	w := g.bearer(context.Background(), "POST", "/v1/certificate", csrBody(t, key)+"{}", g.signInFor(t, iss, key, nil))
	check("certificate", w.Code, w.Body.String())

	sf, _ := newSignInFixture(t)
	w = sf.call(context.Background(), nil, "POST", "/v1/sign-in", `{"name":"alice","password":"x","code":"123456"}{}`)
	check("sign-in", w.Code, w.Body.String())
}

// An idp_mfa proof writes no once-record: its nonce names the challenge, and the challenge is taken
// once, so a second use of the ID token finds it spent (stores/identity: the mfa_token key is moot).
func TestAnIDPMFAProofWritesNoTokenOnceRecord(t *testing.T) {
	f := newMFAFixture(t)
	ch := f.ask(t, f.alice, "core-sw01")
	tok := f.idToken(t, idTokenOpts{principal: "alice@example.com", nonceFor: ch, amr: []string{"mfa"}, authTime: f.clock.Now()})
	if code, detail := f.proveIdPDetail(t, tok, ch); code != 200 {
		t.Fatalf("the proof: %d %s", code, detail)
	}
	sum := sha256.Sum256([]byte(tok))
	if ok, err := f.st.PutOnce(context.Background(), "mfa_token "+hex.EncodeToString(sum[:]), nil, time.Hour); err != nil || !ok {
		t.Fatalf("the store holds an mfa_token record after a proof: %v %v", ok, err)
	}
	if code, detail := f.proveIdPDetail(t, tok, ch); code != 401 || !strings.Contains(detail, "unknown, spent or expired") {
		t.Fatalf("a second use of the token: %d %s", code, detail)
	}
}

// The 503s say when to try again, as the Retry-After header does; no one retries on the caller's
// behalf (identity M4).
func TestBindRefusalsSayWhenToTryAgain(t *testing.T) {
	for _, err := range []error{directory.ErrUnavailable, store.ErrUnavailable, errors.New("other")} {
		ref := directoryRefusal(err)
		if ref.Status != http.StatusServiceUnavailable || !strings.Contains(ref.Detail, "try again in 30s") ||
			strings.Contains(ref.Detail, "the agent retries") {
			t.Errorf("%v: %+v", err, ref)
		}
	}
}

// A by-name request for a device nobody can see is denied with the bundle in force on the record,
// as every other deny is (policy M2).
func TestAByNameNoGrantsDenyCarriesTheBundle(t *testing.T) {
	f := newFixture(t, 8)
	decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["no-such-device"]}`, ""))
	var found bool
	for _, r := range eventsOf(f.records(t), "mint") {
		if r["verdict"] != "deny" {
			continue
		}
		pol, _ := r["policy"].(map[string]any)
		if pol == nil || pol["bundle"] == nil || pol["bundle"] == "" {
			t.Errorf("the deny carries no bundle: %v", r)
		}
		found = true
	}
	if !found {
		t.Fatal("no deny record")
	}
}

// A device name is at most 253 bytes, one constant for the bundle and the broker; a platform or
// attribute key keeps its 255 (policy M3).
func TestADeviceNameOver253BytesIsRefusedByTheBundle(t *testing.T) {
	if bundle.MaxDeviceName != 253 || maxDeviceName != bundle.MaxDeviceName {
		t.Fatalf("limits: bundle %d, broker %d", bundle.MaxDeviceName, maxDeviceName)
	}
	if !bundle.DeviceNameOK(strings.Repeat("a", 253)) || bundle.DeviceNameOK(strings.Repeat("a", 254)) {
		t.Error("DeviceNameOK is not 1 to 253")
	}
	if !bundle.NameOK(strings.Repeat("a", 255)) || bundle.NameOK(strings.Repeat("a", 256)) {
		t.Error("NameOK is not 1 to 255 for a platform or attribute key")
	}
}
