package broker

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/broker/api"
	"github.com/blanketfish/port49/internal/oidc"
	"github.com/blanketfish/port49/internal/store"
	"github.com/blanketfish/port49/internal/store/crypt"
	"github.com/blanketfish/port49/internal/store/memory"
)

// The admin endpoints (plan 12b, task 3c; spec §2, §5.1.4, §5.1.6): each
// write needs its own right, then a touch bound to the request, then runs;
// the list needs a right and no touch. Every key and body here is the
// fixture's own.

const (
	liftPath      = "/v1/revocations/lift"
	listPath      = "/v1/revocations"
	forgetPath    = "/v1/directory/forget"
	resetPath     = "/v1/directory/reset-second-factor"
	unlockPath    = "/v1/directory/unlock"
	importPath    = "/v1/directory/import"
	testIssuer    = "CN=Test CA"
	certBody      = `{"cert_issuer":"CN=Test CA","cert_serial":"0x1A:2b"}`
	liftCertBody  = `{"cert_issuer":"CN=Test CA","cert_serial":"1a2b"}`
	certTarget    = "CN=Test CA serial 1a2b"
	daveBody      = `{"principal":"user:dave@example.com"}`
	daveKey       = "user:dave@example.com"
	resetAllBody  = `{"all":true}`
	maxImportTest = 16 << 20
)

// withAdminOps gives f what the directory operations need to run: a
// directory_password verifier, a sealed enrollment store with its mark, and a
// directory that answers for alice, who calls them.
func (f *mfaFixture) withAdminOps(t *testing.T) {
	t.Helper()
	f.b.PasswordSignIn = &oidc.PasswordSignIn{PrincipalDomains: []string{"example.com"},
		NewEntriesFor: oidc.DefaultNewEntriesFor, ReopenFor: oidc.DefaultReopenFor,
		FailuresPerPrincipal: oidc.DefaultFailuresPerPrincipal, FailuresPerSource: oidc.DefaultFailuresPerSource,
		Window: oidc.DefaultSignInWindow, TOTPLabel: "port49 (broker.test)"}
	sealedStore(t, f.fixture, false)
}

// exportOf is the sealed export of a store holding one enrollment, from a
// broker of its own: the body an import carries.
func exportOf(t *testing.T) string {
	t.Helper()
	donor, _ := newSignInFixture(t)
	sealedStore(t, donor, true)
	donor.enrolled(t, alicePrincipal, "uuid:alice")
	exp, err := donor.b.ExportEnrollments(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return string(exp)
}

// adminRoute is one admin-level request, with what the challenge shows and the
// right it needs.
type adminRoute struct {
	name, path, body string
	op, target       string
	right, event     string
	// setup makes what the call acts on exist, so a proved call runs.
	setup func(t *testing.T, f *mfaFixture)
	// revokeRight marks the one route that revoke_others alone opens.
	revokeRight bool
}

func importTarget(body string) string {
	sum := sha256.Sum256([]byte(body))
	return "merge " + hex.EncodeToString(sum[:])[:12]
}

func adminRoutes(t *testing.T) []adminRoute {
	t.Helper()
	exp := exportOf(t)
	revoke := func(req RevokeRequest) func(*testing.T, *mfaFixture) {
		return func(t *testing.T, f *mfaFixture) {
			t.Helper()
			req.Origin = "test"
			if _, err := f.b.Revoke(context.Background(), req); err != nil {
				t.Fatal(err)
			}
		}
	}
	return []adminRoute{
		{name: "revoke by certificate", path: revokePath, body: certBody, op: "revoke_certificate", target: certTarget,
			right: "revoke_others", event: "revoke", revokeRight: true},
		{name: "lift by principal", path: liftPath, body: daveBody, op: "lift", target: daveKey,
			right: "lift_revocations", event: "revoke", setup: revoke(RevokeRequest{Principal: daveKey})},
		{name: "lift by certificate", path: liftPath, body: liftCertBody, op: "lift", target: certTarget,
			right: "lift_revocations", event: "revoke", setup: revoke(RevokeRequest{Issuer: testIssuer, Serial: "1a2b"})},
		{name: "forget", path: forgetPath, body: daveBody, op: "forget_principal", target: daveKey,
			right: "forget_principals", event: "directory_forget",
			setup: func(t *testing.T, f *mfaFixture) {
				t.Helper()
				if err := f.st.PutMembership(context.Background(), store.Membership{Principal: daveKey,
					DN: "CN=Dave,DC=corp", EntryID: "guid:d4", VerifiedAt: f.now}, time.Hour); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "reset second factor", path: resetPath, body: daveBody, op: "reset_second_factor", target: daveKey,
			right: "reset_second_factor", event: "second_factor_reset"},
		{name: "reset every second factor", path: resetPath, body: resetAllBody, op: "reset_second_factor_all",
			target: "all", right: "reset_second_factor", event: "second_factor_reset"},
		{name: "unlock", path: unlockPath, body: daveBody, op: "unlock_sign_in", target: daveKey,
			right: "unlock_sign_in", event: "sign_in_unlock"},
		{name: "import", path: importPath + "?replace=false", body: exp, op: "import_enrollments",
			target: importTarget(exp), right: "import_enrollments", event: "enrollments_import"},
	}
}

func recordsWith(t *testing.T, f *mfaFixture, event, reason string) int {
	t.Helper()
	n := 0
	for _, r := range f.recs(t) {
		if r["event"] == event && (reason == "" || r["reason"] == reason) {
			n++
		}
	}
	return n
}

// Without its right a caller gets 403 api_right_missing, recorded, and no
// challenge: the right is checked before the gate, so a caller without it
// never presses the key.
func TestEachAdminRouteNeedsItsRight(t *testing.T) {
	for _, who := range []string{"bob", "alice with revoke_others alone"} {
		t.Run(who, func(t *testing.T) {
			var f *mfaFixture
			actor := func() *mfaActor { return f.bob }
			if who == "bob" {
				f = newMFAFixture(t, withTestDirectory())
			} else {
				f = newAdminFixture(t, withTestDirectory())
				actor = func() *mfaActor { return f.alice }
			}
			f.withAdminOps(t)
			for _, rt := range adminRoutes(t) {
				if rt.revokeRight && who != "bob" {
					continue // alice holds this one's right
				}
				t.Run(rt.name, func(t *testing.T) {
					before := recordsWith(t, f, rt.event, "api_right_missing")
					code, raw := actor().conn.post(t, rt.path, nil, rt.body)
					ans := decodeAdminAnswer(t, raw)
					if code != 403 || ans.Error != "api_right_missing" || ans.Admin != nil {
						t.Fatalf("answered %d %s (challenge %v), want 403 api_right_missing and none", code, ans.Error,
							ans.Admin != nil)
					}
					if !strings.Contains(ans.Detail, rt.right) {
						t.Fatalf("the answer does not name the right %s", rt.right)
					}
					if recordsWith(t, f, rt.event, "api_right_missing") != before+1 {
						t.Fatalf("no %s record with api_right_missing", rt.event)
					}
					if f.adminRecords(t, "admin_touch_required") != 0 || f.b.admin.len() != 0 {
						t.Fatal("a caller without the right was issued a challenge")
					}
				})
			}
		})
	}
}

// With the right and no proof, each route answers 401 admin_touch_required
// with the operation and target of spec §5.1.6, and does nothing.
func TestEachAdminRouteNeedsATouch(t *testing.T) {
	f := newMFAFixture(t, withAllAdminRights(), withTestDirectory())
	f.withAdminOps(t)
	for _, rt := range adminRoutes(t) {
		t.Run(rt.name, func(t *testing.T) {
			if rt.setup != nil {
				rt.setup(t, f)
			}
			before := recordsWith(t, f, rt.event, "")
			code, raw := f.alice.conn.post(t, rt.path, nil, rt.body)
			ans := decodeAdminAnswer(t, raw)
			if code != 401 || ans.Error != "admin_touch_required" || ans.Admin == nil {
				t.Fatalf("with no proof: %d %s, want 401 admin_touch_required with a challenge", code, ans.Error)
			}
			if ans.Admin.Operation != rt.op || ans.Admin.Target != rt.target {
				t.Fatalf("operation %q target %q, want %q %q", ans.Admin.Operation, ans.Admin.Target, rt.op, rt.target)
			}
			if recordsWith(t, f, rt.event, "") != before {
				t.Fatalf("a call with no proof wrote a %s record", rt.event)
			}
		})
	}
	// Nothing was done: dave's mark and the certificate's both still stand.
	if !f.marked(t, daveKey) {
		t.Fatal("a call with no proof lifted dave's mark")
	}
}

// A proved call runs, answers its text, and its proof is spent: sending the
// same proof again is refused and runs nothing.
func TestEachProvedAdminRouteRunsOnceOnly(t *testing.T) {
	for _, rt := range adminRoutes(t) {
		t.Run(rt.name, func(t *testing.T) {
			f := newMFAFixture(t, withAllAdminRights(), withTestDirectory())
			f.withAdminOps(t)
			if rt.setup != nil {
				rt.setup(t, f)
			}
			c := f.alice.conn
			ch := f.adminAsk(t, c, rt.path, rt.body)
			sig := f.adminSign(t, f.alice.touchKey, ch.Challenge, "POST", rt.path, rt.body, c.adminExporter(t))
			header := adminHeader(t, ch.Challenge, sig, f.alice.atts)
			code, raw := f.adminSend(t, c, rt.path, rt.body, header)
			var out struct {
				Text string `json:"text"`
			}
			switch {
			case code != 200 || json.Unmarshal(raw, &out) != nil || out.Text == "":
				t.Fatalf("the proved call: %d %s, want 200 with a text", code, decodeAdminAnswer(t, raw).Error)
			case recordsWith(t, f, rt.event, "") == 0:
				t.Fatalf("the proved call wrote no %s record", rt.event)
			}
			if f.adminRecords(t, "admin_touch_proved") != 1 {
				t.Fatal("no admin_touch_proved record")
			}
			before := len(f.recs(t))
			code, raw = f.adminSend(t, c, rt.path, rt.body, header)
			if code != 401 || decodeAdminAnswer(t, raw).Error != "admin_touch_refused" {
				t.Fatalf("a replay: %d %s, want 401 admin_touch_refused", code, decodeAdminAnswer(t, raw).Error)
			}
			for _, r := range f.recs(t)[before:] {
				if r["event"] == rt.event {
					t.Fatalf("a replay wrote a %s record", rt.event)
				}
			}
		})
	}
}

// A revocation's proof is for that revocation: sent to the lift path with the
// same body, it is refused, and the mark stands.
func TestARevokesProofIsNotALiftsProof(t *testing.T) {
	f := newMFAFixture(t, withAllAdminRights())
	if _, err := f.b.Revoke(context.Background(), RevokeRequest{Principal: bobKey, Origin: "test"}); err != nil {
		t.Fatal(err)
	}
	c := f.alice.conn
	for _, rt := range []struct{ name, from, to string }{
		{"revoke to lift", revokePath, liftPath},
		{"lift to revoke", liftPath, revokePath},
	} {
		t.Run(rt.name, func(t *testing.T) {
			ch := f.adminAsk(t, c, rt.from, bobBody)
			sig := f.adminSign(t, f.alice.touchKey, ch.Challenge, "POST", rt.from, bobBody, c.adminExporter(t))
			code, raw := f.adminSend(t, c, rt.to, bobBody, adminHeader(t, ch.Challenge, sig, f.alice.atts))
			if code != 401 || decodeAdminAnswer(t, raw).Error != "admin_touch_refused" {
				t.Fatalf("%d %s, want 401 admin_touch_refused", code, decodeAdminAnswer(t, raw).Error)
			}
			if !f.marked(t, bobKey) {
				t.Fatal("the mark is gone")
			}
		})
	}
}

// A lift is its own right: revoke_others alone cannot lift, and lift_revocations
// alone cannot revoke.
func TestALiftIsNotARevokeRight(t *testing.T) {
	f := newAdminFixture(t)
	code, raw := f.alice.conn.post(t, liftPath, nil, bobBody)
	if ans := decodeAdminAnswer(t, raw); code != 403 || ans.Error != "api_right_missing" ||
		!strings.Contains(ans.Detail, "lift_revocations") {
		t.Fatalf("revoke_others lifting: %d %s, want 403 api_right_missing naming lift_revocations", code, ans.Error)
	}
	g := newMFAFixture(t, withBobLifting())
	code, raw = g.bob.conn.post(t, revokePath, nil, carolBody)
	if ans := decodeAdminAnswer(t, raw); code != 403 || ans.Error != "api_right_missing" {
		t.Fatalf("lift_revocations revoking: %d %s, want 403 api_right_missing", code, ans.Error)
	}
	code, raw = g.bob.conn.post(t, liftPath, nil, carolBody)
	if ans := decodeAdminAnswer(t, raw); code != 401 || ans.Error != "admin_touch_required" {
		t.Fatalf("lift_revocations lifting: %d %s, want 401 admin_touch_required", code, ans.Error)
	}
}

// GET /v1/revocations is the list --list printed: revoke_others or
// lift_revocations reads it, with no touch; neither is 403.
func TestTheListNeedsARightAndNoTouch(t *testing.T) {
	ctx := context.Background()
	t.Run("revoke_others", func(t *testing.T) {
		f := newAdminFixture(t)
		if _, err := f.b.Revoke(ctx, RevokeRequest{Principal: carolKey, Origin: "test"}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.b.Revoke(ctx, RevokeRequest{Issuer: testIssuer, Serial: "1a2b", Origin: "test"}); err != nil {
			t.Fatal(err)
		}
		code, raw := f.alice.conn.do(t, "GET", listPath, nil, "")
		var out api.RevocationList
		if code != 200 || json.Unmarshal(raw, &out) != nil {
			t.Fatalf("answered %d", code)
		}
		if len(out.Marks) != 2 {
			t.Fatalf("%d marks, want 2", len(out.Marks))
		}
		rs, err := f.st.ListRevocations(ctx)
		if err != nil || out.Text != RevocationsText(rs, func(k, key string) (store.Lift, error) {
			return f.st.GetLift(ctx, k, key)
		}) {
			t.Fatal("the text is not what --list prints")
		}
		byKind := map[string]api.Revocation{}
		for _, m := range out.Marks {
			byKind[m.Kind] = m
		}
		if m := byKind["principal"]; m.Principal != carolKey || m.Origin != "test" || m.Since == "" {
			t.Fatalf("the principal mark is %+v", m)
		}
		if m := byKind["cert"]; m.CertIssuer != testIssuer || m.CertSerial != "1a2b" {
			t.Fatalf("the certificate mark is %+v", m)
		}
		if f.adminRecords(t, "admin_touch_required") != 0 {
			t.Fatal("the list asked for a touch")
		}
	})
	t.Run("lift_revocations", func(t *testing.T) {
		f := newMFAFixture(t, withBobLifting())
		code, raw := f.bob.conn.do(t, "GET", listPath, nil, "")
		var out api.RevocationList
		if code != 200 || json.Unmarshal(raw, &out) != nil || out.Text != "no revocation is in force" || out.Marks == nil {
			t.Fatalf("answered %d %s, want 200, no marks and the empty text", code, raw)
		}
	})
	t.Run("neither", func(t *testing.T) {
		f := newMFAFixture(t)
		code, raw := f.bob.conn.do(t, "GET", listPath, nil, "")
		if ans := decodeAdminAnswer(t, raw); code != 403 || ans.Error != "api_right_missing" {
			t.Fatalf("answered %d %s, want 403 api_right_missing", code, ans.Error)
		}
	})
	t.Run("a directory right alone", func(t *testing.T) {
		f := newMFAFixture(t, withBobAPI("forget_principals"))
		code, _ := f.bob.conn.do(t, "GET", listPath, nil, "")
		if code != 403 {
			t.Fatalf("forget_principals read the list: %d", code)
		}
	})
}

// An import is bounded at 16 MiB, answered 413 before any challenge, and the
// bound is on the body: 16 MiB itself is read and asked for a touch.
func TestImportIsBounded(t *testing.T) {
	f := newMFAFixture(t, withAllAdminRights())
	f.withAdminOps(t)
	c := f.alice.conn
	over := strings.Repeat("x", maxImportTest+1<<20)
	code, raw := c.doLoose(t, "POST", importPath+"?replace=false", over)
	if ans := decodeAdminAnswer(t, raw); code != 413 || ans.Admin != nil {
		t.Fatalf("a 17 MiB body: %d %s (challenge %v), want 413 and none", code, ans.Error, ans.Admin != nil)
	}
	if f.adminRecords(t, "admin_touch_required") != 0 || f.b.admin.len() != 0 {
		t.Fatal("a body over the bound was issued a challenge")
	}
	at := f.dial(t, f.alice)
	code, raw = at.doLoose(t, "POST", importPath+"?replace=false", strings.Repeat("x", maxImportTest))
	if ans := decodeAdminAnswer(t, raw); code != 401 || ans.Error != "admin_touch_required" {
		t.Fatalf("a 16 MiB body: %d %s, want 401 admin_touch_required", code, ans.Error)
	}
}

// doLoose sends a large body from a goroutine and reads the answer, since a
// server that refuses a body it will not read may close before it is all sent.
func (c *mfaConn) doLoose(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = fmt.Fprintf(c.c, "%s %s HTTP/1.1\r\nHost: broker\r\nContent-Type: application/octet-stream\r\n"+
			"Content-Length: %d\r\n\r\n%s", method, path, len(body), body)
	}()
	_ = c.c.SetReadDeadline(time.Now().Add(20 * time.Second))
	resp, err := http.ReadResponse(c.br, nil)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw := new(strings.Builder)
	_, _ = bufio.NewReader(resp.Body).WriteTo(raw)
	_ = c.c.Close() // the rest of a refused body may still be unsent
	wg.Wait()
	return resp.StatusCode, []byte(raw.String())
}

// An import's body may take longer to arrive than the server's 30 s read
// timeout allows a mint: the route sets its own deadline (A-M7).
func TestImportReadsItsBodyUnderItsOwnDeadline(t *testing.T) {
	defer func(d time.Duration) { readTimeout = d }(readTimeout)
	readTimeout = 1500 * time.Millisecond
	f := newMFAFixture(t, withAllAdminRights())
	f.withAdminOps(t)
	c := f.alice.conn
	body := strings.Repeat("x", 1<<20)
	if _, err := fmt.Fprintf(c.c, "POST %s?replace=false HTTP/1.1\r\nHost: broker\r\nContent-Length: %d\r\n\r\n%s",
		importPath, len(body), body[:len(body)/2]); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2500 * time.Millisecond) // past the server's read timeout
	if _, err := fmt.Fprint(c.c, body[len(body)/2:]); err != nil {
		t.Fatal(err)
	}
	_ = c.c.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp, err := http.ReadResponse(c.br, nil)
	if err != nil {
		t.Fatalf("no answer: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("a body that arrived slowly was answered %d, want 401 admin_touch_required", resp.StatusCode)
	}
}

// A malformed admin request is 400 before the right and before any challenge:
// a call that cannot run is never asked to press the key.
func TestAMalformedAdminRequestIsRefusedBeforeAnyChallenge(t *testing.T) {
	f := newMFAFixture(t, withAllAdminRights())
	f.withAdminOps(t)
	for _, c := range []struct{ name, path, body string }{
		{"a certificate with no serial", revokePath, `{"cert_issuer":"CN=Test CA"}`},
		{"a certificate with no issuer", revokePath, `{"cert_serial":"1a2b"}`},
		{"a certificate and a principal", revokePath, `{"cert_issuer":"CN=Test CA","cert_serial":"1a2b","principal":"user:bob@example.com"}`},
		{"a certificate with a bad serial", revokePath, `{"cert_issuer":"CN=Test CA","cert_serial":"xyz"}`},
		{"a lift naming nothing", liftPath, `{}`},
		{"a lift naming both", liftPath, `{"principal":"user:bob@example.com","cert_issuer":"CN=Test CA","cert_serial":"1"}`},
		{"a lift with an unknown field", liftPath, `{"principal":"user:bob@example.com","force":true}`},
		{"a forget naming nothing", forgetPath, `{}`},
		{"a forget of a non-principal", forgetPath, `{"principal":"bob"}`},
		{"a reset naming both", resetPath, `{"principal":"user:bob@example.com","all":true}`},
		{"a reset naming neither", resetPath, `{}`},
		{"an unlock of a workload", unlockPath, `{"principal":"app:ci"}`},
		{"an import with an unknown parameter", importPath + "?force=1", "x"},
		{"an import with a bad replace", importPath + "?replace=maybe", "x"},
		{"an import with a doubled replace", importPath + "?replace=true&replace=false", "x"},
		{"an empty import", importPath, "  "},
	} {
		t.Run(c.name, func(t *testing.T) {
			code, raw := f.alice.conn.post(t, c.path, nil, c.body)
			if ans := decodeAdminAnswer(t, raw); code != 400 || ans.Error != "bad_request" || ans.Admin != nil {
				t.Fatalf("answered %d %s, want 400 bad_request and no challenge", code, ans.Error)
			}
		})
	}
	if f.adminRecords(t, "admin_touch_required") != 0 || f.b.admin.len() != 0 {
		t.Fatal("a malformed request was issued a challenge")
	}
}

// An import's proof is bound to its query: the proof for replace=false sent
// with replace=true is refused, so a prompt that said "merge" never wipes.
func TestAnImportsProofIsBoundToItsReplaceFlag(t *testing.T) {
	f := newMFAFixture(t, withAllAdminRights())
	f.withAdminOps(t)
	body := exportOf(t)
	c := f.alice.conn
	merge, wipe := importPath+"?replace=false", importPath+"?replace=true"
	ch := f.adminAsk(t, c, merge, body)
	if ch.Operation != "import_enrollments" || !strings.HasPrefix(ch.Target, "merge ") {
		t.Fatalf("the prompt for a merge says %q %q", ch.Operation, ch.Target)
	}
	sig := f.adminSign(t, f.alice.touchKey, ch.Challenge, "POST", merge, body, c.adminExporter(t))
	code, raw := f.adminSend(t, c, wipe, body, adminHeader(t, ch.Challenge, sig, f.alice.atts))
	if code != 401 || decodeAdminAnswer(t, raw).Error != "admin_touch_refused" {
		t.Fatalf("a merge's proof sent as a replace: %d %s, want 401 admin_touch_refused", code, decodeAdminAnswer(t, raw).Error)
	}
	if again := f.adminAsk(t, c, wipe, body); !strings.HasPrefix(again.Target, "replace ") {
		t.Fatalf("the prompt for a replace says %q", again.Target)
	}
	if recordsWith(t, f, "enrollments_import", "") != 0 {
		t.Fatal("an import ran")
	}
}

// A lift over the API tells the process's copy of the marks, which a
// port49-broker runner keeps for its own restarts (Lifted), after the store
// committed it and with the mark that was lifted.
func TestALiftOverTheAPITellsTheCopy(t *testing.T) {
	f := newMFAFixture(t, withAllAdminRights())
	if _, err := f.b.Revoke(context.Background(), RevokeRequest{Principal: bobKey, Origin: "test"}); err != nil {
		t.Fatal(err)
	}
	var told []store.Revocation
	f.b.OnLift = func(r store.Revocation) {
		if f.marked(t, bobKey) {
			t.Error("the copy was told before the store lifted the mark")
		}
		told = append(told, r)
	}
	if code, _ := f.adminCall(t, f.alice, f.alice.conn, liftPath, bobBody); code != 200 {
		t.Fatalf("the lift: %d", code)
	}
	if len(told) != 1 || told[0].Kind != store.RevocationPrincipal || told[0].Key != bobKey {
		t.Fatalf("the copy was told %+v, want the principal mark of bob", told)
	}
	// A lift of what stands nowhere is 404 and tells no one.
	if code, raw := f.adminCall(t, f.alice, f.alice.conn, liftPath, bobBody); code != 404 ||
		decodeAdminAnswer(t, raw).Error != "not_revoked" || len(told) != 1 {
		t.Fatalf("a second lift: %d %s, told %d", code, decodeAdminAnswer(t, raw).Error, len(told))
	}
}

// A forget over the API runs Forget as the caller, on a broker whose directory
// was configured from the start, with a real proof: it removes the pin, and
// the record's origin is api <caller>.
func TestForgetRunsAsTheCaller(t *testing.T) {
	f := newMFAFixture(t, withAllAdminRights(), withTestDirectory())
	const victim = "user:victim@example.com"
	if err := f.st.PutMembership(context.Background(), store.Membership{Principal: victim, DN: "CN=Victim,DC=corp",
		EntryID: "guid:0a1b", VerifiedAt: f.now}, time.Hour); err != nil {
		t.Fatal(err)
	}
	body := `{"principal":"` + victim + `"}`
	code, raw := f.adminCall(t, f.alice, f.alice.conn, forgetPath, body)
	var out api.AdminResult
	if code != 200 || json.Unmarshal(raw, &out) != nil || !strings.Contains(out.Text, "guid:0a1b") {
		t.Fatalf("%d %s", code, raw)
	}
	if _, err := f.st.GetMembership(context.Background(), victim); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the pin outlived the forget: %v", err)
	}
	if !strings.Contains(f.logs.String(), `"origin":"api `+alicePrincipal+`"`) {
		t.Fatal("no record names the caller as origin")
	}
}

// A call whose operation cannot run on this broker is refused 409 after the
// right and before any challenge: no key press is spent on it, and a caller
// without the right is told nothing of the broker (403).
func TestAnUnavailableOperationAsksForNoTouch(t *testing.T) {
	f := newMFAFixture(t, withAllAdminRights()) // no directory, no directory_password verifier
	exp := exportOf(t)
	for _, c := range []struct{ name, path, body, want string }{
		{"forget", forgetPath, daveBody, "no broker.directory"},
		{"reset a second factor", resetPath, daveBody, "no directory_password verifier"},
		{"reset every second factor", resetPath, resetAllBody, "no directory_password verifier"},
		{"unlock", unlockPath, daveBody, "no directory_password verifier"},
		{"import", importPath, exp, "no directory_password verifier"},
	} {
		t.Run(c.name, func(t *testing.T) {
			code, raw := f.alice.conn.post(t, c.path, nil, c.body)
			ans := decodeAdminAnswer(t, raw)
			if code != 409 || ans.Error != "admin_operation_failed" || ans.Admin != nil ||
				!strings.Contains(ans.Detail, c.want) {
				t.Fatalf("answered %d %s %q, want 409 admin_operation_failed naming %q and no challenge", code,
					ans.Error, ans.Detail, c.want)
			}
			if strings.Contains(ans.Detail, "dave") {
				t.Fatal("the answer echoes the request")
			}
			// Without the right, the caller learns nothing of this broker.
			code, raw = f.bob.conn.post(t, c.path, nil, c.body)
			if ans := decodeAdminAnswer(t, raw); code != 403 || ans.Error != "api_right_missing" {
				t.Fatalf("a caller without the right: %d %s, want 403", code, ans.Error)
			}
		})
	}
	if f.adminRecords(t, "admin_touch_required") != 0 || f.b.admin.len() != 0 {
		t.Fatal("an operation that cannot run was issued a challenge")
	}
}

// A 409's text is the broker's own, or a principal the broker validated: an
// export that names an unknown key id does not have the id echoed back.
func TestAnImportRefusalNeverEchoesTheExport(t *testing.T) {
	f := newMFAFixture(t, withAllAdminRights())
	f.withAdminOps(t)
	// An export sealed under a key this broker does not hold, whose id is the
	// request's own text.
	donor, _ := newSignInFixture(t)
	donor.b.Enrollments = crypt.WrapEnrollments(memory.NewEnrollments(donor.b.Now), testKeys("zz-echo-me"), nil)
	if err := donor.b.Enrollments.CreateEnrollmentMark(context.Background(), store.EnrollmentMark{CreatedAt: donor.now}); err != nil {
		t.Fatal(err)
	}
	exp, err := donor.b.ExportEnrollments(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(exp), "zz-echo-me") {
		t.Fatal("setup: the export does not name its key id")
	}
	body := string(exp)
	code, raw := f.adminCall(t, f.alice, f.alice.conn, importPath+"?replace=true", body)
	if ans := decodeAdminAnswer(t, raw); code != 409 || ans.Error != "admin_operation_failed" ||
		strings.Contains(ans.Detail, "zz-echo-me") || !strings.Contains(ans.Detail, "encryption.previous") {
		t.Fatalf("answered %d %s %q: the text echoes the export or is not a 409", code, ans.Error, ans.Detail)
	}
}

// On the four routes whose right the route itself fixes, the right comes
// before the body is judged: a caller without it gets 403 and a record
// whatever it sent, so a stolen token cannot probe the route unseen. The
// revoke endpoint is the exception: its body's form picks the right.
func TestARightlessCallerWithAMalformedBodyIsRefusedForTheRight(t *testing.T) {
	f := newMFAFixture(t, withTestDirectory())
	f.withAdminOps(t)
	for _, c := range []struct{ name, path, event, body string }{
		{"lift", liftPath, "revoke", `{"force":true}`},
		{"lift naming nothing", liftPath, "revoke", `{}`},
		{"lift not JSON", liftPath, "revoke", `not json`},
		{"lift of an invalid target", liftPath, "revoke", `{"principal":"Not-A-Principal-xyz"}`},
		{"forget of an invalid target", forgetPath, "directory_forget", `{"principal":"Not-A-Principal-xyz"}`},
		{"forget", forgetPath, "directory_forget", `{"force":true}`},
		{"forget of a non-principal", forgetPath, "directory_forget", `{"principal":"bob"}`},
		{"reset naming both", resetPath, "second_factor_reset", `{"principal":"user:bob@example.com","all":true}`},
		{"reset naming neither", resetPath, "second_factor_reset", `{}`},
		{"unlock of a workload", unlockPath, "sign_in_unlock", `{"principal":"app:ci"}`},
		{"unlock not JSON", unlockPath, "sign_in_unlock", `[`},
	} {
		t.Run(c.name, func(t *testing.T) {
			before := recordsWith(t, f, c.event, "api_right_missing")
			code, raw := f.bob.conn.post(t, c.path, nil, c.body)
			if ans := decodeAdminAnswer(t, raw); code != 403 || ans.Error != "api_right_missing" || ans.Admin != nil {
				t.Fatalf("answered %d %s, want 403 api_right_missing", code, ans.Error)
			}
			if recordsWith(t, f, c.event, "api_right_missing") != before+1 {
				t.Fatalf("no %s record with api_right_missing", c.event)
			}
			// An unvalidated target never reaches the record.
			for _, r := range f.recs(t) {
				if enc, _ := json.Marshal(r); strings.Contains(string(enc), "Not-A-Principal-xyz") {
					t.Fatalf("a record carries the unvalidated target: %s", r["event"])
				}
			}
		})
	}
	// The exception, said as a test: the form decides the right there.
	code, raw := f.bob.conn.post(t, revokePath, nil, `{"cert_issuer":"CN=Test CA"}`)
	if ans := decodeAdminAnswer(t, raw); code != 400 || ans.Error != "bad_request" {
		t.Fatalf("a malformed revoke body answered %d %s, want 400 bad_request", code, ans.Error)
	}
}

// provedImportHead is the head of a proved import of body, its challenge taken
// on c: what a client sends before it sends the body.
func (f *mfaFixture) provedImportHead(t *testing.T, c *mfaConn, body string) string {
	t.Helper()
	path := importPath + "?replace=false"
	ch := f.adminAsk(t, c, path, body)
	sig := f.adminSign(t, f.alice.touchKey, ch.Challenge, "POST", path, body, c.adminExporter(t))
	return fmt.Sprintf("POST %s HTTP/1.1\r\nHost: broker\r\nContent-Length: %d\r\n%s: %s\r\n\r\n", path, len(body),
		api.AdminProofHeader, adminHeader(t, ch.Challenge, sig, f.alice.atts))
}

// A proved import whose body is cut short, or stalls past the deadline, is 400
// and spends no challenge: the proof is checked only on a whole body.
func TestAProvedImportWithATruncatedBodyIsRefusedAndKeepsItsChallenge(t *testing.T) {
	for _, how := range []string{"cut", "stalled"} {
		t.Run(how, func(t *testing.T) {
			defer func(d time.Duration) { importReadTimeout = d }(importReadTimeout)
			importReadTimeout = 1 * time.Second
			f := newMFAFixture(t, withAllAdminRights())
			f.withAdminOps(t)
			c := f.alice.conn
			body := exportOf(t)
			head := f.provedImportHead(t, c, body)
			if f.b.admin.len() != 1 {
				t.Fatalf("setup: %d challenges held, want 1", f.b.admin.len())
			}
			if _, err := fmt.Fprint(c.c, head+body[:len(body)/2]); err != nil {
				t.Fatal(err)
			}
			if how == "cut" {
				if err := c.c.CloseWrite(); err != nil {
					t.Fatal(err)
				}
			}
			_ = c.c.SetReadDeadline(time.Now().Add(10 * time.Second))
			resp, err := http.ReadResponse(c.br, nil)
			if err != nil {
				t.Fatalf("no answer: %v", err)
			}
			defer resp.Body.Close()
			raw := new(strings.Builder)
			_, _ = bufio.NewReader(resp.Body).WriteTo(raw)
			if ans := decodeAdminAnswer(t, []byte(raw.String())); resp.StatusCode != 400 || ans.Error != "bad_request" {
				t.Fatalf("a truncated body answered %d %s, want 400 bad_request", resp.StatusCode, ans.Error)
			}
			// The server closes the connection after the cut and drops its
			// challenge, so the held count races that close; what is pinned
			// is that the proof was never judged and the import never ran.
			for _, reason := range []string{"admin_touch_proved", "admin_touch_refused", "admin_touch_unavailable"} {
				if n := f.adminRecords(t, reason); n != 0 {
					t.Fatalf("a truncated body wrote %d %s records", n, reason)
				}
			}
			if recordsWith(t, f, "enrollments_import", "") != 0 {
				t.Fatal("a truncated body reached the import")
			}
		})
	}
}

// slowImport is an enrollment store whose import takes a while, and gives up
// when its context ends, as a store's write does.
type slowImport struct {
	store.Enrollments
	wait time.Duration
}

func (s slowImport) Import(ctx context.Context, sealed []byte, replace bool) (int, time.Time, error) {
	select {
	case <-time.After(s.wait):
	case <-ctx.Done():
		return 0, time.Time{}, ctx.Err()
	}
	return s.Enrollments.Import(ctx, sealed, replace)
}

// A body that arrives near the import deadline leaves the write its whole
// time. A deadline that fired after the body was whole would cancel the
// request's context and cut the write short; net/http clears the deadline at
// the body's EOF, and this pins that the route needs nothing else.
func TestAnImportWhoseBodyArrivesNearTheDeadlineStillWrites(t *testing.T) {
	defer func(d time.Duration) { importReadTimeout = d }(importReadTimeout)
	importReadTimeout = 3 * time.Second
	f := newMFAFixture(t, withAllAdminRights())
	f.withAdminOps(t)
	f.b.Enrollments = slowImport{Enrollments: f.b.Enrollments, wait: 4500 * time.Millisecond}
	c := f.alice.conn
	body := exportOf(t)
	head := f.provedImportHead(t, c, body)
	if _, err := fmt.Fprint(c.c, head+body[:len(body)/2]); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second) // the body is whole 1s inside the deadline
	if _, err := fmt.Fprint(c.c, body[len(body)/2:]); err != nil {
		t.Fatal(err)
	}
	_ = c.c.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp, err := http.ReadResponse(c.br, nil)
	if err != nil {
		t.Fatalf("no answer: %v", err)
	}
	defer resp.Body.Close()
	raw := new(strings.Builder)
	_, _ = bufio.NewReader(resp.Body).WriteTo(raw)
	if resp.StatusCode != 200 {
		ans := decodeAdminAnswer(t, []byte(raw.String()))
		t.Fatalf("the import answered %d %s %q, want 200", resp.StatusCode, ans.Error, ans.Detail)
	}
}

// An operation's error is one printable line, bounded, whatever it holds.
func TestAnAdminFailureIsOnePrintableBoundedLine(t *testing.T) {
	f := newMFAFixture(t)
	rec := httptest.NewRecorder()
	f.b.adminFailed(rec, "forget_principal", errors.New("broker: first\nsecond\x1b[31m "+strings.Repeat("y", 900)))
	var ans struct{ Error, Detail string }
	if err := json.Unmarshal(rec.Body.Bytes(), &ans); err != nil {
		t.Fatal(err)
	}
	if rec.Code != 409 || ans.Error != "admin_operation_failed" {
		t.Fatalf("answered %d %s, want 409 admin_operation_failed", rec.Code, ans.Error)
	}
	if strings.ContainsAny(ans.Detail, "\n\x1b") || len(ans.Detail) > 700 {
		t.Fatalf("the detail is not one bounded printable line: %d bytes", len(ans.Detail))
	}
}
