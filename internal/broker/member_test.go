package broker

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/testpki"
)

const corpAlice = "user:alice@corp.example.com"

// answerFor is a directory answer for principal, as a mapping gives it.
func answerFor(principal, username string) directory.Answer {
	return directory.Answer{Membership: store.Membership{Principal: principal, Username: username,
		GroupDNs: []string{"cn=secret-group,dc=corp"}, GroupNames: []string{"secret-group"}}, Source: directory.Fresh}
}

// withDirectory gives f's broker a static resolver over answers (keyed as
// ForTestsStaticResolver reads a certificate) answering err when set.
func withDirectory(f *fixture, answers map[string]directory.Answer, err error) *directory.Resolver {
	// Current reads a request's membership by the pinned principal, so each
	// answer is also held under the principal it names.
	byPrincipal := map[string]directory.Answer{}
	for k, a := range answers {
		byPrincipal[k] = a
		byPrincipal[a.Principal] = a
	}
	answers = byPrincipal
	r := directory.ForTestsStaticResolver(f.st, answers, err)
	f.b.Directory = r
	return r
}

// serveMapped serves f's broker behind a Listener that maps at bind.
func serveMapped(t *testing.T, f *fixture) (string, *Listener) {
	t.Helper()
	return serveThroughWith(t, f, DefaultListenerLimits, nil, func(l *Listener) { l.Map = f.b.BindMap })
}

// getOn writes a GET to path on the held connection c and reads the answer.
func getOn(t *testing.T, c *tls.Conn, br *bufio.Reader, path string) heldAnswer {
	t.Helper()
	if _, err := fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: broker\r\n\r\n", path); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("GET %s on a held connection: %v", path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return heldAnswer{status: resp.StatusCode, body: string(raw), retryAfter: resp.Header.Get("Retry-After")}
}

func principalOnWire(t *testing.T, a heldAnswer) string {
	t.Helper()
	var id api.Identity
	if a.status != 200 || json.Unmarshal([]byte(a.body), &id) != nil {
		t.Fatalf("%d %s", a.status, a.body)
	}
	return id.Principal
}

func wantRefused(t *testing.T, a heldAnswer, status int, code string) {
	t.Helper()
	var e api.Error
	if err := json.Unmarshal([]byte(a.body), &e); err != nil || a.status != status || e.Error != code {
		t.Fatalf("answered %d %s, want %d %s", a.status, a.body, status, code)
	}
}

// With a directory, the principal is the mapping's, pinned at bind, and
// every request on the connection reads it (Ruling 4).
func TestThePrincipalIsPinnedAtBind(t *testing.T) {
	f := newFixture(t, 8)
	answers := map[string]directory.Answer{alicePrincipal: answerFor(corpAlice, "alice")}
	res := withDirectory(f, answers, nil)
	addr, _ := serveMapped(t, f)
	c, br := held(t, f, addr, f.alice)
	if got := principalOnWire(t, getOn(t, c, br, "/v1/identity")); got != corpAlice {
		t.Fatalf("principal %q", got)
	}
	answers[alicePrincipal] = answerFor("user:mallory@corp.example.com", "mallory")
	if got := principalOnWire(t, getOn(t, c, br, "/v1/identity")); got != corpAlice {
		t.Fatalf("after the directory changed its answer, principal %q: not pinned", got)
	}
	// One mapping at bind; each identity request then reads the pinned
	// principal's membership (Current) and never maps again.
	if n := res.Calls.Load(); n != 3 {
		t.Fatalf("the directory was asked %d times, want the bind's mapping and one membership per request", n)
	}
}

// Each resolver refusal is answered as the agent can act on it (Ruling 4):
// 401 identity_unmapped, identity_ambiguous and username_collision, each
// closing the connection; 503 directory_unavailable with Retry-After 30,
// which the agent retries.
func TestBindRefusalsReadAsTheAgentNeeds(t *testing.T) {
	for err, want := range map[error]struct {
		status int
		code   string
	}{
		directory.ErrUnmapped:      {401, "identity_unmapped"},
		directory.ErrAmbiguous:     {401, "identity_ambiguous"},
		directory.ErrUsernameTaken: {401, "username_collision"},
		directory.ErrUnavailable:   {503, "directory_unavailable"},
	} {
		ref := directoryRefusal(fmt.Errorf("%w: detail", err))
		if ref.Status != want.status || ref.Error != want.code || (want.status == 503) != (ref.RetryAfter == 30) {
			t.Errorf("%v: %+v", err, ref)
		}
		if strings.Contains(ref.Detail, "detail") {
			t.Errorf("%v: the resolver's error text reached the answer: %q", err, ref.Detail)
		}
	}
}

// The same, end to end: at bind, over the wire, with the connection closed,
// and never a directory answer a refusal could leak.
func TestBindRefusalsAreAnsweredOnTheWire(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{directory.ErrUnmapped, 401, "identity_unmapped"},
		{directory.ErrAmbiguous, 401, "identity_ambiguous"},
		{directory.ErrUsernameTaken, 401, "username_collision"},
		{directory.ErrUnavailable, 503, "directory_unavailable"},
		{context.DeadlineExceeded, 503, "store_unavailable"},
	} {
		t.Run(tc.code, func(t *testing.T) {
			f := newFixture(t, 8)
			withDirectory(f, nil, fmt.Errorf("%w: ldaps://dc1.corp.example.com down", tc.err))
			addr, _ := serveMapped(t, f)
			c := dialAs(t, f, addr, f.alice)
			br := bufio.NewReader(c)
			a := postOn(t, c, br, "/v1/tokens", `{"devices":["leaf1"]}`)
			wantRefused(t, a, tc.status, tc.code)
			if (tc.status == 503) != (a.retryAfter == "30") {
				t.Fatalf("Retry-After %q on %d", a.retryAfter, tc.status)
			}
			if strings.Contains(a.body, "dc1.corp") {
				t.Fatalf("the server URI reached the agent: %s", a.body)
			}
			if !closedByPeer(c) {
				t.Fatal("the refused connection was held")
			}
			eventually(t, "nothing charged", func() bool { return f.gauge("pending") == 0 && f.gauge("held") == 0 })
		})
	}
}

// Called without a Server (no held connection), the request maps now and
// answers as the bind does; a refusal is recorded under the event.
func TestARequestWithNoHeldConnectionMapsAndRefusesAsTheBindDoes(t *testing.T) {
	f := newFixture(t, 8)
	res := withDirectory(f, nil, directory.ErrUnavailable)
	w := f.call(context.Background(), f.state(f.alice), "GET", "/v1/identity", "")
	if w.Code != 503 || w.Header().Get("Retry-After") != "30" || !strings.Contains(w.Body.String(), "directory_unavailable") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	recs := eventsOf(f.records(t), "identity")
	if len(recs) != 1 || recs[0]["verdict"] != "deny" || recs[0]["reason"] != "directory_unavailable" {
		t.Fatalf("%v", recs)
	}
	if res.Calls.Load() != 1 {
		t.Fatalf("calls %d", res.Calls.Load())
	}
	f.b.Directory = directory.ForTestsStaticResolver(f.st, map[string]directory.Answer{
		alicePrincipal: answerFor(corpAlice, "alice"), corpAlice: answerFor(corpAlice, "alice")}, nil)
	w = f.call(context.Background(), f.state(f.alice), "GET", "/v1/identity", "")
	var id api.Identity
	if err := json.Unmarshal(w.Body.Bytes(), &id); err != nil || w.Code != 200 || id.Principal != corpAlice {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

// Without a directory, nothing changes: the email SAN is the principal.
func TestNoDirectoryKeepsTheEmailPrincipal(t *testing.T) {
	f := newFixture(t, 8)
	addr, _ := serveThrough(t, f, DefaultListenerLimits, nil)
	c, br := held(t, f, addr, f.alice)
	if got := principalOnWire(t, getOn(t, c, br, "/v1/identity")); got != alicePrincipal {
		t.Fatalf("principal %q", got)
	}
}

// A certificate with no email SAN passes the handshake when a directory
// maps it (VerifyConnection checks the chain, not the mapping).
func TestACertificateWithoutAnEmailSANBindsWithADirectory(t *testing.T) {
	f := newFixture(t, 8)
	bob, err := f.ca.Issue(testpki.Leaf{CommonName: "bob", Client: true, NotBefore: f.now.Add(-time.Hour),
		NotAfter: f.now.Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	withDirectory(f, map[string]directory.Answer{"bob": answerFor("user:bob@corp.example.com", "bob")}, nil)
	addr, _ := serveMapped(t, f)
	c, br := held(t, f, addr, bob)
	if got := principalOnWire(t, getOn(t, c, br, "/v1/identity")); got != "user:bob@corp.example.com" {
		t.Fatalf("principal %q", got)
	}
	// Without a directory the same certificate is refused at the handshake,
	// which TLS 1.3 reports to the client after its own handshake: the
	// dial succeeds, and the connection is closed before it is answered.
	f2 := newFixture(t, 8)
	addr2, _ := serveThrough(t, f2, DefaultListenerLimits, nil)
	c2 := dialAs(t, f2, addr2, bob)
	_, werr := io.WriteString(c2, "GET /v1/config HTTP/1.1\r\nHost: broker\r\n\r\n")
	_ = c2.SetReadDeadline(time.Now().Add(5 * time.Second))
	if resp, rerr := http.ReadResponse(bufio.NewReader(c2), nil); rerr == nil {
		t.Fatalf("a certificate with no email SAN was answered %d without a directory (write: %v)", resp.StatusCode, werr)
	}
}

// A certificate marked by its key, with every directory server down, is
// answered 401 credential_revoked, never 503 directory_unavailable, and
// the resolver is never asked (pre-flight I-4; listen.go's invariant): the
// static resolver's err is directory.ErrUnavailable and its Calls stays 0.
func TestAMarkedCertificateIsRevokedBeforeTheDirectoryIsAsked(t *testing.T) {
	f := newFixture(t, 8)
	res := withDirectory(f, nil, directory.ErrUnavailable)
	addr, bl := serveMapped(t, f)
	mark := store.Revocation{Kind: store.RevocationCert, Key: certKey(f.alice), At: f.now.Add(-time.Minute)}
	bl.Revoked(mark, true)
	answeredRevoked(t, dialAs(t, f, addr, f.alice), mark)
	eventually(t, "nothing charged", func() bool { return f.gauge("pending") == 0 && f.gauge("held") == 0 })
	// And on a request with no held connection, from the store's marks.
	if err := f.st.PutRevocation(context.Background(), mark); err != nil {
		t.Fatal(err)
	}
	w := f.call(context.Background(), f.state(f.alice), "GET", "/v1/identity", "")
	wantRefused(t, heldAnswer{status: w.Code, body: w.Body.String()}, 401, "credential_revoked")
	if n := res.Calls.Load(); n != 0 {
		t.Fatalf("the directory was asked %d times for a marked certificate", n)
	}
}

// A mark made by principal before a directory was configured (the
// certificate's email-SAN principal) still refuses the certificate once
// the directory maps it to another principal (pre-flight I-16): 401
// credential_revoked at the bind, and on a request whose held connection
// bound before the mark.
func TestAMarkOnTheLegacyPrincipalStillHolds(t *testing.T) {
	f := newFixture(t, 8)
	res := withDirectory(f, map[string]directory.Answer{alicePrincipal: answerFor(corpAlice, "alice")}, nil)
	addr, bl := serveMapped(t, f)
	c, br := held(t, f, addr, f.alice) // binds before the mark
	if got := principalOnWire(t, getOn(t, c, br, "/v1/identity")); got != corpAlice {
		t.Fatalf("principal %q", got)
	}
	mark := store.Revocation{Kind: store.RevocationPrincipal, Key: alicePrincipal, At: f.now.Add(-time.Minute)}
	if err := f.st.PutRevocation(context.Background(), mark); err != nil {
		t.Fatal(err)
	}
	wantRefused(t, getOn(t, c, br, "/v1/identity"), 401, "credential_revoked")
	// A new connection is refused at the bind, before the directory is asked.
	before := res.Calls.Load()
	bl.Revoked(mark, true)
	answeredRevoked(t, dialAs(t, f, addr, f.alice), mark)
	if n := res.Calls.Load(); n != before {
		t.Fatalf("the directory was asked for a certificate whose legacy principal is marked (%d calls)", n-before)
	}
	// A mark on the mapped principal refuses too, after the mapping.
	f2 := newFixture(t, 8)
	withDirectory(f2, map[string]directory.Answer{alicePrincipal: answerFor(corpAlice, "alice")}, nil)
	if err := f2.st.PutRevocation(context.Background(), store.Revocation{Kind: store.RevocationPrincipal,
		Key: corpAlice, At: f2.now}); err != nil {
		t.Fatal(err)
	}
	w := f2.call(context.Background(), f2.state(f2.alice), "GET", "/v1/identity", "")
	wantRefused(t, heldAnswer{status: w.Code, body: w.Body.String()}, 401, "credential_revoked")
}

// A machine principal never touches the directory (pre-flight I-10).
func TestAMachinePrincipalNeverTouchesTheDirectory(t *testing.T) {
	f := newFixture(t, 8)
	res := withDirectory(f, nil, nil)
	for _, p := range []string{"spiffe://corp/agent", "app:backup"} {
		if _, err := res.Verify(context.Background(), p); !errors.Is(err, directory.ErrNotUser) {
			t.Fatalf("%s: %v", p, err)
		}
		if _, err := res.Current(context.Background(), p); !errors.Is(err, directory.ErrNotUser) {
			t.Fatalf("%s: %v", p, err)
		}
	}
	if n := res.Calls.Load(); n != 0 {
		t.Fatalf("the directory was asked %d times for machine principals", n)
	}
	// A mapping that gave a machine principal is refused, never pinned.
	withDirectory(f, map[string]directory.Answer{alicePrincipal: answerFor("spiffe://corp/agent", "agent")}, nil)
	if _, ref := f.b.BindMap(context.Background(), *f.state(f.alice), store.Credential{}); ref == nil ||
		ref.Error != "identity_unmapped" {
		t.Fatalf("%+v", ref)
	}
}

// A refresh on a mapped connection acts as the pinned principal, never as
// the email-SAN principal the certificate had before a directory: a mark on
// the pinned principal refuses it, and no context of the legacy principal is
// extended (review I-1).
func TestARefreshActsAsThePinnedPrincipal(t *testing.T) {
	f := newFixture(t, 8)
	withDirectory(f, map[string]directory.Answer{alicePrincipal: answerFor(corpAlice, "alice")}, nil)
	addr, _ := serveMapped(t, f)
	c, br := held(t, f, addr, f.alice)
	auth := f.now
	f.liveContextAt(t, "nx1", "legacy_alice", alicePrincipal, certKey(f.alice), auth, auth.Add(8*time.Hour))
	f.liveContextAt(t, "leaf1", "alice", corpAlice, certKey(f.alice), auth, auth.Add(8*time.Hour))
	before, err := f.st.GetContext(context.Background(), store.ContextKey{NAS: "nx1", Username: "legacy_alice"})
	if err != nil {
		t.Fatal(err)
	}
	f.advance(time.Hour)
	// Unmarked: the pinned principal's context is the one visited, and the
	// legacy principal's is never touched.
	status, resp := refreshOn(t, c, br, f.alice)
	if status != 200 {
		t.Fatalf("%d %+v", status, resp)
	}
	for _, s := range resp.Sessions {
		if s.Device == "nx1" {
			t.Fatalf("a refresh on a connection pinned to %s reported the legacy principal's context: %+v", corpAlice, resp)
		}
	}
	after, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "nx1", Username: "legacy_alice"})
	if !after.SessionExpires.Equal(before.SessionExpires) || !after.RefreshedAt.Equal(before.RefreshedAt) {
		t.Fatalf("the legacy principal's context was extended: %+v -> %+v", before, after)
	}
	// A mark on the pinned principal refuses the refresh and extends nothing.
	if err := f.st.PutRevocation(context.Background(), store.Revocation{Kind: store.RevocationPrincipal,
		Key: corpAlice, At: f.now, Origin: "test"}); err != nil {
		t.Fatal(err)
	}
	f.advance(time.Minute)
	f.advance(refreshEvery)
	status, _ = refreshOn(t, c, br, f.alice)
	if status != 401 {
		t.Fatalf("a refresh on a marked pinned principal: %d, want 401", status)
	}
	after, _ = f.st.GetContext(context.Background(), store.ContextKey{NAS: "nx1", Username: "legacy_alice"})
	if !after.SessionExpires.Equal(before.SessionExpires) {
		t.Fatalf("the legacy principal's context was extended under a mark on the pinned one: %+v", after)
	}
}

// A mark on the legacy principal refuses a refresh on the mapped connection.
func TestARefreshReadsTheLegacyMark(t *testing.T) {
	f := newFixture(t, 8)
	withDirectory(f, map[string]directory.Answer{alicePrincipal: answerFor(corpAlice, "alice")}, nil)
	addr, _ := serveMapped(t, f)
	c, br := held(t, f, addr, f.alice)
	if err := f.st.PutRevocation(context.Background(), store.Revocation{Kind: store.RevocationPrincipal,
		Key: alicePrincipal, At: f.now, Origin: "test"}); err != nil {
		t.Fatal(err)
	}
	if status, _ := refreshOn(t, c, br, f.alice); status != 401 {
		t.Fatalf("%d, want 401", status)
	}
}

// A held connection with no pin under a directory is never re-mapped per
// request (review M-1): it is refused 503 directory_unavailable.
func TestAHeldConnectionWithNoPinIsNotRemapped(t *testing.T) {
	f := newFixture(t, 8)
	res := withDirectory(f, map[string]directory.Answer{alicePrincipal: answerFor(corpAlice, "alice")}, nil)
	ctx := withHeldConn(context.Background(), f.now, nil)
	w := f.call(ctx, f.state(f.alice), "GET", "/v1/identity", "")
	wantRefused(t, heldAnswer{status: w.Code, body: w.Body.String()}, 503, "directory_unavailable")
	if res.Calls.Load() != 0 {
		t.Fatalf("a held connection was mapped per request: %d calls", res.Calls.Load())
	}
}

// A legacy-principal mark landing while a mint runs is read by the re-read
// after the mint (review M-3), and closes the mapped connection (M-2).
func TestALegacyMarkClosesTheMappedConnection(t *testing.T) {
	f := newFixture(t, 8)
	withDirectory(f, map[string]directory.Answer{alicePrincipal: answerFor(corpAlice, "alice")}, nil)
	addr, bl := serveMapped(t, f)
	c, _ := held(t, f, addr, f.alice)
	if n := bl.CloseHeld(func(principal, _ string) bool { return principal == alicePrincipal }); n != 1 {
		t.Fatalf("a mark on the legacy principal closed %d connections, want 1", n)
	}
	if !closedByPeer(c) {
		t.Fatal("not closed")
	}
}

// The re-read after a mint reads the legacy principal's mark too (review M-3).
func TestTheRereadAfterAMintReadsTheLegacyMark(t *testing.T) {
	f := newFixture(t, 8)
	withDirectory(f, map[string]directory.Answer{alicePrincipal: answerFor(corpAlice, "alice")}, nil)
	if err := f.st.PutRevocation(context.Background(), store.Revocation{Kind: store.RevocationPrincipal,
		Key: alicePrincipal, At: f.now, Origin: "test"}); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/v1/tokens", nil)
	r.TLS = f.state(f.alice)
	w := httptest.NewRecorder()
	_, cred, err := Identity(r.TLS, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if !f.b.revokedSince(w, r, corpAlice, cred, nil) || w.Code != 401 {
		t.Fatalf("revokedSince under a legacy mark: %d %s", w.Code, w.Body)
	}
}

// On a connection with no pin (a directory without Listener.Map), a
// challenge, a refresh and a mint all answer 503 directory_unavailable with
// Retry-After, the session kept, and no context moves (spec §5.7).
func TestAnUnpinnedConnectionIsTheDirectoryNotAnswering(t *testing.T) {
	f := newFixture(t, 8)
	withDirectory(f, map[string]directory.Answer{alicePrincipal: answerFor(corpAlice, "alice")}, nil)
	addr, _ := serveThrough(t, f, DefaultListenerLimits, nil) // no Map: nothing pins
	c, br := held(t, f, addr, f.alice)
	f.liveContextAt(t, "nx1", "legacy_alice", alicePrincipal, certKey(f.alice), f.now, f.now.Add(8*time.Hour))
	before, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "nx1", Username: "legacy_alice"})
	for _, tc := range []struct{ path, body string }{
		{"/v1/refresh/challenge", ""},
		{"/v1/refresh", `{"nonce":"AAAA","signature":"AAAA"}`},
		{"/v1/tokens", `{"devices":["leaf1"]}`},
	} {
		a := postOn(t, c, br, tc.path, tc.body)
		wantRefused(t, a, 503, "directory_unavailable")
		if a.retryAfter != "30" {
			t.Fatalf("%s: Retry-After %q", tc.path, a.retryAfter)
		}
	}
	after, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "nx1", Username: "legacy_alice"})
	if !after.SessionExpires.Equal(before.SessionExpires) || !after.RefreshedAt.Equal(before.RefreshedAt) {
		t.Fatalf("a context moved: %+v -> %+v", before, after)
	}
	for _, ev := range []string{"refresh", "mint"} {
		recs := eventsOf(f.records(t), ev)
		if len(recs) == 0 || recs[len(recs)-1]["reason"] != "directory_unavailable" {
			t.Fatalf("%s records: %v", ev, recs)
		}
	}
}

const groupPolicy = `
scopes:
  - {name: all_devices, match: {}}
  - {name: eos, match: {platform: arista_eos}, on_missing: exclude}
roles:
  - {name: network_admin, privilege: admin, permit: ["**"]}
  - {name: ro, privilege: readonly, permit: ["show **"]}
subjects:
  - {name: ops, group: secret-group, token_ttl: 60s}
  - {name: oncall, group: oncall-group, token_ttl: 60s, api: [explain_others, revoke_others]}
  - {name: ci, identity: ["app:ci-runner"], username: ci, token_ttl: 60s}
grants:
  - {subject: ops, scope: all_devices, roles: [ro], max_privilege: readonly}
  - {subject: oncall, scope: eos, roles: [network_admin]}
  - {subject: ci, scope: all_devices, roles: [ro]}
`

// groupFixture is a fixture whose policy is groupPolicy loaded for a
// directory, with a static resolver answering answers.
func groupFixture(t *testing.T, answers map[string]directory.Answer, err error) (*fixture, *directory.Resolver) {
	t.Helper()
	f := newFixtureWithPolicy(t, 8, testPolicy)
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if werr := os.WriteFile(path, []byte(groupPolicy), 0o600); werr != nil {
		t.Fatal(werr)
	}
	pol, lerr := policy.Load(path, policy.Env{Devices: f.inventory(), Directory: policy.DirectoryOn})
	if lerr != nil {
		t.Fatal(lerr)
	}
	f.b.Policy.Swap(pol)
	return f, withDirectory(f, answers, err)
}

// pinned is ctx with a connection that authenticated at f.now and was pinned
// to a at bind (Task 12): a request on it acts as a.Principal.
func (f *fixture) pinned(a directory.Answer) context.Context {
	return withHeldConn(context.Background(), f.now, &a)
}

func (f *fixture) mintOnPinned(a directory.Answer, devices string) *httptest.ResponseRecorder {
	return f.post(f.pinned(a), f.state(f.alice), `{"devices":`+devices+`}`, "")
}

// A group member mints on a device the group's grant selects, and the
// token carries the membership's verification time (Rulings 5, 11).
func TestAGroupMemberMints(t *testing.T) {
	a := answerFor(corpAlice, "alice")
	a.VerifiedAt = time.Now().Add(-5 * time.Minute).Truncate(time.Second)
	f, _ := groupFixture(t, map[string]directory.Answer{corpAlice: a}, nil)
	// The certificate's email SAN is alice@example.com: the pinned
	// principal, not that, is who mints.
	r := decodeMint(t, f.mintOnPinned(a, `["leaf1"]`))
	if r.Principal != corpAlice || r.Subject != "ops" || len(r.Results) != 1 || r.Results[0].Verdict != "permit" ||
		r.Results[0].Username != "alice" {
		t.Fatalf("%+v", r)
	}
	toks, err := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf1", Username: "alice"})
	if err != nil || len(toks) == 0 {
		t.Fatalf("%v %v", toks, err)
	}
	for _, tok := range toks {
		if !tok.VerifiedAt.Equal(a.VerifiedAt) || tok.Principal != corpAlice {
			t.Fatalf("token %+v, want verified_at %s", tok, a.VerifiedAt)
		}
	}
	mints := eventsOf(f.records(t), "mint")
	if len(mints) != 1 {
		t.Fatalf("%v", mints)
	}
	pol, _ := mints[0]["policy"].(map[string]any)
	auth, _ := mints[0]["auth"].(map[string]any)
	dir, _ := auth["directory"].(map[string]any)
	if mints[0]["principal"] != corpAlice || pol["subject"] != "ops" || dir["source"] != "fresh" ||
		dir["verified_at"] != decision.FormatTime(a.VerifiedAt) {
		t.Fatalf("%v", mints[0])
	}
	if strings.Contains(f.log.String(), "secret-group") {
		t.Fatal("a group reached the log")
	}
}

// A directory that answers unavailable (no server, nothing within grace;
// the resolver's own tests drive grace) refuses the whole request 503
// directory_unavailable with Retry-After, nothing minted, one mint deny
// record (Review Focus 4).
func TestAMintTheDirectoryRefusesUnavailableIsRefused(t *testing.T) {
	a := answerFor(corpAlice, "alice")
	f, _ := groupFixture(t, nil, directory.ErrUnavailable)
	w := f.mintOnPinned(a, `["leaf1","nx1"]`)
	if w.Code != 503 || w.Header().Get("Retry-After") != "30" || !strings.Contains(w.Body.String(), "directory_unavailable") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	mints := eventsOf(f.records(t), "mint")
	if len(mints) != 1 || mints[0]["verdict"] != "deny" || mints[0]["reason"] != "directory_unavailable" ||
		mints[0]["principal"] != corpAlice {
		t.Fatalf("%v", mints)
	}
	if toks, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf1", Username: "alice"}); len(toks) != 0 {
		t.Fatalf("minted %d tokens", len(toks))
	}
}

// A grace mint mints, its record says source grace and verified_at, and
// the token's VerifiedAt is that instant, not now (Ruling 11).
func TestAGraceMintCarriesItsVerification(t *testing.T) {
	a := answerFor(corpAlice, "alice")
	a.Source = directory.Grace
	a.VerifiedAt = time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	f, _ := groupFixture(t, map[string]directory.Answer{corpAlice: a}, nil)
	if r := decodeMint(t, f.mintOnPinned(a, `["leaf1"]`)); r.Results[0].Verdict != "permit" {
		t.Fatalf("%+v", r)
	}
	toks, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf1", Username: "alice"})
	if len(toks) == 0 || !toks[0].VerifiedAt.Equal(a.VerifiedAt) {
		t.Fatalf("%+v, want verified_at %s", toks, a.VerifiedAt)
	}
	mints := eventsOf(f.records(t), "mint")
	auth, _ := mints[0]["auth"].(map[string]any)
	dir, _ := auth["directory"].(map[string]any)
	if dir["source"] != "grace" || dir["verified_at"] != decision.FormatTime(a.VerifiedAt) {
		t.Fatalf("%v", mints[0])
	}
}

// Two subjects whose composition a joint check refuses: that device is
// denied composition_refused, the rest of the batch minted (Ruling 5).
func TestARefusedCompositionDeniesThatDeviceAlone(t *testing.T) {
	a := answerFor(corpAlice, "alice")
	a.GroupNames = []string{"secret-group", "oncall-group"} // ro capped at readonly + admin on eos
	f, _ := groupFixture(t, map[string]directory.Answer{corpAlice: a}, nil)
	r := decodeMint(t, f.mintOnPinned(a, `["leaf1","nx1"]`))
	if len(r.Results) != 2 || r.Results[0].Verdict != "deny" || r.Results[0].Reason != "composition_refused" ||
		r.Results[1].Verdict != "permit" {
		t.Fatalf("%+v", r.Results)
	}
	mints := eventsOf(f.records(t), "mint")
	if len(mints) != 2 || mints[0]["reason"] != "composition_refused" {
		t.Fatalf("%v", mints)
	}
}

// A directory member with no username is identity_unmapped, per device.
func TestANoUsernameIsIdentityUnmapped(t *testing.T) {
	a := answerFor(corpAlice, "")
	f, _ := groupFixture(t, map[string]directory.Answer{corpAlice: a}, nil)
	r := decodeMint(t, f.mintOnPinned(a, `["nx1"]`))
	if r.Results[0].Verdict != "deny" || r.Results[0].Reason != "identity_unmapped" {
		t.Fatalf("%+v", r.Results)
	}
}

// revoke_others held through a group lets a member revoke another
// principal; without the group it is api_right_missing (Ruling 13).
func TestRevokeOthersThroughAGroup(t *testing.T) {
	a := answerFor(corpAlice, "alice")
	a.GroupNames = []string{"oncall-group"}
	f, _ := groupFixture(t, map[string]directory.Answer{corpAlice: a}, nil)
	body := `{"principal":"user:victim@corp.example.com"}`
	w := f.call(f.pinned(a), f.state(f.alice), "POST", "/v1/tokens/revoke", body)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if r := decodeRevoke(t, w); r.By != ByPrincipal || r.Principal != "user:victim@corp.example.com" {
		t.Fatalf("%+v", r)
	}
	b := answerFor(corpAlice, "alice")
	f.b.Directory = directory.ForTestsStaticResolver(f.st, map[string]directory.Answer{corpAlice: b}, nil)
	w = f.call(f.pinned(b), f.state(f.alice), "POST", "/v1/tokens/revoke", body)
	if w.Code != 403 || !strings.Contains(w.Body.String(), "api_right_missing") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

// /v1/identity answers the subjects, groups, username, verified_at and
// source.
func TestIdentityAnswersTheMembership(t *testing.T) {
	a := answerFor(corpAlice, "alice")
	a.GroupNames = []string{"secret-group", "oncall-group"}
	a.GroupDNs = []string{"cn=secret-group,dc=corp"}
	a.VerifiedAt = time.Now().Add(-time.Minute).Truncate(time.Second)
	f, _ := groupFixture(t, map[string]directory.Answer{corpAlice: a}, nil)
	w := f.call(f.pinned(a), f.state(f.alice), "GET", "/v1/identity", "")
	var id api.Identity
	if err := json.Unmarshal(w.Body.Bytes(), &id); err != nil || w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if id.Principal != corpAlice || id.Subject != "" || !slices.Equal(id.Subjects, []string{"oncall", "ops"}) || id.Username != "alice" || id.Source != "fresh" ||
		id.VerifiedAt != decision.FormatTime(a.VerifiedAt) || !slices.Equal(id.Groups, a.GroupNames) ||
		!slices.Equal(id.GroupDNs, a.GroupDNs) || !slices.Equal(id.API, []string{"explain_others", "revoke_others"}) || len(id.Grants) != 2 {
		t.Fatalf("%+v", id)
	}
}

// POST /v1/revoke {mine: true} works with the directory unavailable and
// nothing stored: revoking oneself never asks the directory (pre-flight
// I-9). The static resolver's err is directory.ErrUnavailable and its
// Calls stays 0 across the request.
func TestRevokeMineNeedsNoDirectory(t *testing.T) {
	a := answerFor(corpAlice, "alice")
	f, res := groupFixture(t, nil, directory.ErrUnavailable)
	w := f.call(f.pinned(a), f.state(f.alice), "POST", "/v1/tokens/revoke", `{"mine":true}`)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if n := res.Calls.Load(); n != 0 {
		t.Fatalf("the directory was asked %d times", n)
	}
}

// A machine principal (an app: identity subject) mints under a directory
// without the directory being asked (pre-flight I-10).
func TestAMachinePrincipalMintsWithoutTheDirectory(t *testing.T) {
	f, res := groupFixture(t, nil, directory.ErrUnavailable)
	ci := directory.Answer{Membership: store.Membership{Principal: "app:ci-runner"}}
	r := decodeMint(t, f.mintOnPinned(ci, `["leaf1"]`))
	if r.Principal != "app:ci-runner" || r.Subject != "ci" || r.Results[0].Verdict != "permit" {
		t.Fatalf("%+v", r)
	}
	if n := res.Calls.Load(); n != 0 {
		t.Fatalf("the directory was asked %d times", n)
	}
}

// An explain about another principal resolves their membership, and the
// caller's right is read through the caller's own groups.
func TestExplainAnswersForTheirMembership(t *testing.T) {
	caller := answerFor(corpAlice, "alice")
	caller.GroupNames = []string{"oncall-group"}
	bob := answerFor("user:bob@corp.example.com", "bob")
	f, _ := groupFixture(t, map[string]directory.Answer{corpAlice: caller, bob.Principal: bob}, nil)
	w := f.call(f.pinned(caller), f.state(f.alice), "POST", "/v1/explain",
		`{"device":"nx1","principal":"user:bob@corp.example.com"}`)
	var e api.ExplainResponse
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil || w.Code != 200 || e.Verdict != "permit" || e.Subject != "ops" {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

// Explaining a principal the directory refuses answers that principal's
// reason in the body, 200, the connection kept; it is never the caller's own
// 401 and close (review I-1).
func TestExplainOfARefusedPrincipalIsAnswerNotARefusalOfTheCaller(t *testing.T) {
	caller := answerFor(corpAlice, "alice")
	caller.GroupNames = []string{"oncall-group"}
	f, _ := groupFixture(t, map[string]directory.Answer{corpAlice: caller}, nil) // no entry for ghost
	w := f.call(f.pinned(caller), f.state(f.alice), "POST", "/v1/explain",
		`{"device":"nx1","principal":"user:ghost@corp.example.com"}`)
	var e api.ExplainResponse
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil || w.Code != 200 || w.Header().Get("Connection") == "close" ||
		e.Verdict != "deny" || e.Reason != "identity_unmapped" || e.Principal != "user:ghost@corp.example.com" ||
		!strings.Contains(e.Text, "ghost") || strings.Contains(e.Text, "this certificate") {
		t.Fatalf("%d %v %s", w.Code, w.Header(), w.Body)
	}
	recs := eventsOf(f.records(t), "explain")
	if len(recs) != 1 || recs[0]["principal"] != "user:ghost@corp.example.com" || recs[0]["reason"] != "identity_unmapped" {
		t.Fatalf("%v", recs)
	}
}

// The caller's own refused membership is the caller's: 401, and the record
// names the caller, never the principal being explained (review I-2).
func TestExplainRefusalOfTheCallerNamesTheCaller(t *testing.T) {
	caller := answerFor(corpAlice, "alice")
	f, _ := groupFixture(t, map[string]directory.Answer{}, nil) // nothing for anyone
	w := f.call(f.pinned(caller), f.state(f.alice), "POST", "/v1/explain",
		`{"device":"nx1","principal":"user:bob@corp.example.com"}`)
	wantRefused(t, heldAnswer{status: w.Code, body: w.Body.String()}, 401, "identity_unmapped")
	recs := eventsOf(f.records(t), "explain")
	if len(recs) != 1 || recs[0]["principal"] != corpAlice || recs[0]["reason"] != "identity_unmapped" {
		t.Fatalf("%v", recs)
	}
}
