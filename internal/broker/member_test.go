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
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/directory"
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
	if n := res.Calls.Load(); n != 1 {
		t.Fatalf("the directory was asked %d times, want once at bind", n)
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
		alicePrincipal: answerFor(corpAlice, "alice")}, nil)
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
