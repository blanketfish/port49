package broker

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/blanketfish/port49/internal/broker/api"
	"github.com/blanketfish/port49/internal/decision"
	"github.com/blanketfish/port49/internal/directory"
	"github.com/blanketfish/port49/internal/issuer"
	"github.com/blanketfish/port49/internal/store"
	"github.com/blanketfish/port49/internal/store/memory"
	"github.com/blanketfish/port49/internal/totp"
)

// fakeDir is a directory of people by name: their entry and password.
// down makes every call ErrUnavailable, carrying the name typed in its
// text (as a server's diagnostic may: I13); state is a refusal every right
// password gets. It counts searches and binds.
type fakeDir struct {
	mu       sync.Mutex
	people   map[string]fakePerson
	down     bool
	bindDown bool  // only the bind is unavailable
	fault    error // the search's own error, as a raw LDAP one
	state    string
	result   int // the LDAP result a state refusal carries; 49 when 0
	// stateForAny gives the state refusal to a wrong password too.
	stateForAny bool
	searches    int
	binds       int
	names       []string // every name searched, as the directory saw it
}

type fakePerson struct {
	entry    directory.SignInEntry
	password string
}

func (d *fakeDir) SignInEntry(_ context.Context, name, _ string) (directory.SignInEntry, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.searches++
	d.names = append(d.names, name)
	if d.down {
		return directory.SignInEntry{}, fmt.Errorf("%w (the last: dc-01: filter (sAMAccountName=%s): busy)",
			directory.ErrUnavailable, name)
	}
	if d.fault != nil {
		return directory.SignInEntry{}, d.fault
	}
	p, ok := d.people[name]
	if !ok {
		return directory.SignInEntry{}, fmt.Errorf("%w: no entry", directory.ErrUnmapped)
	}
	return p.entry, nil
}

func (d *fakeDir) CheckPassword(_ context.Context, _ directory.Server, dn, password string) error {
	if strings.TrimSpace(password) == "" {
		return directory.ErrEmptyPassword
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.down || d.bindDown {
		return fmt.Errorf("%w: dc-01", directory.ErrUnavailable)
	}
	d.binds++
	for _, p := range d.people {
		switch {
		case p.entry.DN != dn:
		case d.stateForAny && (d.state != "" || d.result != 0):
			// A directory that gives a locked account's answer to any password
			// (Samba's 775, OpenLDAP's accountLocked with UseLockout TRUE; L67).
			res := d.result
			if res == 0 {
				res = 49
			}
			return &directory.PasswordRefusal{Result: res, Data: d.state}
		case p.password != password:
			return &directory.PasswordRefusal{Result: 49, Data: "52e"}
		case d.state != "" || d.result != 0:
			res := d.result
			if res == 0 {
				res = 49
			}
			return &directory.PasswordRefusal{Result: res, Data: d.state}
		default:
			return nil
		}
	}
	return &directory.PasswordRefusal{Result: 49, Data: "525"}
}

func (d *fakeDir) bindCount() int   { d.mu.Lock(); defer d.mu.Unlock(); return d.binds }
func (d *fakeDir) searchCount() int { d.mu.Lock(); defer d.mu.Unlock(); return d.searches }
func (d *fakeDir) setDown(v bool)   { d.mu.Lock(); d.down = v; d.mu.Unlock() }

// lineBuffer is the broker's own lines (the standard logger's), which the
// fixture's decision log does not hold.
type lineBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lineBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lineBuffer) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

// signInLines is each sign-in fixture's lineBuffer.
var signInLines sync.Map

// logs is everything f's broker wrote: its decision records, then its lines.
func (f *fixture) logs() string {
	out := f.log.String()
	if l, ok := signInLines.Load(f); ok {
		out += l.(*lineBuffer).String()
	}
	return out
}

// newSignInFixture is a password-only broker (withPasswordSignIn, Task 8)
// over the memory store and an in-memory enrollment store with its mark,
// with alice in the directory: entry uuid:alice, password "right", created
// a year ago (no new-entry window), and no other window open. Its lines are
// captured (f.logs).
func newSignInFixture(t *testing.T) (*fixture, *fakeDir) {
	t.Helper()
	f := newFixture(t, 8)
	lines := &lineBuffer{}
	signInLines.Store(f, lines)
	prev := log.Writer()
	log.SetOutput(lines)
	t.Cleanup(func() { log.SetOutput(prev); signInLines.Delete(f) })
	f.withPasswordSignIn(t)
	f.b.Enrollments = memory.NewEnrollments(f.b.Now)
	if err := f.b.Enrollments.CreateEnrollmentMark(context.Background(), store.EnrollmentMark{CreatedAt: f.now}); err != nil {
		t.Fatal(err)
	}
	if err := f.b.CheckEnrollmentStore(context.Background()); err != nil {
		t.Fatal(err)
	}
	dir := &fakeDir{people: map[string]fakePerson{"alice": {password: "right", entry: directory.SignInEntry{
		Identity: directory.Identity{DN: "uid=alice,ou=Staff,dc=example,dc=com", EntryID: "uuid:alice",
			Principal: alicePrincipal, Username: "alice"},
		Server:    directory.Server{URI: "ldaps://dc-01.example.com"},
		CreatedAt: f.now.Add(-365 * 24 * time.Hour)}}}}
	f.b.SignInDirectory = dir
	return f, dir
}

// csrOf is a CSR for key as a sign-in body carries it: base64url DER (I10).
func csrOf(t *testing.T, key crypto.Signer) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(der)
}

// signIn posts req to /v1/sign-in with no client certificate, from
// httptest's 192.0.2.1:1234.
func (f *fixture) signIn(t *testing.T, req api.SignInRequest) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(req)
	return f.call(context.Background(), nil, "POST", "/v1/sign-in", string(body))
}

func (f *fixture) confirm(t *testing.T, req api.ConfirmRequest) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(req)
	return f.call(context.Background(), nil, "POST", "/v1/sign-in/confirm", string(body))
}

// enrolled writes an active second factor for principal on entry, with a
// fresh secret, and returns the secret.
func (f *fixture) enrolled(t *testing.T, principal, entry string) []byte {
	t.Helper()
	secret, err := totp.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.b.Enrollments.SwapSecondFactor(context.Background(), store.SecondFactor{Principal: principal,
		State: store.SecondFactorActive, EntryID: entry, Secret: secret, EnrolledAt: f.now.Add(-time.Hour),
		EnrolledFrom: "192.0.2.0/32"}, 0); err != nil {
		t.Fatal(err)
	}
	return secret
}

// codeAt is secret's code at at (M9).
func codeAt(t *testing.T, secret []byte, at time.Time) string {
	t.Helper()
	c, err := totp.Code(secret, at)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// wrongCode is a six-digit code that is not secret's at at.
func wrongCode(t *testing.T, secret []byte, at time.Time) string {
	if codeAt(t, secret, at) == "000000" {
		return "000001"
	}
	return "000000"
}

func (f *fixture) lastIssue(t *testing.T) map[string]any {
	t.Helper()
	recs := eventsOf(f.records(t), decision.EventIssue)
	if len(recs) == 0 {
		t.Fatal("no issue record")
	}
	return recs[len(recs)-1]
}

func signInOf(rec map[string]any) map[string]any { m, _ := rec["sign_in"].(map[string]any); return m }

func (f *fixture) outcome(o string) float64 {
	return testutil.ToFloat64(f.b.Metrics.SignIns.WithLabelValues(o))
}

// counted is the attempts held under key, cleared as it is read.
func (f *fixture) counted(t *testing.T, key string) int {
	t.Helper()
	n, err := f.b.Store.ClearSignInAttempts(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

const aliceSource = "source:192.0.2.1/32"

// The whole path: the code, then the password, then 9b's certificate,
// recorded with auth.directory_password; the principal's count cleared,
// the source's attempt taken back, the step taken.
func TestADirectorySignInIsIssuedACertificate(t *testing.T) {
	f, dir := newSignInFixture(t)
	secret := f.enrolled(t, alicePrincipal, "uuid:alice")
	w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: codeAt(t, secret, f.now),
		CSR: csrOf(t, newECKey(t))})
	if w.Code != 200 {
		t.Fatalf("%s", shown(w))
	}
	var resp api.IssueResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(resp.Certificate))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	s, err := issuer.ReadSignIn(cert)
	if err != nil || s.Method != issuer.MethodDirectoryPassword || s.Principal != alicePrincipal ||
		s.Subject != issuer.EntrySubject("uuid:alice") || !slices.Equal(s.AMR, []string{"pwd", "otp"}) || s.Issuer != "" {
		t.Fatalf("%+v %v", s, err)
	}
	if dir.bindCount() != 1 || resp.Principal != alicePrincipal {
		t.Fatalf("%d binds, principal %s", dir.bindCount(), resp.Principal)
	}
	rec := f.lastIssue(t)
	auth, _ := rec["auth"].(map[string]any)
	dp, _ := auth["directory_password"].(map[string]any)
	if rec["verdict"] != "permit" || rec["reason"] != "certificate_issued" || dp == nil || auth["oidc"] != nil ||
		dp["entry_sha256"] != strings.TrimPrefix(issuer.EntrySubject("uuid:alice"), "entry-sha256:") ||
		signInOf(rec)["source"] != "192.0.2.1/32" || signInOf(rec)["failed"] != nil {
		t.Fatalf("%v", rec)
	}
	if n := f.counted(t, "principal:"+alicePrincipal); n != 0 {
		t.Fatalf("the principal's count holds %d", n)
	}
	if n := f.counted(t, aliceSource); n != 0 {
		t.Fatalf("the source's count holds %d", n)
	}
	got, _ := f.b.Enrollments.GetSecondFactor(context.Background(), alicePrincipal)
	if got.LastStep != f.now.Unix()/30 || f.outcome("issued") != 1 {
		t.Fatalf("step %d, issued %v", got.LastStep, f.outcome("issued"))
	}
}

// The code before the password (D4): a wrong code never reaches the directory.
func TestAWrongCodeNeverReachesTheDirectory(t *testing.T) {
	f, dir := newSignInFixture(t)
	secret := f.enrolled(t, alicePrincipal, "uuid:alice")
	w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: wrongCode(t, secret, f.now),
		CSR: csrOf(t, newECKey(t))})
	if w.Code != 401 || apiError(w) != "sign_in_refused" || dir.bindCount() != 0 ||
		signInOf(f.lastIssue(t))["failed"] != "second_factor" || f.outcome("refused") != 1 {
		t.Fatalf("%s, %d binds", shown(w), dir.bindCount())
	}
}

// One answer for a wrong name, password or code (ruling 7); the record
// says which, and names no principal for an unknown name.
func TestOneRefusalForTheThree(t *testing.T) {
	var bodies []string
	for _, tc := range []struct {
		name, password string
		rightCode      bool
		failed         string
		principal      any
	}{
		{"nobody", "right", true, "name", nil},
		{"alice", "wrong", true, "password", alicePrincipal},
		{"alice", "right", false, "second_factor", alicePrincipal},
	} {
		f, _ := newSignInFixture(t)
		secret := f.enrolled(t, alicePrincipal, "uuid:alice")
		code := codeAt(t, secret, f.now)
		if !tc.rightCode {
			code = wrongCode(t, secret, f.now)
		}
		w := f.signIn(t, api.SignInRequest{Name: tc.name, Password: tc.password, Code: code, CSR: csrOf(t, newECKey(t))})
		rec := f.lastIssue(t)
		if w.Code != 401 || apiError(w) != "sign_in_refused" || rec["reason"] != "sign_in_refused" ||
			signInOf(rec)["failed"] != tc.failed || rec["principal"] != tc.principal {
			t.Fatalf("%s: %s %v", tc.failed, shown(w), rec)
		}
		bodies = append(bodies, w.Body.String())
	}
	if bodies[0] != bodies[1] || bodies[1] != bodies[2] {
		t.Fatalf("the three answers differ:\n%s", strings.Join(bodies, "\n"))
	}
}

// A name that maps to no entry never reaches an answer, a line, a record or
// the store, hashed included, even when the directory's error carries it
// (Review Focus 2; I13).
func TestAnUnknownNameIsNeverLogged(t *testing.T) {
	const typed = "hunter2-typed-at-the-name-prompt"
	sum := sha256.Sum256([]byte(typed))
	for _, down := range []bool{false, true} {
		f, dir := newSignInFixture(t)
		dir.setDown(down)
		w := f.signIn(t, api.SignInRequest{Name: typed, Password: "x", Code: "123456", CSR: csrOf(t, newECKey(t))})
		if w.Code == 200 || strings.Contains(w.Body.String(), typed) || strings.Contains(f.logs(), typed) ||
			strings.Contains(f.logs(), fmt.Sprintf("%x", sum)) {
			t.Fatalf("down %v: the name typed reached the answer or the log", down)
		}
		if ps, _ := f.b.Enrollments.SecondFactorPrincipals(context.Background()); len(ps) != 0 {
			t.Fatal("a record was written for it")
		}
	}
}

// Nothing secret reaches a record, an answer other than the person's own
// 202, or a line: the password, the code, the secret, the URI, the handle.
func TestNoSecretIsLogged(t *testing.T) {
	f, _ := newSignInFixture(t)
	f.b.PasswordSignIn.OpenUntil = f.now.Add(time.Hour)
	const password = "correct-horse-battery-staple"
	f.b.SignInDirectory.(*fakeDir).people["alice"] = fakePerson{password: password,
		entry: f.b.SignInDirectory.(*fakeDir).people["alice"].entry}
	w := f.signIn(t, api.SignInRequest{Name: "alice", Password: password, CSR: csrOf(t, newECKey(t))})
	var er api.EnrollResponse
	if w.Code != 202 || json.Unmarshal(w.Body.Bytes(), &er) != nil || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%s", shown(w))
	}
	u, _ := url.Parse(er.Enroll.URI)
	b32 := u.Query().Get("secret")
	secret, _ := totp.DecodeSecret(b32)
	code := codeAt(t, secret, f.now)
	if w := f.confirm(t, api.ConfirmRequest{Handle: er.Enroll.Handle, Code: code, CSR: csrOf(t, newECKey(t))}); w.Code != 200 {
		t.Fatalf("%s", shown(w))
	}
	f.advance(time.Minute)
	w = f.signIn(t, api.SignInRequest{Name: "alice", Password: password, Code: "999999", CSR: csrOf(t, newECKey(t))})
	for _, s := range []string{password, code, b32, er.Enroll.URI, er.Enroll.Handle, "otpauth"} {
		if strings.Contains(f.logs(), s) || strings.Contains(w.Body.String(), s) {
			t.Fatalf("%q reached the log or a later answer", s)
		}
	}
}

// An empty password is refused before the directory, and counted against
// the source (Review Focus 1; M7).
func TestAnEmptyPasswordIsRefusedAndCounted(t *testing.T) {
	f, dir := newSignInFixture(t)
	f.enrolled(t, alicePrincipal, "uuid:alice")
	w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "   ", Code: "123456", CSR: csrOf(t, newECKey(t))})
	rec := f.lastIssue(t)
	if w.Code != 401 || apiError(w) != "sign_in_refused" || dir.bindCount() != 0 || dir.searchCount() != 0 ||
		signInOf(rec)["failed"] != "password" || rec["principal"] != nil {
		t.Fatalf("%s %v", shown(w), rec)
	}
	if n := f.counted(t, aliceSource); n != 1 {
		t.Fatalf("the source counted %d", n)
	}
}

// Throttled: the sixth failure for a principal is 429 with Retry-After and
// the unlock command, names no principal, checks nothing, and the held
// certificate still mints (I3).
func TestThePrincipalLimit(t *testing.T) {
	f, dir := newSignInFixture(t)
	secret := f.enrolled(t, alicePrincipal, "uuid:alice")
	c := f.issuedDirectory(t, alicePrincipal, "uuid:alice")
	bad := wrongCode(t, secret, f.now)
	for i := range 5 {
		if w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: bad, CSR: csrOf(t, newECKey(t))}); w.Code != 401 {
			t.Fatalf("attempt %d: %s", i+1, shown(w))
		}
	}
	w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: codeAt(t, secret, f.now), CSR: csrOf(t, newECKey(t))})
	if w.Code != 429 || apiError(w) != "sign_in_throttled" || w.Header().Get("Retry-After") == "" ||
		!strings.Contains(shown(w), "port49 directory unlock") || strings.Contains(w.Body.String(), "alice@example.com") ||
		strings.Contains(w.Body.String(), "alice") ||
		signInOf(f.lastIssue(t))["failed"] != "principal_limit" || dir.bindCount() != 0 || f.outcome("throttled") != 1 {
		t.Fatalf("%s", shown(w))
	}
	if w := f.postAt(context.Background(), f.issuedState(c), mintLeaf1, "", f.now); w.Code != 200 {
		t.Fatalf("a holder's mint: %s", shown(w))
	}
}

// The source limit, before any directory call; 0 turns it off and writes
// no count (M6).
func TestTheSourceLimit(t *testing.T) {
	f, dir := newSignInFixture(t)
	f.b.PasswordSignIn.FailuresPerSource = 3
	for i := range 3 {
		if w := f.signIn(t, api.SignInRequest{Name: fmt.Sprintf("nobody%d", i), Password: "x", Code: "123456",
			CSR: csrOf(t, newECKey(t))}); w.Code != 401 {
			t.Fatalf("%s", shown(w))
		}
	}
	searches := dir.searchCount()
	w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: "123456", CSR: csrOf(t, newECKey(t))})
	if w.Code != 429 || signInOf(f.lastIssue(t))["failed"] != "source_limit" || dir.searchCount() != searches {
		t.Fatalf("%s", shown(w))
	}
	f, dir = newSignInFixture(t)
	f.b.PasswordSignIn.FailuresPerSource = 0
	for i := range 10 {
		if w := f.signIn(t, api.SignInRequest{Name: fmt.Sprintf("nobody%d", i), Password: "x", Code: "123456",
			CSR: csrOf(t, newECKey(t))}); w.Code != 401 {
			t.Fatalf("off, attempt %d: %s", i+1, shown(w))
		}
	}
	if n := f.counted(t, aliceSource); n != 0 {
		t.Fatalf("off, yet counted %d (M6)", n)
	}
}

// Fifty parallel wrong codes judge at most five (Review Focus 3).
func TestParallelAttemptsCannotPassThePrincipalLimit(t *testing.T) {
	f, dir := newSignInFixture(t)
	f.b.PasswordSignIn.FailuresPerSource = 0
	secret := f.enrolled(t, alicePrincipal, "uuid:alice")
	bad := wrongCode(t, secret, f.now)
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: bad, CSR: csrOf(t, newECKey(t))})
			mu.Lock()
			codes[w.Code]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if codes[401] > 5 || codes[401]+codes[429] != 50 || dir.bindCount() != 0 {
		t.Fatalf("%v, %d binds", codes, dir.bindCount())
	}
}

// signInStoreDown fails every attempt count.
type signInStoreDown struct{ store.Store }

func (signInStoreDown) NoteSignInAttempt(context.Context, string, time.Duration) (int, time.Time, error) {
	return 0, time.Time{}, store.ErrUnavailable
}

// A store that does not answer refuses, 503 store_unavailable, nothing checked.
func TestAStoreErrorRefusesTheSignIn(t *testing.T) {
	f, dir := newSignInFixture(t)
	f.b.Store = signInStoreDown{f.b.Store}
	w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: "123456", CSR: csrOf(t, newECKey(t))})
	if w.Code != 503 || apiError(w) != "store_unavailable" || dir.searchCount() != 0 || dir.bindCount() != 0 ||
		f.outcome("store_unavailable") != 1 {
		t.Fatalf("%s", shown(w))
	}
}

// The 3am case (owner's ruling 4): the directory down, a sign-in is 503
// directory_unavailable saying anyone signed in keeps working, and a held
// directory-sign-in certificate mints.
func TestTheDirectoryDownSignInSaysSoAndHoldersMint(t *testing.T) {
	f, dir := newSignInFixture(t)
	c := f.issuedDirectory(t, alicePrincipal, "uuid:alice")
	dir.setDown(true)
	w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: "123456", CSR: csrOf(t, newECKey(t))})
	if w.Code != 503 || apiError(w) != "directory_unavailable" || !strings.Contains(shown(w), "keeps working") ||
		w.Header().Get("Retry-After") == "" || f.outcome("directory_unavailable") != 1 {
		t.Fatalf("%s", shown(w))
	}
	if w := f.postAt(context.Background(), f.issuedState(c), mintLeaf1, "", f.now); w.Code != 200 {
		t.Fatalf("a holder's mint: %s", shown(w))
	}
}

// A fault in the broker's own search (the bind account's ACL changed: LDAP 50)
// is the directory's, not the person's wrong name: 503 directory_unavailable,
// the counts given back, one line with the result code alone, and the name
// typed nowhere (R8).
func TestABrokerSideSearchFaultIsNotTheNamesFault(t *testing.T) {
	f, dir := newSignInFixture(t)
	dir.fault = ldap.NewError(50, errors.New("insufficient access for (sAMAccountName=typedname)"))
	for range 2 {
		w := f.signIn(t, api.SignInRequest{Name: "typedname", Password: "right", Code: "123456", CSR: csrOf(t, newECKey(t))})
		if w.Code != 503 || apiError(w) != "directory_unavailable" || strings.Contains(shown(w), "typedname") {
			t.Fatalf("%s", shown(w))
		}
	}
	if n := f.counted(t, aliceSource); n != 0 {
		t.Fatalf("the source count was not given back: %d", n)
	}
	logs := f.logs()
	if strings.Contains(logs, "typedname") || strings.Contains(logs, "insufficient") {
		t.Fatalf("the name or the server's text is in the log:\n%s", logs)
	}
	if got := strings.Count(logs, "result code 50"); got != 1 {
		t.Fatalf("%d lines name code 50 (want one, said once):\n%s", got, logs)
	}
	if f.outcome("directory_unavailable") != 2 || f.outcome("refused") != 0 {
		t.Fatalf("outcomes: unavailable %v refused %v", f.outcome("directory_unavailable"), f.outcome("refused"))
	}
	// A non-LDAP error says its type alone.
	dir.fault = fmt.Errorf("boom for typedname")
	f.advance(sayEvery + time.Second)
	if w := f.signIn(t, api.SignInRequest{Name: "typedname", Password: "right", Code: "123456", CSR: csrOf(t, newECKey(t))}); w.Code != 503 {
		t.Fatalf("%s", shown(w))
	}
	if logs := f.logs(); strings.Contains(logs, "typedname") || !strings.Contains(logs, "*fmt.wrapError") && !strings.Contains(logs, "*errors.errorString") {
		t.Fatalf("log:\n%s", logs)
	}
}

// A search that runs out of the hold budget is the directory not answering in
// time, not a refusal of the broker's own search: the same 503, the line says
// so, and the error's text and the name typed are in no log line (N2).
func TestASearchThatRunsOutOfTimeIsTheDirectoryNotAnswering(t *testing.T) {
	f, dir := newSignInFixture(t)
	dir.fault = fmt.Errorf("search for typedname: %w", context.DeadlineExceeded)
	w := f.signIn(t, api.SignInRequest{Name: "typedname", Password: "right", Code: "123456", CSR: csrOf(t, newECKey(t))})
	if w.Code != 503 || apiError(w) != "directory_unavailable" {
		t.Fatalf("%s", shown(w))
	}
	logs := f.logs()
	if strings.Contains(logs, "refused the broker's own search") || strings.Contains(logs, "typedname") ||
		!strings.Contains(logs, "the directory did not answer") {
		t.Fatalf("log:\n%s", logs)
	}
	if n := f.counted(t, aliceSource); n != 0 {
		t.Fatalf("the source count was not given back: %d", n)
	}
}

// A phone's clock off by 90s: refused, the skew said, counted, nothing
// bound; by 30s: accepted.
func TestAClockOffIsSaid(t *testing.T) {
	f, dir := newSignInFixture(t)
	secret := f.enrolled(t, alicePrincipal, "uuid:alice")
	w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: codeAt(t, secret, f.now.Add(-90*time.Second)),
		CSR: csrOf(t, newECKey(t))})
	rec := f.lastIssue(t)
	if w.Code != 401 || !strings.Contains(shown(w), "about 2 minutes off") || dir.bindCount() != 0 ||
		signInOf(rec)["failed"] != "second_factor_skew" || signInOf(rec)["skew_seconds"] != float64(-90) {
		t.Fatalf("%s %v", shown(w), rec)
	}
	f.advance(30 * time.Second)
	if w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: codeAt(t, secret, f.now.Add(-30*time.Second)),
		CSR: csrOf(t, newECKey(t))}); w.Code != 200 {
		t.Fatalf("30s off: %s", shown(w))
	}
}

// A code taken once; two sign-ins racing one code issue once and reach the
// directory once (Review Focus 5; I1).
func TestTwoSignInsWithOneCodeIssueOnce(t *testing.T) {
	f, dir := newSignInFixture(t)
	secret := f.enrolled(t, alicePrincipal, "uuid:alice")
	code := codeAt(t, secret, f.now)
	var wg sync.WaitGroup
	got := make(chan int, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got <- f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: code, CSR: csrOf(t, newECKey(t))}).Code
		}()
	}
	wg.Wait()
	close(got)
	var codes []int
	for c := range got {
		codes = append(codes, c)
	}
	slices.Sort(codes)
	if !slices.Equal(codes, []int{200, 401}) || dir.bindCount() != 1 {
		t.Fatalf("%v, %d binds", codes, dir.bindCount())
	}
	if w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: code, CSR: csrOf(t, newECKey(t))}); w.Code != 401 {
		t.Fatalf("a replay: %s", shown(w))
	}
}

// unreadableEnrollments answers GetSecondFactor as a record under a key
// no one holds does, and records any write.
type unreadableEnrollments struct {
	store.Enrollments
	wrote bool
}

func (u *unreadableEnrollments) GetSecondFactor(context.Context, string) (store.SecondFactor, error) {
	return store.SecondFactor{}, errors.New("crypt: opening second factor: crypt: sealed under an unknown key")
}

func (u *unreadableEnrollments) SwapSecondFactor(context.Context, store.SecondFactor, uint64) error {
	u.wrote = true
	return nil
}

// A record that will not open refuses, 503, naming reset-second-factor,
// and never reads as "not enrolled" (Review Focus 4).
func TestAnUnreadableSecondFactorRefusesTheSignIn(t *testing.T) {
	f, dir := newSignInFixture(t)
	f.b.PasswordSignIn.OpenUntil = f.now.Add(time.Hour) // a window is open: "not enrolled" would enroll
	u := &unreadableEnrollments{Enrollments: f.b.Enrollments}
	f.b.Enrollments = u
	w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: "123456", CSR: csrOf(t, newECKey(t))})
	if w.Code != 503 || apiError(w) != "store_unavailable" || !strings.Contains(shown(w), "reset-second-factor") ||
		dir.bindCount() != 0 || u.wrote {
		t.Fatalf("%s, %d binds, wrote %v", shown(w), dir.bindCount(), u.wrote)
	}
}

// A second factor of another entry refuses with the one sentence, and the
// broker's log names reset-second-factor (ruling 12; I12).
func TestASecondFactorOfAnotherEntryRefuses(t *testing.T) {
	f, dir := newSignInFixture(t)
	secret := f.enrolled(t, alicePrincipal, "uuid:old")
	w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: codeAt(t, secret, f.now), CSR: csrOf(t, newECKey(t))})
	if w.Code != 401 || apiError(w) != "sign_in_refused" || strings.Contains(w.Body.String(), "another directory entry") ||
		!strings.Contains(f.logs(), "reset-second-factor") || dir.bindCount() != 0 ||
		signInOf(f.lastIssue(t))["failed"] != "second_factor" {
		t.Fatalf("%s", shown(w))
	}
}

// The directory's state, past the code, is said (ruling 7); with a wrong
// code it is never reached.
func TestTheDirectoryStateIsSaidPastTheCode(t *testing.T) {
	for data, words := range map[string]string{"532": "expired", "773": "must be changed", "533": "disabled",
		"775": "locked"} {
		f, dir := newSignInFixture(t)
		secret := f.enrolled(t, alicePrincipal, "uuid:alice")
		dir.state = data
		w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: codeAt(t, secret, f.now), CSR: csrOf(t, newECKey(t))})
		rec := signInOf(f.lastIssue(t))
		if w.Code != 401 || !strings.Contains(shown(w), words) || rec["failed"] != "directory_state" ||
			rec["directory_result"] != float64(49) || rec["directory_data"] != data {
			t.Fatalf("%s: %s %v", data, shown(w), rec)
		}
		f.advance(time.Minute)
		w = f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: wrongCode(t, secret, f.now), CSR: csrOf(t, newECKey(t))})
		if strings.Contains(shown(w), words) {
			t.Fatalf("%s said without the code", data)
		}
	}
}

// An enrolling person has proven nothing but a password the directory has
// not yet judged: a state that a directory also gives to a wrong password
// (775, account_locked, a 53) must not be said to them, or any password
// would learn which accounts are locked. They get the sentence a wrong
// password gets; the record still keeps the state and its data (L67; Q1).
func TestAnEnrollingPersonIsNotToldAnUnprovenState(t *testing.T) {
	for _, tc := range []struct {
		data   string
		result int
	}{{"775", 0}, {"account_locked", 0}, {"", 53}} {
		f, dir := newSignInFixture(t)
		f.b.PasswordSignIn.OpenUntil = f.now.Add(time.Hour)
		dir.state, dir.result, dir.stateForAny = tc.data, tc.result, true
		w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "not-the-password", CSR: csrOf(t, newECKey(t))})
		rec := signInOf(f.lastIssue(t))
		if w.Code != 401 || apiError(w) != "sign_in_refused" || !strings.Contains(shown(w), refusedText) ||
			strings.Contains(shown(w), "locked") || strings.Contains(shown(w), "refuses this account") {
			t.Fatalf("%q/%d: %s", tc.data, tc.result, shown(w))
		}
		wantData := any(tc.data)
		if tc.data == "" {
			wantData = nil
		}
		if rec["failed"] != "directory_state" || rec["directory_data"] != wantData {
			t.Fatalf("%q/%d: the record lost the state: %v", tc.data, tc.result, rec)
		}
	}
}

// An enrolling person is told a state the directory gives only after the
// password checked out (533 here).
func TestAnEnrollingPersonIsToldAProvenState(t *testing.T) {
	f, dir := newSignInFixture(t)
	f.b.PasswordSignIn.OpenUntil = f.now.Add(time.Hour)
	dir.state, dir.stateForAny = "533", true
	w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", CSR: csrOf(t, newECKey(t))})
	if w.Code != 401 || !strings.Contains(shown(w), "your directory account is disabled") {
		t.Fatalf("%s", shown(w))
	}
}

// An enrolled person with the right code has proven a second factor, so a
// locked account is said to them even when the password is wrong (ruling 7).
func TestAnEnrolledPersonPastTheCodeIsToldALockedAccount(t *testing.T) {
	f, dir := newSignInFixture(t)
	secret := f.enrolled(t, alicePrincipal, "uuid:alice")
	dir.state, dir.stateForAny = "775", true
	w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "not-the-password", Code: codeAt(t, secret, f.now), CSR: csrOf(t, newECKey(t))})
	if w.Code != 401 || !strings.Contains(shown(w), "your directory account is locked") {
		t.Fatalf("%s", shown(w))
	}
}

// A 53 (unwilling to perform) carries no data code: its own sentence, the
// result alone recorded.
func TestAnUnwillingDirectoryIsSaid(t *testing.T) {
	f, dir := newSignInFixture(t)
	secret := f.enrolled(t, alicePrincipal, "uuid:alice")
	dir.result = 53
	w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: codeAt(t, secret, f.now), CSR: csrOf(t, newECKey(t))})
	rec := signInOf(f.lastIssue(t))
	if w.Code != 401 || !strings.Contains(shown(w), "your directory refuses this account now: ask your directory administrator") ||
		rec["failed"] != "directory_state" || rec["directory_result"] != float64(53) || rec["directory_data"] != nil {
		t.Fatalf("%s %v", shown(w), rec)
	}
}

// enrollAlice is a 202 for alice with the right password, and the secret
// its URI carries.
func enrollAlice(t *testing.T, f *fixture) (api.Enrollment, []byte) {
	t.Helper()
	w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", CSR: csrOf(t, newECKey(t))})
	var er api.EnrollResponse
	if w.Code != 202 || json.Unmarshal(w.Body.Bytes(), &er) != nil {
		t.Fatalf("%s", shown(w))
	}
	u, err := url.Parse(er.Enroll.URI)
	if err != nil || u.Scheme != "otpauth" || u.Host != "totp" {
		t.Fatalf("%q", er.Enroll.URI)
	}
	secret, err := totp.DecodeSecret(u.Query().Get("secret"))
	if err != nil {
		t.Fatal(err)
	}
	return er.Enroll, secret
}

// Enrollment: inside the new-entry window, the right password answers 202
// with a URI and a handle, nothing issued or recorded; confirm with the
// first code issues, records enroll permit second_factor_enrolled, and the
// record is active with enrolled_from the source.
func TestANewEntryEnrolls(t *testing.T) {
	f, dir := newSignInFixture(t)
	p := dir.people["alice"]
	p.entry.CreatedAt = f.now.Add(-time.Hour)
	dir.people["alice"] = p
	e, secret := enrollAlice(t, f)
	if e.Handle == "" || e.ConfirmBy != decision.FormatTime(f.now.Add(10*time.Minute)) ||
		len(eventsOf(f.records(t), decision.EventIssue)) != 0 || f.outcome("enrollment_started") != 1 {
		t.Fatalf("%+v", e)
	}
	w := f.confirm(t, api.ConfirmRequest{Handle: e.Handle, Code: codeAt(t, secret, f.now), CSR: csrOf(t, newECKey(t))})
	if w.Code != 200 {
		t.Fatalf("%s", shown(w))
	}
	enr := eventsOf(f.records(t), decision.EventEnroll)
	if len(enr) != 1 || enr[0]["verdict"] != "permit" || enr[0]["reason"] != "second_factor_enrolled" ||
		signInOf(enr[0])["source"] != "192.0.2.1/32" || f.lastIssue(t)["reason"] != "certificate_issued" {
		t.Fatalf("%v", enr)
	}
	got, err := f.b.Enrollments.GetSecondFactor(context.Background(), alicePrincipal)
	if err != nil || got.State != store.SecondFactorActive || got.EnrolledFrom != "192.0.2.1/32" ||
		got.EntryID != "uuid:alice" || got.LastStep != f.now.Unix()/30 || f.outcome("enrolled") != 1 {
		t.Fatalf("%+v %v", got, err)
	}
}

// The rollout window, a reopened record, and reset --all's window each open
// enrollment; outside every window any password is 403 enrollment_closed
// and nothing is bound (C5).
func TestEnrollmentWindows(t *testing.T) {
	ctx := context.Background()
	for name, open := range map[string]func(f *fixture){
		"rollout": func(f *fixture) { f.b.PasswordSignIn.OpenUntil = f.now.Add(time.Hour) },
		"reopened": func(f *fixture) {
			_ = f.b.Enrollments.SwapSecondFactor(ctx, store.SecondFactor{Principal: alicePrincipal,
				State: store.SecondFactorReopened, Until: f.now.Add(time.Hour)}, 0)
		},
		"reset --all": func(f *fixture) {
			_ = f.b.Enrollments.PutEnrollmentMark(ctx, store.EnrollmentMark{CreatedAt: f.now, ReopenAllUntil: f.now.Add(time.Hour)})
		},
	} {
		f, _ := newSignInFixture(t)
		open(f)
		if w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", CSR: csrOf(t, newECKey(t))}); w.Code != 202 {
			t.Fatalf("%s: %s", name, shown(w))
		}
	}
	for _, pw := range []string{"right", "wrong"} {
		f, dir := newSignInFixture(t)
		w := f.signIn(t, api.SignInRequest{Name: "alice", Password: pw, CSR: csrOf(t, newECKey(t))})
		if w.Code != 403 || apiError(w) != "enrollment_closed" || dir.bindCount() != 0 ||
			signInOf(f.lastIssue(t))["failed"] != "enrollment" || f.outcome("enrollment_closed") != 1 {
			t.Fatalf("closed, %s password: %s, %d binds", pw, shown(w), dir.bindCount())
		}
	}
}

// A wrong first code puts the handle back; a handle confirms once; an
// expired handle is refused.
func TestTheHandle(t *testing.T) {
	f, _ := newSignInFixture(t)
	f.b.PasswordSignIn.OpenUntil = f.now.Add(time.Hour)
	e, secret := enrollAlice(t, f)
	if w := f.confirm(t, api.ConfirmRequest{Handle: e.Handle, Code: wrongCode(t, secret, f.now), CSR: csrOf(t, newECKey(t))}); w.Code != 401 {
		t.Fatalf("a wrong code: %s", shown(w))
	}
	if w := f.confirm(t, api.ConfirmRequest{Handle: e.Handle, Code: codeAt(t, secret, f.now), CSR: csrOf(t, newECKey(t))}); w.Code != 200 {
		t.Fatalf("the handle was not put back: %s", shown(w))
	}
	f.advance(30 * time.Second)
	if w := f.confirm(t, api.ConfirmRequest{Handle: e.Handle, Code: codeAt(t, secret, f.now), CSR: csrOf(t, newECKey(t))}); w.Code != 401 ||
		!strings.Contains(shown(w), "port49 login") {
		t.Fatalf("a handle confirmed twice: %s", shown(w))
	}
	f, _ = newSignInFixture(t)
	f.b.PasswordSignIn.OpenUntil = f.now.Add(time.Hour)
	e, secret = enrollAlice(t, f)
	f.advance(11 * time.Minute)
	if w := f.confirm(t, api.ConfirmRequest{Handle: e.Handle, Code: codeAt(t, secret, f.now), CSR: csrOf(t, newECKey(t))}); w.Code != 401 {
		t.Fatalf("an expired handle: %s", shown(w))
	}
}

// A confirm throttled by the principal's limit keeps its handle (M10):
// after an unlock, the same handle confirms.
func TestAThrottledConfirmKeepsTheHandle(t *testing.T) {
	ctx := context.Background()
	f, _ := newSignInFixture(t)
	f.b.PasswordSignIn.OpenUntil = f.now.Add(time.Hour)
	e, secret := enrollAlice(t, f)
	for range 5 {
		if _, _, err := f.b.Store.NoteSignInAttempt(ctx, "principal:"+alicePrincipal, f.b.PasswordSignIn.Window); err != nil {
			t.Fatal(err)
		}
	}
	if w := f.confirm(t, api.ConfirmRequest{Handle: e.Handle, Code: codeAt(t, secret, f.now), CSR: csrOf(t, newECKey(t))}); w.Code != 429 {
		t.Fatalf("over the limit: %s", shown(w))
	}
	f.counted(t, "principal:"+alicePrincipal)
	if w := f.confirm(t, api.ConfirmRequest{Handle: e.Handle, Code: codeAt(t, secret, f.now), CSR: csrOf(t, newECKey(t))}); w.Code != 200 {
		t.Fatalf("the throttled confirm spent the handle: %s", shown(w))
	}
}

// Two enrollments at once for one principal: whatever each answers, at
// most one handle ever confirms.
func TestTwoEnrollmentsAtOnce(t *testing.T) {
	for range 20 {
		f, _ := newSignInFixture(t)
		f.b.PasswordSignIn.OpenUntil = f.now.Add(time.Hour)
		f.b.PasswordSignIn.FailuresPerSource = 0
		type got struct {
			e      api.Enrollment
			secret []byte
		}
		var wg sync.WaitGroup
		res := make(chan got, 2)
		for range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", CSR: csrOf(t, newECKey(t))})
				var er api.EnrollResponse
				if w.Code != 202 || json.Unmarshal(w.Body.Bytes(), &er) != nil {
					return
				}
				u, _ := url.Parse(er.Enroll.URI)
				s, _ := totp.DecodeSecret(u.Query().Get("secret"))
				res <- got{er.Enroll, s}
			}()
		}
		wg.Wait()
		close(res)
		ok := 0
		for g := range res {
			if f.confirm(t, api.ConfirmRequest{Handle: g.e.Handle, Code: codeAt(t, g.secret, f.now), CSR: csrOf(t, newECKey(t))}).Code == 200 {
				ok++
			}
		}
		if ok > 1 {
			t.Fatalf("%d enrollments confirmed for one principal", ok)
		}
	}
}

// /v1/config says the broker signs in by directory password, with totp.
func TestConfigSaysDirectoryPassword(t *testing.T) {
	f, _ := newSignInFixture(t)
	w := f.call(context.Background(), nil, "GET", "/v1/config", "")
	var c api.Config
	if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.Methods, []string{"directory_password"}) || c.SignIn == nil || c.SignIn.SecondFactor != "totp" ||
		c.Issuance == nil {
		t.Fatalf("%+v", c)
	}
}

// A client certificate at /v1/sign-in is refused; a broker with no verifier
// is 404 not_signing_in; a body with an unknown field is 400 and echoes
// none of it.
func TestSignInRefusesWhatIsNotASignIn(t *testing.T) {
	f, dir := newSignInFixture(t)
	c := f.issuedDirectory(t, alicePrincipal, "uuid:alice")
	body, _ := json.Marshal(api.SignInRequest{Name: "alice", Password: "right", Code: "123456", CSR: csrOf(t, newECKey(t))})
	cs := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{c.Leaf}}
	if w := f.call(context.Background(), cs, "POST", "/v1/sign-in", string(body)); w.Code != 400 || dir.searchCount() != 0 {
		t.Fatalf("a client certificate: %s", shown(w))
	}
	f.b.PasswordSignIn = nil
	if w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: "123456", CSR: csrOf(t, newECKey(t))}); w.Code != 404 ||
		apiError(w) != "not_signing_in" {
		t.Fatalf("no verifier: %s", shown(w))
	}
	f, _ = newSignInFixture(t)
	w := f.call(context.Background(), nil, "POST", "/v1/sign-in", `{"name":"alice","password":"hunter2-in-a-body","x":1}`)
	if w.Code != 400 || strings.Contains(w.Body.String(), "hunter2") || strings.Contains(f.logs(), "hunter2") {
		t.Fatalf("an unknown field: %s", shown(w))
	}
}

// D7: a lost enrollment store refuses every password sign-in before
// anything is counted, 503 enrollment_store_lost; a held certificate mints.
func TestALostEnrollmentStoreRefusesOnlyTheSignIn(t *testing.T) {
	f, dir := newSignInFixture(t)
	c := f.issuedDirectory(t, alicePrincipal, "uuid:alice")
	f.b.Enrollments = lostEnrollments{}
	if err := f.b.CheckEnrollmentStore(context.Background()); err != nil {
		t.Fatal(err)
	}
	w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: "123456", CSR: csrOf(t, newECKey(t))})
	if w.Code != 503 || apiError(w) != "enrollment_store_lost" || dir.searchCount() != 0 || dir.bindCount() != 0 ||
		f.outcome("enrollment_store_lost") != 1 || f.lastIssue(t)["reason"] != "enrollment_store_lost" {
		t.Fatalf("%s", shown(w))
	}
	if n := f.counted(t, aliceSource); n != 0 {
		t.Fatalf("counted %d", n)
	}
	if testutil.ToFloat64(f.b.Metrics.DirectoryEnrollmentStoreOK) != 0 {
		t.Fatal("the gauge says ok")
	}
	if w := f.postAt(context.Background(), f.issuedState(c), mintLeaf1, "", f.now); w.Code != 200 {
		t.Fatalf("a holder's mint: %s", shown(w))
	}
}

// lostEnrollments answers the mark ErrEnrollmentStoreLost; nothing else of
// it may be called.
type lostEnrollments struct{ store.Enrollments }

func (lostEnrollments) GetEnrollmentMark(context.Context) (store.EnrollmentMark, error) {
	return store.EnrollmentMark{}, fmt.Errorf("%w: test", store.ErrEnrollmentStoreLost)
}

// D7 and pre-flight I15: no mark is lost whatever the rollout window says,
// and the check never creates one; a mark, once created, clears it.
func TestTheMarkAtStart(t *testing.T) {
	ctx := context.Background()
	f, dir := newSignInFixture(t)
	f.b.Enrollments = memory.NewEnrollments(f.b.Now)
	f.b.PasswordSignIn.OpenUntil = f.now.Add(time.Hour) // the rollout window open: still lost
	if err := f.b.CheckEnrollmentStore(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := f.b.Enrollments.GetEnrollmentMark(ctx); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the check created a mark: %v", err)
	}
	if f.b.EnrollmentStoreLost() == "" || testutil.ToFloat64(f.b.Metrics.DirectoryEnrollmentStoreOK) != 0 ||
		!strings.Contains(f.logs(), "init-enrollments") || !strings.Contains(f.logs(), "reset-second-factor --all") {
		t.Fatalf("no mark read as well: %q", f.b.EnrollmentStoreLost())
	}
	if w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", CSR: csrOf(t, newECKey(t))}); w.Code != 503 ||
		apiError(w) != "enrollment_store_lost" || dir.bindCount() != 0 {
		t.Fatalf("%s", shown(w))
	}
	if err := f.b.Enrollments.CreateEnrollmentMark(ctx, store.EnrollmentMark{CreatedAt: f.now}); err != nil {
		t.Fatal(err)
	}
	if err := f.b.CheckEnrollmentStore(ctx); err != nil || f.b.EnrollmentStoreLost() != "" ||
		testutil.ToFloat64(f.b.Metrics.DirectoryEnrollmentStoreOK) != 1 {
		t.Fatalf("a mark, still lost: %v %q", err, f.b.EnrollmentStoreLost())
	}
}

// downEnrollments does not answer.
type downEnrollments struct{ store.Enrollments }

func (downEnrollments) GetEnrollmentMark(context.Context) (store.EnrollmentMark, error) {
	return store.EnrollmentMark{}, store.ErrUnavailable
}

// A store that does not answer is not lost: the check returns its error,
// and the state and the gauge stay as they were (the next pass looks again).
func TestAnEnrollmentStoreThatDoesNotAnswerIsNotLost(t *testing.T) {
	f, _ := newSignInFixture(t)
	f.b.Enrollments = downEnrollments{}
	if err := f.b.CheckEnrollmentStore(context.Background()); !errors.Is(err, store.ErrUnavailable) ||
		f.b.EnrollmentStoreLost() != "" || testutil.ToFloat64(f.b.Metrics.DirectoryEnrollmentStoreOK) != 1 {
		t.Fatalf("%v %q", err, f.b.EnrollmentStoreLost())
	}
}

// The name is normalised before it is searched: surrounding space is
// dropped; a control character, an empty or a very long name is refused
// before the directory, counted against the source.
func TestTheNameIsNormalised(t *testing.T) {
	f, dir := newSignInFixture(t)
	secret := f.enrolled(t, alicePrincipal, "uuid:alice")
	w := f.signIn(t, api.SignInRequest{Name: "  alice\t", Password: "right", Code: codeAt(t, secret, f.now),
		CSR: csrOf(t, newECKey(t))})
	if w.Code != 200 || dir.names[0] != "alice" {
		t.Fatalf("%s, searched %q", shown(w), dir.names)
	}
	// Printable ASCII only (decision 47 ruling 3): no accented or fullwidth look-alike reaches a search.
	for _, name := range []string{"", "   ", "al\x00ice", "al\nice", "al‮ice", strings.Repeat("a", 300),
		"ålice", "ａlice", "al ice"} {
		f, dir := newSignInFixture(t)
		w := f.signIn(t, api.SignInRequest{Name: name, Password: "right", Code: "123456", CSR: csrOf(t, newECKey(t))})
		rec := f.lastIssue(t)
		if w.Code != 401 || dir.searchCount() != 0 || signInOf(rec)["failed"] != "name" || rec["principal"] != nil {
			t.Fatalf("%q: %s %v", name, shown(w), rec)
		}
		if n := f.counted(t, aliceSource); n != 1 {
			t.Fatalf("%q: the source counted %d", name, n)
		}
	}
}

// A principal outside principal_domains is no one this verifier signs in:
// the one refusal, no principal in the record, nothing bound.
func TestAPrincipalOutsideTheDomainsIsRefused(t *testing.T) {
	f, dir := newSignInFixture(t)
	bob := directory.SignInEntry{Identity: directory.Identity{DN: "uid=bob,dc=other,dc=com", EntryID: "uuid:bob",
		Principal: "user:bob@other.com", Username: "bob"}, CreatedAt: f.now.Add(-time.Hour)}
	dir.people["bob"] = fakePerson{entry: bob, password: "right"}
	f.b.PasswordSignIn.OpenUntil = f.now.Add(time.Hour)
	w := f.signIn(t, api.SignInRequest{Name: "bob", Password: "right", Code: "123456", CSR: csrOf(t, newECKey(t))})
	rec := f.lastIssue(t)
	if w.Code != 401 || apiError(w) != "sign_in_refused" || dir.bindCount() != 0 || signInOf(rec)["failed"] != "name" ||
		rec["principal"] != nil || strings.Contains(f.logs(), "other.com") {
		t.Fatalf("%s %v", shown(w), rec)
	}
	if ps, _ := f.b.Enrollments.SecondFactorPrincipals(context.Background()); len(ps) != 0 {
		t.Fatalf("a record for %v", ps)
	}
	// A principal that is not a user: one at all is no one's either.
	bob.Identity.Principal = "service:bob@example.com"
	dir.people["bob"] = fakePerson{entry: bob, password: "right"}
	if w := f.signIn(t, api.SignInRequest{Name: "bob", Password: "right", CSR: csrOf(t, newECKey(t))}); w.Code != 401 {
		t.Fatalf("a non-user principal: %s", shown(w))
	}
}

// A ':' in the otpauth label or account would shift the URI's label: the
// broker answers an enrollment it cannot make as it answers a principal no
// certificate carries (401 sign_in_not_certifiable, 9b's reason), and starts
// none.
func TestAColonInTheTOTPLabelRefusesTheEnrollment(t *testing.T) {
	for name, set := range map[string]func(f *fixture, d *fakeDir){
		"label": func(f *fixture, _ *fakeDir) { f.b.PasswordSignIn.TOTPLabel = "port49: lab" },
		"account": func(f *fixture, d *fakeDir) {
			p := d.people["alice"]
			p.entry.Principal = "user:al:ice@example.com"
			d.people["alice"] = p
		},
	} {
		f, dir := newSignInFixture(t)
		f.b.PasswordSignIn.OpenUntil = f.now.Add(time.Hour)
		set(f, dir)
		w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", CSR: csrOf(t, newECKey(t))})
		rec := f.lastIssue(t)
		if w.Code != 401 || apiError(w) != "sign_in_not_certifiable" || strings.Contains(w.Body.String(), "otpauth") ||
			f.outcome("enrollment_started") != 0 || rec["reason"] != "trust_domain_unresolved" || dir.bindCount() != 0 {
			t.Fatalf("%s: %s %v", name, shown(w), rec)
		}
		if ps, _ := f.b.Enrollments.SecondFactorPrincipals(context.Background()); len(ps) != 0 {
			t.Fatalf("%s: a record for %v", name, ps)
		}
	}
}

// What cannot pass is checked before the bind (C3): a principal no
// certificate carries, inside an enrollment window, is refused with the
// directory never asked.
func TestAnEnrollmentOfANotCertifiablePrincipalBindsNothing(t *testing.T) {
	f, dir := newSignInFixture(t)
	f.b.PasswordSignIn.OpenUntil = f.now.Add(time.Hour)
	p := dir.people["alice"]
	p.entry.Principal = "user:a b@example.com" // a space: not carried in a certificate
	dir.people["alice"] = p
	w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", CSR: csrOf(t, newECKey(t))})
	if w.Code != 401 || apiError(w) != "sign_in_not_certifiable" || dir.bindCount() != 0 {
		t.Fatalf("%s, %d binds", shown(w), dir.bindCount())
	}
}

// A store lost between the sign-in and the confirm refuses the confirm too.
func TestALostEnrollmentStoreRefusesTheConfirm(t *testing.T) {
	f, _ := newSignInFixture(t)
	f.b.PasswordSignIn.OpenUntil = f.now.Add(time.Hour)
	e, secret := enrollAlice(t, f)
	real := f.b.Enrollments
	f.b.Enrollments = lostEnrollments{}
	if err := f.b.CheckEnrollmentStore(context.Background()); err != nil {
		t.Fatal(err)
	}
	w := f.confirm(t, api.ConfirmRequest{Handle: e.Handle, Code: codeAt(t, secret, f.now), CSR: csrOf(t, newECKey(t))})
	if w.Code != 503 || apiError(w) != "enrollment_store_lost" {
		t.Fatalf("%s", shown(w))
	}
	// spec 5.7: enrollment_store_lost is recorded under issue and enroll; a
	// confirm's is enroll's.
	recs := eventsOf(f.records(t), decision.EventEnroll)
	if len(recs) == 0 || recs[len(recs)-1]["reason"] != "enrollment_store_lost" {
		t.Fatalf("no enroll record for the lost store: %v", recs)
	}
	f.b.Enrollments = real
	if err := f.b.CheckEnrollmentStore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if w := f.confirm(t, api.ConfirmRequest{Handle: e.Handle, Code: codeAt(t, secret, f.now), CSR: csrOf(t, newECKey(t))}); w.Code != 200 {
		t.Fatalf("the handle was spent by a refused confirm: %s", shown(w))
	}
}

// sourcePrefix is an IPv4 address /32 and an IPv6 address /64; anything else
// is "unknown".
func TestSourcePrefix(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.1:1234":             "192.0.2.1/32",
		"[::ffff:192.0.2.7]:9":       "192.0.2.7/32",
		"[2001:db8:1:2:3:4:5:6]:443": "2001:db8:1:2::/64",
		"[2001:db8:1:2:ffff::9]:443": "2001:db8:1:2::/64",
		"not an address":             "unknown",
		"":                           "unknown",
	} {
		if got := sourcePrefix(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
