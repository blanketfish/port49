//go:build linux

package port49d

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/daemon/admin"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/session"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/tacacs/wire"
	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/internal/token"
)

// withAdminSocket adds admin_socket to the config at cfgPath.
func withAdminSocket(t *testing.T, cfgPath, socket string) {
	t.Helper()
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, append([]byte("admin_socket: "+socket+"\n"), raw...), 0o600); err != nil {
		t.Fatal(err)
	}
}

// An admin_socket port49d cannot open ends the start, says nothing is
// listening, and lets go of the broker's port (pre-flight M6).
func TestRunWithAnAdminSocketItCannotOpenReleasesTheBroker(t *testing.T) {
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	brokerAddr := free.Addr().String()
	free.Close()
	b := brokerConfig(t, minimalPolicy).Broker
	b.Listen = brokerAddr
	cfgPath := writeRunConfig(t, b)
	socket := filepath.Join(filepath.Dir(cfgPath), "port49d.sock")
	if err := os.WriteFile(socket, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	withAdminSocket(t, cfgPath, socket)
	out, err := runExpectingRefusal(t, cfgPath)
	if err == nil || !strings.Contains(err.Error(), "admin_socket "+socket) || !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("run: %v", err)
	}
	if strings.Contains(out, "listening") {
		t.Fatalf("stderr claims a listener is up: %q", out)
	}
	again, err := net.Listen("tcp", brokerAddr)
	if err != nil {
		t.Fatalf("the broker's port is still held: %v", err)
	}
	again.Close()
}

// With admin_socket set, a packet under a key port49d does not hold is held
// for the device, and keys_diagnose over the socket names what it validates
// under, and the group the policy in force assigns.
func TestRunAnswersKeysDiagnoseOverTheAdminSocket(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log

	b := brokerConfig(t, minimalPolicy).Broker
	cfgPath := writeRunConfig(t, b)
	socket := filepath.Join(filepath.Dir(cfgPath), "port49d.sock")
	withAdminSocket(t, cfgPath, socket)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfgPath) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
		}
	})
	waitFor(t, &out, "port49d: broker listening on ")
	waitFor(t, &out, "port49d: admin socket on "+socket)
	addr := regexp.MustCompile(`port49d: listening on (127\.0\.0\.1:\d+)`).FindStringSubmatch(out.String())
	if addr == nil {
		t.Fatalf("stderr: %q", out.String())
	}
	if fi, err := os.Lstat(socket); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("%v, %v", fi, err)
	}

	ask := func() admin.Response {
		t.Helper()
		c, err := net.Dial("unix", socket)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		json.NewEncoder(c).Encode(admin.Request{Op: "keys_diagnose", Device: "leaf1"})
		var r admin.Response
		if err := json.NewDecoder(c).Decode(&r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	if r := ask(); !strings.Contains(r.Error, "holds no unvalidated packet") {
		t.Fatalf("%+v", r)
	}

	conn, err := net.Dial("tcp", addr[1])
	if err != nil {
		t.Fatal(err)
	}
	body := wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("pw-never-returned")}.Encode()
	h := wire.Header{MajorVersion: 0xc, Type: wire.TypeAuthen, SeqNo: 1, SessionID: 0x5eed, Length: uint32(len(body))}
	conn.Write(append(h.Encode(), wire.Obfuscate(h, []byte("a-key-port49d-lacks"), body)...))
	defer conn.Close()

	deadline := time.Now().Add(5 * time.Second)
	r := ask()
	for r.Error != "" && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		r = ask()
	}
	if r.Finding == nil || len(r.Finding.Matches) != 0 || r.Finding.Assigned != "k" ||
		!strings.Contains(r.Text, "validates under nothing port49d holds") {
		t.Fatalf("%+v", r)
	}
	raw, _ := json.Marshal(r)
	for _, leak := range []string{"pw-never-returned", "run-test-secret", "a-key-port49d-lacks"} {
		if strings.Contains(string(raw), leak) || strings.Contains(log.String(), leak) {
			t.Fatalf("%q reached the answer or the log", leak)
		}
	}
}

// With admin_socket set and a broker, port49 revoke over the socket closes
// the held broker connection, refuses every new mint, writes the mark to
// revocations_file with the caller's uid as its origin, lists it, and a
// lift lets the principal mint again.
func TestRunRevokesListsAndLiftsOverTheAdminSocket(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log

	b := brokerConfig(t, minimalPolicy).Broker
	cfgPath := writeRunConfig(t, b)
	socket := filepath.Join(filepath.Dir(cfgPath), "port49d.sock")
	withAdminSocket(t, cfgPath, socket)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfgPath) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
		}
	})
	waitFor(t, &out, "port49d: broker listening on ")
	if strings.Contains(out.String(), "no admin_socket:") {
		t.Fatalf("said with an admin socket: %q", out.String())
	}
	waitFor(t, &out, "port49d: admin socket on "+socket+" (port49 keys diagnose, port49 revoke)")

	pki := filepath.Dir(b.ClientCAFile) // brokerConfig wrote the lab PKI there (testpki.WriteLab)
	alice, err := tls.LoadX509KeyPair(filepath.Join(pki, testpki.LabClientCert), filepath.Join(pki, testpki.LabClientKey))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	caPEM, _ := os.ReadFile(b.ClientCAFile)
	pool.AppendCertsFromPEM(caPEM)
	brokerAddr := regexp.MustCompile(`port49d: broker listening on (\S+)`).FindStringSubmatch(out.String())[1]
	dial := func() *tls.Conn {
		c, err := tls.Dial("tcp", brokerAddr, &tls.Config{Certificates: []tls.Certificate{alice}, RootCAs: pool,
			MinVersion: tls.VersionTLS13, ServerName: "127.0.0.1"})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	mint := func(c *tls.Conn) int {
		body := `{"devices":["leaf1"]}`
		fmt.Fprintf(c, "POST /v1/tokens HTTP/1.1\r\nHost: broker\r\nContent-Type: application/json\r\n"+
			"Content-Length: %d\r\n\r\n%s", len(body), body)
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			return 0
		}
		// Read to the end, so a second request on this connection starts
		// at a response boundary and a 0 can only mean the broker closed it.
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}
	revoke := func(req admin.Request) admin.Response {
		t.Helper()
		c, err := net.Dial("unix", socket)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		json.NewEncoder(c).Encode(req)
		var r admin.Response
		if err := json.NewDecoder(c).Decode(&r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	heldConn := dial()
	if code := mint(heldConn); code != 200 {
		t.Fatalf("a mint before the revocation: %d", code)
	}
	r := revoke(admin.Request{Op: "revoke", Principal: "user:alice@example.com"})
	if r.Error != "" || !strings.Contains(r.Text, "1 held broker connection(s) closed") {
		t.Fatalf("%+v", r)
	}
	if code := mint(heldConn); code != 0 {
		t.Fatalf("the held connection still answered after the revocation: %d", code)
	}
	// A new connection is refused as it binds, from the listener's copy of
	// the marks (Task 6): its one request, which reaches no handler, is
	// answered 401 credential_revoked, so the agent ends its session, and
	// the connection is closed.
	c := dial()
	if code := mint(c); code != http.StatusUnauthorized {
		t.Fatalf("a new connection after the revocation: %d", code)
	}
	if code := mint(c); code != 0 {
		t.Fatalf("a refused connection answered a second request: %d", code)
	}
	waitFor(t, &out, "is revoked")
	raw, err := os.ReadFile(b.RevocationsFile)
	if err != nil || !strings.Contains(string(raw), `"user:alice@example.com"`) ||
		!strings.Contains(string(raw), fmt.Sprintf("admin_socket uid %d", os.Geteuid())) {
		t.Fatalf("the file: %s %v", raw, err)
	}
	if r := revoke(admin.Request{Op: "revocations"}); !strings.Contains(r.Text, "principal user:alice@example.com since") {
		t.Fatalf("%+v", r)
	}
	if r := revoke(admin.Request{Op: "revoke", Principal: "user:alice@example.com", Lift: true}); r.Error != "" ||
		!strings.Contains(r.Text, "Contexts it marked stay revoked") {
		t.Fatalf("%+v", r)
	}
	if code := mint(dial()); code != 200 {
		t.Fatalf("a mint after the lift: %d", code)
	}
	raw, _ = json.Marshal(r)
	if strings.Contains(string(raw), "run-test-secret") || strings.Contains(log.String(), "run-test-secret") {
		t.Fatal("a key reached the answer or the log")
	}
}

// A broker with no admin_socket says once, at start, that an HTTP revocation
// is made but nothing can lift it, and how to cut someone off meanwhile
// (pre-flight I7).
func TestRunWithABrokerAndNoAdminSocketSaysWhatRevocationCanDo(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	cfgPath := writeRunConfig(t, brokerConfig(t, minimalPolicy).Broker)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfgPath) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
		}
	})
	waitFor(t, &out, "port49d: broker listening on ")
	if n := strings.Count(out.String(), "port49d: broker: no admin_socket: a revocation over HTTP"); n != 1 ||
		strings.Contains(out.String(), "port49 revoke is unavailable") {
		t.Fatalf("said %d times: %q", n, out.String())
	}
}

// hungStore hangs PutRevocation while hang is open, until its ctx ends,
// as a store behind a dead network does; ended gets the ctx's error. One
// hung when hang closes goes on.
type hungStore struct {
	store.Store
	hang    chan struct{}
	entered chan struct{}
	ended   chan error
}

func (h *hungStore) PutRevocation(ctx context.Context, r store.Revocation) error {
	select {
	case <-h.hang:
		return h.Store.PutRevocation(ctx, r)
	default:
	}
	h.entered <- struct{}{}
	select {
	case <-h.hang:
		return h.Store.PutRevocation(ctx, r)
	case <-ctx.Done():
	}
	h.ended <- ctx.Err()
	return ctx.Err()
}

// adminOverBroker serves the admin socket over a real broker on st, with
// opTimeout, and returns the socket's path.
func adminOverBroker(t *testing.T, st store.Store, opTimeout time.Duration) string {
	t.Helper()
	cfg := brokerConfig(t, minimalPolicy)
	m := newMetrics()
	minter := token.NewMinter(st, decision.NewJSONLines(io.Discard), rand.Reader, token.TagKey([]byte("admin-test-key")),
		time.Now, 8)
	_, brk, err := buildBroker(cfg, "inventory_file "+cfg.InventoryFile, st, minter, decision.NewJSONLines(io.Discard), m)
	if err != nil {
		t.Fatal(err)
	}
	brk.Sessions = session.New(st, time.Now, time.Hour, time.Hour)
	brk.Persist = persister(st, filepath.Join(safeDir(t), "revocations.json"), nil, nil, m)
	brk.RevokeTimeout = opTimeout
	p := filepath.Join(t.TempDir(), "port49d.sock")
	ln, err := admin.Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv := &admin.Server{Now: time.Now, OpTimeout: opTimeout, Revoke: adminRevoke(brk, nil), Revocations: adminRevocations(st)}
	go srv.Serve(ctx, ln)
	return p
}

// ask sends req to the socket at p and decodes the answer.
func ask(p string, req admin.Request) (admin.Response, error) {
	c, err := net.Dial("unix", p)
	if err != nil {
		return admin.Response{}, err
	}
	defer c.Close()
	if err := json.NewEncoder(c).Encode(req); err != nil {
		return admin.Response{}, err
	}
	var r admin.Response
	err = json.NewDecoder(c).Decode(&r)
	return r, err
}

// A revocation behind a hung store gives up at the admin socket's deadline,
// and the answer says nothing was revoked and how to cut access instead.
func TestARevocationOnAHungStoreGivesUpAtTheDeadlineAndSaysSo(t *testing.T) {
	st := &hungStore{Store: memory.New(time.Now), hang: make(chan struct{}), entered: make(chan struct{}, 1),
		ended: make(chan error, 1)}
	p := adminOverBroker(t, st, 200*time.Millisecond)
	start := time.Now()
	r, err := ask(p, admin.Request{Op: "revoke", Principal: "user:alice@example.com"})
	if err != nil || r.Partial || !strings.Contains(r.Error, "nothing else was revoked") ||
		!strings.Contains(r.Error, "deadline exceeded") || !strings.Contains(r.Error, "broker.policy_file") {
		t.Fatalf("%+v, %v", r, err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("answered after %v", d)
	}
}

// A caller that hangs up while its revocation waits behind a hung one
// writes no mark, and the hung one, once its store answers, finishes and
// is answered in full.
func TestACallerThatHangsUpWhileWaitingWritesNoMark(t *testing.T) {
	st := &hungStore{Store: memory.New(time.Now), hang: make(chan struct{}), entered: make(chan struct{}, 1),
		ended: make(chan error, 1)}
	p := adminOverBroker(t, st, time.Minute)
	first := make(chan admin.Response, 1)
	go func() {
		r, _ := ask(p, admin.Request{Op: "revoke", Principal: "user:alice@example.com"})
		first <- r
	}()
	<-st.entered
	c, err := net.Dial("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	json.NewEncoder(c).Encode(admin.Request{Op: "revoke", Principal: "user:carol@example.com"})
	time.Sleep(50 * time.Millisecond) // into its wait for the semaphore
	c.Close()
	time.Sleep(50 * time.Millisecond)
	close(st.hang)
	select {
	case r := <-first:
		if r.Error != "" || !strings.Contains(r.Text, "revoked user:alice@example.com") {
			t.Fatalf("%+v", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the first revocation was not answered")
	}
	r, err := ask(p, admin.Request{Op: "revocations"})
	if err != nil || strings.Contains(r.Text, "carol") || !strings.Contains(r.Text, "alice") {
		t.Fatalf("%+v %v", r, err)
	}
}

// Revocations, lifts and lists asked at once are each answered, and every
// mark put lands in the store and in the list.
func TestConcurrentRevocationsAreEachAnswered(t *testing.T) {
	st := memory.New(time.Now)
	p := adminOverBroker(t, st, 10*time.Second)
	const n = 8
	var wg sync.WaitGroup
	errs := make(chan string, 3*n)
	for i := 0; i < n; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			r, err := ask(p, admin.Request{Op: "revoke", Principal: fmt.Sprintf("user:u%d@example.com", i)})
			if err != nil || r.Error != "" || !strings.Contains(r.Text, fmt.Sprintf("revoked user:u%d@example.com", i)) {
				errs <- fmt.Sprintf("revoke %d: %+v %v", i, r, err)
			}
		}(i)
		go func() {
			defer wg.Done()
			if r, err := ask(p, admin.Request{Op: "revocations"}); err != nil || r.Error != "" {
				errs <- fmt.Sprintf("list: %+v %v", r, err)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	r, err := ask(p, admin.Request{Op: "revocations"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if !strings.Contains(r.Text, fmt.Sprintf("principal user:u%d@example.com since", i)) {
			t.Fatalf("u%d is missing from the list: %s", i, r.Text)
		}
	}
	// Lifted at once, each is answered and none is left.
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if r, err := ask(p, admin.Request{Op: "revoke", Principal: fmt.Sprintf("user:u%d@example.com", i),
				Lift: true}); err != nil || r.Error != "" {
				t.Errorf("lift %d: %+v %v", i, r, err)
			}
		}(i)
	}
	wg.Wait()
	if r, err := ask(p, admin.Request{Op: "revocations"}); err != nil || r.Text != "no revocation is in force" {
		t.Fatalf("%+v %v", r, err)
	}
}

// listFailingStore fails every list of the marks.
type listFailingStore struct{ store.Store }

func (listFailingStore) ListRevocations(context.Context) ([]store.Revocation, error) {
	return nil, context.DeadlineExceeded
}

// A list the store cannot answer says what failed, not a bare store error.
func TestAFailedListSaysWhatFailed(t *testing.T) {
	_, err := adminRevocations(listFailingStore{memory.New(time.Now)})(context.Background())
	if err == nil || !strings.HasPrefix(err.Error(), "broker: the revocations in force could not be read") ||
		!strings.Contains(err.Error(), "deadline exceeded") {
		t.Fatalf("%v", err)
	}
}

// A lift on the admin socket is out of this replica's copy, on disk, when
// it is answered: a stop before the watch delivers it neither keeps the
// mark in force at the restart nor puts it back (TestATakeoverPutsBackAMarkTheStoreLost).
// The watch's late put of the lifted mark does not add it back; a newer
// revocation of the key does.
func TestALiftOnTheAdminSocketLeavesTheCopyBeforeItIsAnswered(t *testing.T) {
	st := memory.New(time.Now)
	cfg := brokerConfig(t, minimalPolicy)
	m := newMetrics()
	minter := token.NewMinter(st, decision.NewJSONLines(io.Discard), rand.Reader, token.TagKey([]byte("admin-test-key")),
		time.Now, 8)
	_, brk, err := buildBroker(cfg, "inventory_file "+cfg.InventoryFile, st, minter, decision.NewJSONLines(io.Discard), m)
	if err != nil {
		t.Fatal(err)
	}
	brk.Sessions = session.New(st, time.Now, time.Hour, time.Hour)
	path := filepath.Join(safeStateDir(t), "marks.json")
	var out bytes.Buffer
	c := openMarksCopy(path, &out)
	revoke := adminRevoke(brk, c)
	ctx := context.Background()
	const carol = "user:carol@example.com"
	if _, _, err := revoke(ctx, admin.RevokeOp{Principal: carol}); err != nil {
		t.Fatal(err)
	}
	put, err := st.GetRevocation(ctx, store.RevocationPrincipal, carol)
	if err != nil {
		t.Fatal(err)
	}
	c.Apply(store.MarkChange{Revocation: put, Standing: true}) // the watch delivers the revocation
	if _, _, err := revoke(ctx, admin.RevokeOp{Principal: carol, Lift: true}); err != nil {
		t.Fatal(err)
	}
	if got := openMarksCopy(path, io.Discard).All(); len(got) != 0 {
		t.Fatalf("after the lift was answered the file holds %+v", got)
	}
	c.Apply(store.MarkChange{Revocation: put, Standing: true}) // the watch, behind, delivers the put again
	if got := openMarksCopy(path, io.Discard).All(); len(got) != 0 {
		t.Fatalf("the watch's late put added the lifted mark back: %+v", got)
	}
	newer := store.Revocation{Kind: put.Kind, Key: put.Key, At: put.At.Add(time.Second)}
	c.Apply(store.MarkChange{Revocation: newer, Standing: true})
	c.Lifted(put) // a stale lift never drops a newer mark
	if got := openMarksCopy(path, io.Discard).All(); len(got) != 1 || !got[0].At.Equal(newer.At) {
		t.Fatalf("a newer revocation of the key: %+v", got)
	}
}
