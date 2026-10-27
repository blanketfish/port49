package admin

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/keyring"
)

func TestAnswerRefusesAnUnknownOpAndAnUnheldDevice(t *testing.T) {
	s := &Server{Held: &keyring.Held{}, Keys: func() map[string]keyring.Set { return map[string]keyring.Set{} }, Now: time.Now}
	if r := s.answer(context.Background(), Request{Op: "keys_show", Device: "x"}, 0); r.Error != "unknown op; the ops are keys_diagnose, revoke, revocations, directory_forget, store_status, "+
		"second_factor_reset, sign_in_unlock, enrollments_init, enrollments_export and enrollments_import" {
		t.Fatalf("%+v", r)
	}
	if r := s.answer(context.Background(), Request{Op: "keys_diagnose", Device: "x"}, 0); !strings.Contains(r.Error, "holds no unvalidated packet") {
		t.Fatalf("%+v", r)
	}
}

func TestListenRefusesAPathThatIsNotASocket(t *testing.T) {
	p := filepath.Join(t.TempDir(), "port49d.sock")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(p); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("%v", err)
	}
}

// A symlink at the path is refused and never followed: its target keeps its
// mode and its contents.
func TestListenRefusesASymlinkAndLeavesItsTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "port49d.sock")
	if err := os.Symlink(target, p); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(p); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("%v", err)
	}
	fi, err := os.Stat(target)
	if err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("target mode %v, %v", fi.Mode(), err)
	}
	if fi, err := os.Lstat(p); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the link was removed or replaced: %v, %v", fi, err)
	}
}

// The uid rule itself: port49d's own and root, and no other.
func TestUIDAllowedIsOwnAndRootOnly(t *testing.T) {
	const own = 1000
	if err := uidAllowed(own, own); err != nil {
		t.Fatal(err)
	}
	if err := uidAllowed(0, own); err != nil {
		t.Fatal(err)
	}
	if err := uidAllowed(1001, own); err == nil || !strings.Contains(err.Error(), "neither port49d's") {
		t.Fatalf("another uid: %v", err)
	}
}

// A request that is not one JSON object is refused without echoing it.
func TestAnswerNeverEchoesAMalformedRequest(t *testing.T) {
	s := &Server{Held: &keyring.Held{}, Keys: func() map[string]keyring.Set { return map[string]keyring.Set{} }, Now: time.Now}
	r := s.answer(context.Background(), Request{Op: "keys_diagnose\x00secret", Device: "x"}, 0)
	if !strings.Contains(r.Error, "unknown op") || strings.Contains(r.Error, "secret") {
		t.Fatalf("%+v", r)
	}
}

// revoke and revocations reach the funcs port49d gives, with the uid that
// asked; without a broker they are refused, saying why.
func TestRevokeOpsReachTheBroker(t *testing.T) {
	ctx := context.Background()
	var got RevokeOp
	s := &Server{Held: &keyring.Held{}, Now: time.Now,
		Revoke: func(_ context.Context, op RevokeOp) (string, bool, error) {
			got = op
			return "revoked it", op.Lift, nil
		},
		Revocations: func(context.Context) (string, error) { return "no revocation is in force", nil }}
	r := s.answer(ctx, Request{Op: "revoke", Principal: "user:alice@example.com"}, 1000)
	if r.Text != "revoked it" || got.Principal != "user:alice@example.com" || got.UID != 1000 || got.Lift {
		t.Fatalf("%+v %+v", r, got)
	}
	if r := s.answer(ctx, Request{Op: "revoke", CertIssuer: "CN=Corp CA", CertSerial: "3f9a01", Lift: true}, 0); !r.Partial {
		t.Fatalf("a partial answer must say so: %+v", r)
	}
	if got.Issuer != "CN=Corp CA" || got.Serial != "3f9a01" || !got.Lift {
		t.Fatalf("%+v", got)
	}
	// A panic behind an op answers an error and leaves port49d running (M12).
	boom := &Server{Held: &keyring.Held{}, Now: time.Now,
		Revoke:      func(context.Context, RevokeOp) (string, bool, error) { panic("boom") },
		Revocations: func(context.Context) (string, error) { return "", nil }}
	r = boom.answer(ctx, Request{Op: "revoke", Principal: "user:a@b"}, 0)
	if r.Error != "internal error; port49d's log says what" {
		t.Fatalf("%+v", r)
	}
	// On port49-broker the line and the answer name it (Task 15a review M-6).
	var logged bytes.Buffer
	log.SetOutput(&logged)
	defer log.SetOutput(os.Stderr)
	boom.Proc = "port49-broker"
	r = boom.answer(ctx, Request{Op: "revoke", Principal: "user:a@b"}, 0)
	if r.Error != "internal error; port49-broker's log says what" ||
		!strings.Contains(logged.String(), "port49-broker: admin socket: op \"revoke\" failed: boom") {
		t.Fatalf("%+v; logged %q", r, logged.String())
	}
	if r := s.answer(ctx, Request{Op: "revocations"}, 0); r.Text != "no revocation is in force" {
		t.Fatalf("%+v", r)
	}
	none := &Server{Held: &keyring.Held{}, Now: time.Now}
	if r := none.answer(ctx, Request{Op: "revoke", Principal: "user:a@b"}, 0); !strings.Contains(r.Error, "runs no broker") {
		t.Fatalf("%+v", r)
	}
}

// A revocation asked of port49d with no broker in it, beside
// port49-broker on etcd, is refused naming where it is answered and how
// to ask there (plan 7e, Ruling 13); the list is too. Unset, the memory
// store's line stands.
func TestARevokeWithNoBrokerNamesWhereItIs(t *testing.T) {
	ctx := context.Background()
	s := &Server{Held: &keyring.Held{}, Now: time.Now,
		RevokeElsewhere: "port49-broker's admin socket (its admin_socket in port49-broker.yaml)"}
	for _, op := range []string{"revoke", "revocations"} {
		r := s.answer(ctx, Request{Op: op, Principal: "user:alice@example.com"}, 0)
		if !strings.Contains(r.Error, "port49 revoke --socket") || !strings.Contains(r.Error, "port49-broker") ||
			strings.Contains(r.Error, "nothing to revoke") {
			t.Fatalf("%s: %+v", op, r)
		}
	}
	none := &Server{Held: &keyring.Held{}, Now: time.Now}
	if r := none.answer(ctx, Request{Op: "revoke", Principal: "user:a@b"}, 0); !strings.Contains(r.Error,
		"nothing to revoke") {
		t.Fatalf("%+v", r)
	}
}

// port49-broker holds no device packets: a keys diagnose at its socket
// names port49d's, where the packets are held (plan 7e, Ruling 13;
// pre-flight M16).
func TestAKeysDiagnoseWithNoPacketsNamesWhereItIs(t *testing.T) {
	s := &Server{Now: time.Now, DiagnoseElsewhere: "port49d's admin socket"}
	r := s.answer(context.Background(), Request{Op: "keys_diagnose", Device: "leaf1"}, 0)
	if r.Error != "port49-broker holds no device packets; keys diagnose is port49d's admin socket" {
		t.Fatalf("%+v", r)
	}
}

// A revoke's connection outlasts its wait for its turn, its run and the save
// it waits on; a list's, its one bound. The exported waits are the defaults.
func TestConnTimeoutCoversTheOpsWorstCase(t *testing.T) {
	s := &Server{}
	if got := s.connTimeout("revoke"); got != RevokeWait || got <= 2*OpTimeout+PersistTimeout {
		t.Fatalf("revoke: %v", got)
	}
	if got := s.connTimeout("revocations"); got != ListWait || got <= OpTimeout {
		t.Fatalf("revocations: %v", got)
	}
	if got := s.connTimeout("directory_forget"); got != ListWait {
		t.Fatalf("directory_forget: %v", got)
	}
}

// The sign-in ops: a process with no broker says where they run; an empty
// principal is refused for second_factor_reset without all and for
// sign_in_unlock; a principal and all together are refused; an import body
// over maxImport is refused and never reaches the broker; each op reaches the
// broker with the caller's uid; the unknown-op line lists all nine ops.
func TestTheSignInAdminOps(t *testing.T) {
	ctx := context.Background()
	ops := []Request{{Op: "second_factor_reset", All: true}, {Op: "sign_in_unlock", Principal: "user:a@b"},
		{Op: "enrollments_init"}, {Op: "enrollments_export"}, {Op: "enrollments_import"}}
	none := &Server{Held: &keyring.Held{}, Now: time.Now}
	beside := &Server{Held: &keyring.Held{}, Now: time.Now, RevokeElsewhere: "port49-broker's admin socket"}
	for _, req := range ops {
		if r := none.answer(ctx, req, 0); !strings.Contains(r.Error, "runs no broker") || !strings.Contains(r.Error, "port49 directory ") {
			t.Fatalf("%s with no broker: %+v", req.Op, r)
		}
		if r := beside.answer(ctx, req, 0); !strings.Contains(r.Error, "port49-broker's admin socket") ||
			!strings.Contains(r.Error, "--socket <that path>") {
			t.Fatalf("%s beside port49-broker: %+v", req.Op, r)
		}
	}

	type call struct {
		op, principal string
		all, replace  bool
		uid           uint32
		body          string
	}
	var got []call
	s := &Server{Held: &keyring.Held{}, Now: time.Now,
		SecondFactorReset: func(_ context.Context, p string, all bool, uid uint32) (string, error) {
			got = append(got, call{op: "reset", principal: p, all: all, uid: uid})
			return "reset it", nil
		},
		SignInUnlock: func(_ context.Context, p string, uid uint32) (string, error) {
			got = append(got, call{op: "unlock", principal: p, uid: uid})
			return "unlocked it", nil
		},
		EnrollmentsInit: func(_ context.Context, uid uint32) (string, error) {
			got = append(got, call{op: "init", uid: uid})
			return "created it", nil
		},
		EnrollmentsExport: func(_ context.Context, uid uint32) ([]byte, error) {
			got = append(got, call{op: "export", uid: uid})
			return []byte("sealed export"), nil
		},
		EnrollmentsImport: func(_ context.Context, sealed []byte, replace bool, uid uint32) (string, error) {
			got = append(got, call{op: "import", replace: replace, uid: uid, body: string(sealed)})
			return "imported it", nil
		}}
	for _, req := range []Request{{Op: "second_factor_reset"}, {Op: "sign_in_unlock"},
		{Op: "second_factor_reset", All: true, Principal: "user:a@b"}} {
		if r := s.answer(ctx, req, 0); r.Error == "" || len(got) != 0 {
			t.Fatalf("%+v was taken: %+v, %v", req, r, got)
		}
	}
	if r := s.answer(ctx, Request{Op: "second_factor_reset", Principal: "user:a@b"}, 1000); r.Text != "reset it" {
		t.Fatalf("%+v", r)
	}
	if r := s.answer(ctx, Request{Op: "second_factor_reset", All: true}, 1001); r.Text != "reset it" {
		t.Fatalf("%+v", r)
	}
	if r := s.answer(ctx, Request{Op: "sign_in_unlock", Principal: "user:a@b"}, 1002); r.Text != "unlocked it" {
		t.Fatalf("%+v", r)
	}
	if r := s.answer(ctx, Request{Op: "enrollments_init"}, 1003); r.Text != "created it" {
		t.Fatalf("%+v", r)
	}
	if r := s.answer(ctx, Request{Op: "enrollments_export"}, 1004); string(r.Sealed) != "sealed export" || r.Error != "" {
		t.Fatalf("%+v", r)
	}
	imp := Request{Op: "enrollments_import", Replace: true, body: strings.NewReader("\nthe export")}
	if r := s.answer(ctx, imp, 1005); r.Text != "imported it" {
		t.Fatalf("%+v", r)
	}
	want := []call{{op: "reset", principal: "user:a@b", uid: 1000}, {op: "reset", all: true, uid: 1001},
		{op: "unlock", principal: "user:a@b", uid: 1002}, {op: "init", uid: 1003}, {op: "export", uid: 1004},
		{op: "import", replace: true, uid: 1005, body: "the export"}}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("call %d: %+v, want %+v", i, got[i], want[i])
		}
	}

	// An import body one byte over the bound is refused, and an empty one.
	got = nil
	big := Request{Op: "enrollments_import", body: io.LimitReader(zeros{}, maxImport+1)}
	if r := s.answer(ctx, big, 0); !strings.Contains(r.Error, "over 64 MiB") || len(got) != 0 {
		t.Fatalf("%+v, %v", r, got)
	}
	exact := Request{Op: "enrollments_import", body: io.LimitReader(ones{}, maxImport)}
	if r := s.answer(ctx, exact, 0); r.Text != "imported it" || len(got) != 1 {
		t.Fatalf("a body of exactly maxImport: %+v", r)
	}
	got = nil
	if r := s.answer(ctx, Request{Op: "enrollments_import", body: strings.NewReader("\n")}, 0); r.Error == "" || len(got) != 0 {
		t.Fatalf("%+v, %v", r, got)
	}
	// An export the socket cannot carry is not sent.
	s.EnrollmentsExport = func(context.Context, uint32) ([]byte, error) { return make([]byte, maxImport+1), nil }
	if r := s.answer(ctx, Request{Op: "enrollments_export"}, 0); r.Error == "" || len(r.Sealed) != 0 {
		t.Fatalf("an export over the bound: %d bytes, %q", len(r.Sealed), r.Error)
	}
	// The broker's refusal is the answer, whole.
	s.EnrollmentsInit = func(context.Context, uint32) (string, error) { return "", errors.New("it is already there") }
	if r := s.answer(ctx, Request{Op: "enrollments_init"}, 0); r.Error != "it is already there" {
		t.Fatalf("%+v", r)
	}
	if got := s.connTimeout("enrollments_import"); got != ListWait {
		t.Fatalf("enrollments_import holds its connection %v", got)
	}
}

// zeros and ones are endless readers of one byte.
type zeros struct{}

func (zeros) Read(p []byte) (int, error) { clear(p); return len(p), nil }

type ones struct{}

func (ones) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = '1'
	}
	return len(p), nil
}

// directory_forget reaches the broker with the caller's uid; with no
// broker it names where it is answered; a request naming no principal is
// refused before the broker is asked (plan 7g, Ruling 3's escape).
func TestDirectoryForgetReachesTheBroker(t *testing.T) {
	ctx := context.Background()
	var gotP string
	var gotUID uint32
	s := &Server{Held: &keyring.Held{}, Now: time.Now,
		Forget: func(_ context.Context, principal string, uid uint32) (string, error) {
			gotP, gotUID = principal, uid
			return "forgot it", nil
		}}
	if r := s.answer(ctx, Request{Op: "directory_forget", Principal: "user:alice@example.com"}, 1000); r.Text != "forgot it" ||
		gotP != "user:alice@example.com" || gotUID != 1000 {
		t.Fatalf("%+v %q %d", r, gotP, gotUID)
	}
	gotP = ""
	if r := s.answer(ctx, Request{Op: "directory_forget"}, 0); !strings.Contains(r.Error, "names a principal") || gotP != "" {
		t.Fatalf("%+v", r)
	}
	beside := &Server{Held: &keyring.Held{}, Now: time.Now, RevokeElsewhere: "port49-broker's admin socket"}
	if r := beside.answer(ctx, Request{Op: "directory_forget", Principal: "user:a@b"}, 0); !strings.Contains(r.Error,
		"port49-broker's admin socket") || !strings.Contains(r.Error, "port49 directory forget --socket") {
		t.Fatalf("%+v", r)
	}
	none := &Server{Held: &keyring.Held{}, Now: time.Now}
	if r := none.answer(ctx, Request{Op: "directory_forget", Principal: "user:a@b"}, 0); !strings.Contains(r.Error, "runs no broker") {
		t.Fatalf("%+v", r)
	}
}

// store_status answers the process's lines and whether a store did not
// answer; a process that reports no stores says so (plan 11a).
func TestStoreStatusOp(t *testing.T) {
	srv := &Server{Now: time.Now, StoreStatus: func(context.Context) (string, bool, error) {
		return "directory  etcd    ?/3 members  unreachable  cache 1.0s", true, nil
	}}
	r := srv.answer(context.Background(), Request{Op: "store_status"}, 0)
	if r.Error != "" || !r.Degraded || r.Text != "directory  etcd    ?/3 members  unreachable  cache 1.0s" {
		t.Fatalf("%+v", r)
	}
	if r := (&Server{Now: time.Now}).answer(context.Background(), Request{Op: "store_status"}, 0); r.Error == "" {
		t.Fatalf("a server with no StoreStatus answered %+v", r)
	}
}
