//go:build darwin && hwkey_dlopen

package secureenclave

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/blanketfish/port49/internal/broker/api"
	"github.com/blanketfish/port49/internal/hwkey"
)

// The second process: opens the key the parent made, signs with it, and
// prints the SHA-256 of the public key it found, never the key itself.
const childLabelEnv = "PORT49_SE_TEST_CHILD_LABEL"

func TestMain(m *testing.M) {
	if label := os.Getenv(childLabelEnv); label != "" {
		Warnings = io.Discard
		os.Exit(child(label))
	}
	os.Exit(m.Run())
}

// child is the second process's work, its exit code: a func of its own so
// the key is closed (deferred) before os.Exit, which runs no defers.
func child(label string) int {
	s, err := Open(label)
	if err != nil {
		fmt.Println("open:", err)
		return 1
	}
	defer s.Close()
	msg := api.RefreshMessage([]byte("nonce"), []byte("ekm"))
	sig, err := api.SignRefresh(s, msg)
	if err != nil {
		fmt.Println("sign:", err)
		return 1
	}
	sum := sha256.Sum256(msg)
	if !ecdsa.VerifyASN1(s.Public().(*ecdsa.PublicKey), sum[:], sig) {
		fmt.Println("sign: the signature does not verify")
		return 1
	}
	fmt.Println("public", pubSum(s.Public().(*ecdsa.PublicKey)))
	return 0
}

func pubSum(p *ecdsa.PublicKey) string {
	b, _ := p.Bytes()
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// A key made under a random label signs a refresh message that verifies, is
// found and signs again from a second process (the agent opens the key the
// login made), and is deleted at the end. Run on a Mac:
// go test -tags hwkey_dlopen ./internal/hwkey/secureenclave/
func TestGenerateSignAndOpenFromASecondProcess(t *testing.T) {
	var rnd [6]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		t.Fatal(err)
	}
	label := "port49-test-" + hex.EncodeToString(rnd[:])
	var said strings.Builder
	Warnings, experimental = &said, new(sync.Once)
	t.Cleanup(func() { Warnings = os.Stderr })

	s, err := Generate(label)
	if err != nil {
		t.Fatalf("Generate: %v (L63 open: an OSStatus here is the measurement to report)", err)
	}
	t.Cleanup(func() {
		s.Close()
		if err := Delete(label); err != nil {
			t.Errorf("Delete %s: %v", label, err)
		}
		if _, err := Open(label); !errors.Is(err, ErrNotFound) {
			t.Errorf("after Delete, Open %s: %v, want ErrNotFound", label, err)
		}
	})
	if said.String() != ExperimentalWords+"\n" {
		t.Errorf("Generate said %q", said.String())
	}
	if s.State() != hwkey.Present {
		t.Fatalf("state %v", s.State())
	}
	msg := api.RefreshMessage([]byte("nonce"), []byte("ekm"))
	sig, err := api.SignRefresh(s, msg)
	if err != nil {
		t.Fatalf("SignRefresh: %v", err)
	}
	sum := sha256.Sum256(msg)
	pub := s.Public().(*ecdsa.PublicKey)
	if !ecdsa.VerifyASN1(pub, sum[:], sig) {
		t.Fatal("the signature does not verify")
	}
	if _, err := Generate(label); err == nil || !strings.Contains(err.Error(), "already labeled") {
		t.Fatalf("a second Generate under %s: %v", label, err)
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run", "^$")
	cmd.Env = append(os.Environ(), childLabelEnv+"="+label)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the second process: %v: %s", err, out)
	}
	if want := "public " + pubSum(pub) + "\n"; string(out) != want {
		t.Fatalf("the second process found %q, want %q", out, want)
	}
}

// A label no key has opens as ErrNotFound, which is not ErrKeyAbsent: a key
// that is not there is made, not plugged in.
func TestOpenOfNoKeyIsNotFound(t *testing.T) {
	Warnings = io.Discard
	t.Cleanup(func() { Warnings = os.Stderr })
	_, err := Open("port49-test-no-such-key")
	if !errors.Is(err, ErrNotFound) || errors.Is(err, hwkey.ErrKeyAbsent) {
		t.Fatalf("%v", err)
	}
}

// HostID names this Mac the same way twice, in 8 hex digits.
func TestHostID(t *testing.T) {
	a, err := HostID()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := HostID()
	if len(a) != 8 || a != b {
		t.Fatalf("%q %q", a, b)
	}
}
