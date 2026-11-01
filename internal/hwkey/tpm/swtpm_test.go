//go:build hwkey

package tpm_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blanketfish/port49/internal/broker/api"
	"github.com/blanketfish/port49/internal/hwkey"
	"github.com/blanketfish/port49/internal/hwkey/hwtest"
	"github.com/blanketfish/port49/internal/hwkey/tpm"
)

func TestATPMKeySignsAndSurvivesAReopen(t *testing.T) {
	hwtest.SWTPM(t) // sets tpm.Dial to swtpm over TCP for this test
	path := filepath.Join(t.TempDir(), "k.tpmkey")
	s, err := tpm.Generate(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600", fi.Mode().Perm())
	}
	msg := api.RefreshMessage(make([]byte, api.RefreshNonceLen), make([]byte, 32))
	sig, err := api.SignRefresh(s, msg)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(msg)
	if !ecdsa.VerifyASN1(s.Public().(*ecdsa.PublicKey), sum[:], sig) {
		t.Fatal("the signature does not verify")
	}
	s.Close()
	again, err := tpm.Open(path)
	if err != nil || !again.Public().(*ecdsa.PublicKey).Equal(s.Public()) {
		t.Fatalf("reopen: %v", err)
	}
}

func TestATPMKeyFromAnotherTPMDoesNotLoad(t *testing.T) {
	hwtest.SWTPM(t)
	path := filepath.Join(t.TempDir(), "k.tpmkey")
	if _, err := tpm.Generate(path); err != nil {
		t.Fatal(err)
	}
	hwtest.SWTPMFresh(t) // a second swtpm with its own state: another machine
	if _, err := tpm.Open(path); err == nil || !strings.Contains(err.Error(), "this machine's TPM") {
		t.Fatalf("Open on another TPM = %v, want refused naming this machine's TPM", err)
	}
}

func TestATPMGoneIsAbsentAndBackIsPresentWithoutASignature(t *testing.T) {
	sim := hwtest.SWTPM(t)
	s, err := tpm.Generate(filepath.Join(t.TempDir(), "k.tpmkey"))
	if err != nil {
		t.Fatal(err)
	}
	sim.Stop()
	if _, err := s.Sign(nil, make([]byte, 32), crypto.SHA256); !errors.Is(err, hwkey.ErrKeyAbsent) || s.State() != hwkey.Absent {
		t.Fatalf("Sign with swtpm stopped = %v, state %v", err, s.State())
	}
	// Re-inserted: the same state directory. State re-probes from Absent with
	// no Sign in between (decision 45 ruling 8; pre-flight C2).
	sim.Restart()
	if got := s.State(); got != hwkey.Present {
		t.Fatalf("State after swtpm restarted = %v, want Present with no Sign between", got)
	}
}
