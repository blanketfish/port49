package port49d

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/pivattest"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/testpki"
)

func TestAnUnusableAttestationRootsFileNeverRefusesTheStart(t *testing.T) {
	dir := t.TempDir()
	var said []string
	say := func(f string, a ...any) { said = append(said, fmt.Sprintf(f, a...)) }

	if v := loadPerLoginMFA(nil, say); v != nil {
		t.Fatalf("no per_login_mfa configured: %+v", v)
	}
	for name, content := range map[string]string{"missing": "", "notpem": "not a certificate"} {
		path := filepath.Join(dir, name+".pem")
		if name != "missing" {
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		said = nil
		v := loadPerLoginMFA(&oidc.PerLoginMFA{AttestationRootsFile: path}, say)
		if v == nil || v.Anchors != nil || len(said) != 1 || !strings.Contains(said[0], path) {
			t.Fatalf("%s: verifiers %+v, said %q: want touch unavailable and one line naming the file", name, v, said)
		}
	}

	root, err := testpki.NewCA("roots", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(dir, "good.pem")
	if err := os.WriteFile(good, root.PEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	if v := loadPerLoginMFA(&oidc.PerLoginMFA{AttestationRootsFile: good, AMR: []string{"hwk"}}, say); v == nil ||
		v.Anchors == nil || len(v.AMR) != 1 {
		t.Fatalf("a good roots file: %+v", v)
	}
}

func rootsPEM(t *testing.T, cn string) (pem []byte, pool *pivattest.Anchors) {
	t.Helper()
	ca, err := testpki.NewCA(cn, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	a, err := pivattest.ParseAnchors(ca.PEM())
	if err != nil {
		t.Fatal(err)
	}
	return ca.PEM(), &a
}

// A SIGHUP re-reads attestation_roots_file: a replaced file is in force at once, a file that
// cannot be used keeps the roots already held and says so in one line, and nothing else of
// the verifiers changes.
func TestSIGHUPReReadsTheAttestationRoots(t *testing.T) {
	path := filepath.Join(t.TempDir(), "roots.pem")
	oldPEM, oldRoots := rootsPEM(t, "old root")
	newPEM, newRoots := rootsPEM(t, "new root")
	write := func(b []byte) {
		t.Helper()
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var said []string
	say := func(f string, a ...any) { said = append(said, fmt.Sprintf(f, a...)) }
	pol := func() *policy.Policy { return nil }
	cfg := &oidc.PerLoginMFA{AttestationRootsFile: path, AMR: []string{"hwk"}, ACRValues: "acr-x"}
	write(oldPEM)
	b := &broker.Broker{PerLoginMFA: loadPerLoginMFA(cfg, say)}
	if b.PerLoginMFA.Anchors == nil || !b.PerLoginMFA.Anchors.Roots.Equal(oldRoots.Roots) {
		t.Fatal("the roots at start are not the file's")
	}

	write(newPEM)
	said = nil
	reloadAttestationRoots(cfg, b, pol, say)
	if !b.PerLoginMFA.Anchors.Roots.Equal(newRoots.Roots) || b.PerLoginMFA.Anchors.Roots.Equal(oldRoots.Roots) {
		t.Fatal("a SIGHUP did not put the replaced roots file in force")
	}
	if len(b.PerLoginMFA.AMR) != 1 || b.PerLoginMFA.ACRValues != "acr-x" {
		t.Fatalf("the swap changed the other verifier settings: %+v", b.PerLoginMFA)
	}
	if len(said) != 1 || !strings.Contains(said[0], path) || !strings.Contains(said[0], "re-read: 1 roots (was 1)") {
		t.Fatalf("a good reload said %q, want one line naming the file and the root counts", said)
	}

	// Unusable files keep the roots in force, and say so once.
	held := b.PerLoginMFA.Anchors
	for name, body := range map[string][]byte{"not PEM": []byte("not a certificate"), "empty": {}, "missing": nil} {
		if body == nil {
			_ = os.Remove(path)
		} else {
			write(body)
		}
		said = nil
		reloadAttestationRoots(cfg, b, pol, say)
		if b.PerLoginMFA.Anchors != held {
			t.Errorf("%s: the roots in force were replaced", name)
		}
		if len(said) != 1 || !strings.Contains(said[0], "keeping the attestation roots already in force") ||
			!strings.Contains(said[0], path) {
			t.Errorf("%s: said %q, want one line naming the file and that the old roots are kept", name, said)
		}
	}

	// No roots file configured: nothing read, nothing said.
	said = nil
	reloadAttestationRoots(&oidc.PerLoginMFA{}, b, pol, say)
	reloadAttestationRoots(nil, b, pol, say)
	if len(said) != 0 || b.PerLoginMFA.Anchors != held {
		t.Errorf("with no roots file: said %q", said)
	}
}

// The reloader runs every function added for a SIGHUP, in the order added.
func TestAddHUPChains(t *testing.T) {
	r := &reloader{}
	var order []string
	r.addHUP(func() { order = append(order, "first") })
	r.addHUP(func() { order = append(order, "second") })
	r.onHUP()
	if strings.Join(order, ",") != "first,second" {
		t.Fatalf("order %v", order)
	}
}
