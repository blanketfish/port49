package port49d

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/oidc"
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
