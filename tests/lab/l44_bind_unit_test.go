//go:build lab

package lab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// L44's ADCS EXTERNAL bind loads the broker's pair through the file fence, which refuses an in-tree path
// (a group-writable ancestor, as under ~/git): the bind names private copies, as L42-L43 and L48 do (#48).
func TestL44ADCSBindNamesPrivateCopies(t *testing.T) {
	r, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	defer func(was string) { root = was }(root)
	root = r
	inTree := filepath.Join(r, "tests", "lab", "l44-bind-unit-fixture")
	if err := os.MkdirAll(inTree, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(inTree) })
	c := &winCerts{brokerCertFile: filepath.Join(inTree, "broker-adcs.pem"), brokerKeyFile: filepath.Join(inTree, "broker-adcs-key.pem")}
	for _, p := range []string{c.brokerCertFile, c.brokerKeyFile} {
		if err := os.WriteFile(p, []byte("fixture "+filepath.Base(p)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var cert, key string
	t.Run("bind", func(t *testing.T) {
		b := c.adcsBind(t)
		if b.Mechanism != "external" {
			t.Fatalf("mechanism %q", b.Mechanism)
		}
		cert, key = b.TLSCertFile, b.TLSKeyFile
		for _, p := range []string{cert, key} {
			if _, in := underRoot(p); in || strings.HasPrefix(p, inTree) {
				t.Errorf("%s is inside the repository: the fence refuses it", p)
			}
			if st, err := os.Stat(p); err != nil || st.Mode().Perm() != 0o600 {
				t.Errorf("%s: want a 0600 file (stat %v, %v)", p, st, err)
			}
		}
		if got, _ := os.ReadFile(cert); string(got) != "fixture broker-adcs.pem" {
			t.Errorf("the certificate copy differs from its source")
		}
	})
	for _, p := range []string{cert, key} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("the private copy %s outlived its test (stat: %v)", p, err)
		}
	}
}
