//go:build lab

package lab

import (
	"os"
	"strings"
	"testing"
)

// platformSessionAttributes is lab-tagged, so this test is too. SR Linux runs
// the checked-in reply: cell (b)'s probe b1 logged in with it.
func TestL76RunsTheSharedReply(t *testing.T) {
	if got, ok := platformSessionAttributes[l76PlatformName]; ok {
		t.Fatalf("platformSessionAttributes has an entry for %s: %q", l76PlatformName, got)
	}
	// derivedConfig swaps one line for cell (b)'s probes, so it must exist
	// exactly once in the shared lab policy.
	b, err := os.ReadFile("port49d-lab.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(b), "\n  session_attributes: "); n != 1 {
		t.Errorf("port49d-lab.yaml has %d session_attributes lines, want 1", n)
	}
}

// A TACACS+ user's exec channels run in sr_cli on SR Linux 26.7.2 (L76 cell k),
// so SR Linux logins are exec channels; only C8000V runs one exec channel per
// connection and needs the pty path.
func TestSRLinuxLoginsUseExecChannels(t *testing.T) {
	for platform, want := range map[string]string{
		"nokia_srlinux": "exec",
		"cisco_iosxe":   "pty",
		"arista_eos":    "exec",
	} {
		if got := loginPath(platform); got != want {
			t.Errorf("loginPath(%s) = %q, want %q", platform, got, want)
		}
	}
	src, err := os.ReadFile("harness_test.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	i := strings.Index(s, "func (l *lab) loginWithin(")
	if i < 0 {
		t.Fatal("loginWithin not found in harness_test.go")
	}
	body := s[i:]
	if j := strings.Index(body, "\n}\n"); j >= 0 {
		body = body[:j]
	}
	if strings.Contains(body, "nokia_srlinux") {
		t.Error("loginWithin names nokia_srlinux; SR Linux logins are exec channels (L76 cell k), the L88 pty path is l88LoginWithin")
	}
}

// L87 and L88 measured SR Linux through the pty path, so their logins call
// l88LoginWithin, and l88LoginWithin keeps that path for nokia_srlinux.
func TestL87AndL88KeepSRLinuxsPtyPath(t *testing.T) {
	for _, f := range []string{"l88_test.go", "l87_test.go"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), ".loginWithin(") {
			t.Errorf("%s calls loginWithin; its SR Linux logins run through l88LoginWithin", f)
		}
	}
	src, err := os.ReadFile("l88_harness_test.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	i := strings.Index(s, "func (l *lab) l88LoginWithin(")
	if i < 0 {
		t.Fatal("l88LoginWithin not found")
	}
	body := s[i:]
	if j := strings.Index(body, "\n}\n"); j >= 0 {
		body = body[:j]
	}
	for _, want := range []string{"nokia_srlinux", "l.ptyCommands(", "echo l88-end"} {
		if !strings.Contains(body, want) {
			t.Errorf("l88LoginWithin lacks %q", want)
		}
	}
}
