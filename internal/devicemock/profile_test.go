package devicemock

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const root = "testdata"

func TestLoadAFixture(t *testing.T) {
	p, err := Load("testdata/profiles/fixture_junos.yaml", root)
	if err != nil {
		t.Fatal(err)
	}
	if p.Platform != "juniper_junos" || len(p.Stimulus.Steps) != 3 || p.Acceptance[0].Max != 255 {
		t.Fatalf("%+v", p)
	}
}

func TestLoadAcceptsTheWholeReactionVocabulary(t *testing.T) {
	if _, err := Load("testdata/profiles/fixture_vocabulary.yaml", root); err != nil {
		t.Fatalf("every on and then value must load (send_credential included): %v", err)
	}
}

func refused(t *testing.T, edit func(string) string, want string) {
	t.Helper()
	raw, _ := os.ReadFile("testdata/profiles/fixture_junos.yaml")
	path := filepath.Join(t.TempDir(), "p.yaml")
	os.WriteFile(path, []byte(edit(string(raw))), 0o600)
	_, err := Load(path, root)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("want an error naming %q, got %v", want, err)
	}
}

func TestLoadRefuses(t *testing.T) {
	t.Run("an unknown key", func(t *testing.T) {
		refused(t, func(s string) string { return s + "camelCase: 1\n" }, "camelCase")
	})
	t.Run("a missing note", func(t *testing.T) {
		refused(t, func(s string) string {
			return strings.Replace(s, "notes/L99-fixture_junos.md, register: L99}]\n    note:", "notes/L98-gone.md, register: L98}]\n    note:", 1)
		}, "L98-gone.md")
	})
	t.Run("a measured rule with no source", func(t *testing.T) {
		refused(t, func(s string) string {
			return strings.Replace(s, "    sources: [{note: notes/L99-fixture_junos.md, register: L99}]\n    note:", "    note:", 1)
		}, "junos_reply_total")
	})
	t.Run("a measured claim citing another firmware's note", func(t *testing.T) {
		refused(t, func(s string) string {
			return strings.Replace(s, "notes/L99-fixture_junos.md, register: L99}]\n    note:", "notes/L99-fixture_junos-2.md, register: L99}]\n    note:", 1)
		}, "Image version")
	})
	t.Run("an unknown reaction", func(t *testing.T) {
		refused(t, func(s string) string { return strings.Replace(s, "then: stop", "then: shrug", 1) }, "shrug")
	})
	t.Run("a credential-shaped key", func(t *testing.T) {
		refused(t, func(s string) string { return s + "token_sha256: x\n" }, "named like credential material")
	})
	t.Run("a credential-shaped value", func(t *testing.T) {
		refused(t, func(s string) string {
			return strings.Replace(s, `"service=junos-exec"`, `"credential_sha256=`+strings.Repeat("ab", 32)+`"`, 1)
		}, "credential")
	})
	t.Run("a PEM block", func(t *testing.T) {
		refused(t, func(s string) string {
			return strings.Replace(s, "image: fixture 1.0", "image: \"-----BEGIN PRIVATE KEY-----\"", 1)
		}, "BEGIN")
	})
	t.Run("a field the engine cannot send", func(t *testing.T) {
		refused(t, func(s string) string {
			return strings.Replace(s, "authen_type: pap, service: login, priv_lvl: 1", "authen_type: mschap, service: login, priv_lvl: 1", 1)
		}, "mschap")
	})
	t.Run("a full 40-hex commit", func(t *testing.T) {
		refused(t, func(s string) string {
			return strings.Replace(s, `commit: "0000000"`, `commit: "`+strings.Repeat("a1", 20)+`"`, 1)
		}, "credential")
	})
	t.Run("a commit that is not a short sha", func(t *testing.T) {
		refused(t, func(s string) string { return strings.Replace(s, `commit: "0000000"`, `commit: "main"`, 1) }, "commit")
	})
}

func TestAnUnmeasuredRuleMayCiteAnotherFirmwaresNote(t *testing.T) {
	raw, _ := os.ReadFile("testdata/profiles/fixture_junos.yaml")
	s := strings.Replace(string(raw), "    status: measured\n    sources: [{note: notes/L99-fixture_junos.md", "    status: unmeasured\n    sources: [{note: notes/L99-fixture_junos-2.md", 1)
	path := filepath.Join(t.TempDir(), "p.yaml")
	os.WriteFile(path, []byte(s), 0o600)
	if _, err := Load(path, root); err != nil {
		t.Fatalf("an unmeasured claim may cite the note that left it open: %v", err)
	}
}

func TestSlug(t *testing.T) {
	for in, want := range map[string]string{"10.6(2)F": "10.6-2-F", "26.2R1.7": "26.2R1.7", "4.36.3M": "4.36.3M", "26.7.2-519": "26.7.2-519"} {
		if got := Slug(in); got != want {
			t.Errorf("Slug(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestScenarioTransport(t *testing.T) {
	for sc, want := range map[string]string{"tls_token_login": "tls", "flight_delay": "tls", "token_login": "tcp", "single_connection": "tcp"} {
		if got := ScenarioTransport(sc); got != want {
			t.Errorf("ScenarioTransport(%q) = %q, want %q", sc, got, want)
		}
	}
	if BaseScenario("tls_unknown_ca") != "unknown_ca" || BaseScenario("token_login") != "token_login" {
		t.Error("BaseScenario")
	}
}
