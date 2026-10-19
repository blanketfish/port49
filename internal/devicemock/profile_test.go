package devicemock

import (
	"crypto/rand"
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
	_, err := loadEdited(t, edit)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("want an error naming %q, got %v", want, err)
	}
}

// loadEdited loads fixture_junos.yaml after edit, failing if the edit
// changed nothing so a stale Replace cannot make a test vacuous.
func loadEdited(t *testing.T, edit func(string) string) (*Profile, error) {
	t.Helper()
	raw, err := os.ReadFile("testdata/profiles/fixture_junos.yaml")
	if err != nil {
		t.Fatal(err)
	}
	s := edit(string(raw))
	if s == string(raw) {
		t.Fatal("the edit changed nothing")
	}
	path := filepath.Join(t.TempDir(), "p.yaml")
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(path, root)
}

func randBase62(t *testing.T, n int) string {
	t.Helper()
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

func TestNamesFirmware(t *testing.T) {
	for _, c := range []struct {
		line, fw string
		want     bool
	}{
		{"vJunos-router 23.4R2", "23.4R2", true},
		{"vJunos-router 23.4R2-S2.1", "23.4R2", false},
		{"vJunos-router 23.4R2.1", "23.4R2", false},
		{"vJunos-router 123.4R2", "23.4R2", false},
		{"fixture 1.0", "1.0", true},
		{"image 10.6(2)F, lab", "10.6(2)F", true},
		{"image 10.6(2)F.", "10.6(2)F", true},
		{"anything", "", false},
	} {
		if got := namesFirmware(c.line, c.fw); got != c.want {
			t.Errorf("namesFirmware(%q, %q) = %v, want %v", c.line, c.fw, got, c.want)
		}
	}
}

func TestLoadRefuses(t *testing.T) {
	t.Run("an unknown key", func(t *testing.T) {
		refused(t, func(s string) string { return s + "camelCase: 1\n" }, "camelCase")
	})
	t.Run("a missing note", func(t *testing.T) {
		refused(t, func(s string) string {
			return strings.Replace(s, "tests/lab/results/L99-fixture_junos.md, register: L99}]\n    note:", "tests/lab/results/L98-gone.md, register: L98}]\n    note:", 1)
		}, "L98-gone.md")
	})
	t.Run("a measured rule with no source", func(t *testing.T) {
		refused(t, func(s string) string {
			return strings.Replace(s, "    sources: [{note: tests/lab/results/L99-fixture_junos.md, register: L99}]\n    note:", "    note:", 1)
		}, "junos_reply_total")
	})
	t.Run("a measured claim citing another firmware's note", func(t *testing.T) {
		refused(t, func(s string) string {
			return strings.Replace(s, "tests/lab/results/L99-fixture_junos.md, register: L99}]\n    note:", "tests/lab/results/L99-fixture_junos-2.md, register: L99}]\n    note:", 1)
		}, "Image version")
	})
	t.Run("an unknown reaction", func(t *testing.T) {
		refused(t, func(s string) string { return strings.Replace(s, "then: stop", "then: shrug", 1) }, "shrug")
	})
	t.Run("a credential-shaped key", func(t *testing.T) {
		refused(t, func(s string) string { return s + "token_sha256: x\n" }, "named like credential material")
	})
	t.Run("a credential hash value", func(t *testing.T) {
		refused(t, func(s string) string {
			return strings.Replace(s, `"service=junos-exec"`, `"credential_sha256=x"`, 1)
		}, "a credential hash")
	})
	t.Run("a long hex value", func(t *testing.T) {
		refused(t, func(s string) string {
			return strings.Replace(s, `"service=junos-exec"`, `"service=`+strings.Repeat("ab", 32)+`"`, 1)
		}, "long hex")
	})
	t.Run("a base64 value", func(t *testing.T) {
		refused(t, func(s string) string {
			return strings.Replace(s, `"service=junos-exec"`, `"service=`+strings.Repeat("A", 20)+"+"+strings.Repeat("B", 24)+`"`, 1)
		}, "long base64")
	})
	t.Run("a token-shaped value", func(t *testing.T) {
		refused(t, func(s string) string {
			return strings.Replace(s, `"service=junos-exec"`, `"`+randBase62(t, 30)+`"`, 1)
		}, "port49 token shape")
	})
	t.Run("a secret used as a key is refused without echoing it", func(t *testing.T) {
		key := randBase62(t, 30)
		_, err := loadEdited(t, func(s string) string { return s + key + ": 1\n" })
		if err == nil || !strings.Contains(err.Error(), "a key shaped like credential material") {
			t.Fatalf("got %v", err)
		}
		if strings.Contains(err.Error(), key) {
			t.Fatal("the error echoes the key")
		}
	})
	t.Run("a schema version this engine does not read", func(t *testing.T) {
		refused(t, func(s string) string { return strings.Replace(s, "schema_version: 1", "schema_version: 2", 1) }, "schema_version")
	})
	t.Run("an empty firmware", func(t *testing.T) {
		refused(t, func(s string) string { return strings.Replace(s, `firmware: "1.0"`, `firmware: ""`, 1) }, "firmware is empty")
	})
	t.Run("a firmware only a longer version names", func(t *testing.T) {
		refused(t, func(s string) string { return strings.Replace(s, `firmware: "1.0"`, `firmware: "fixture 1"`, 1) }, "Image version")
	})
	t.Run("a typo in a reaction step", func(t *testing.T) {
		refused(t, func(s string) string {
			return strings.Replace(s, "step: login, on: authen_pass", "step: logn, on: authen_pass", 1)
		}, "logn")
	})
	t.Run("an unknown connection mode", func(t *testing.T) {
		refused(t, func(s string) string { return strings.Replace(s, "mode: per_step", "mode: per_stp", 1) }, "per_stp")
	})
	t.Run("an unknown acceptance effect", func(t *testing.T) {
		refused(t, func(s string) string { return strings.Replace(s, "effect: lockout", "effect: lockuot", 1) }, "lockuot")
	})
	t.Run("a note outside tests/lab/results", func(t *testing.T) {
		refused(t, func(s string) string {
			return strings.Replace(s, "note: tests/lab/results/L99-fixture_junos.md, register: L99}]\n    note:", "note: tests/lab/results/../../../../profiles/fixture_plain.yaml, register: L99}]\n    note:", 1)
		}, "must be a clean .md path")
	})
	t.Run("a clean note path outside tests/lab/results", func(t *testing.T) {
		refused(t, func(s string) string {
			return strings.Replace(s, "note: tests/lab/results/L99-fixture_junos.md, register: L99}]\n    note:", "note: docs/design/other.md, register: L99}]\n    note:", 1)
		}, "must be a clean .md path")
	})
	t.Run("a vetted note that is missing", func(t *testing.T) {
		refused(t, func(s string) string {
			return strings.Replace(s, "notes: [tests/lab/results/L99-fixture_junos.md]", "notes: [tests/lab/results/L98-gone.md]", 1)
		}, "L98-gone.md")
	})
	t.Run("an engine gap citing a missing note", func(t *testing.T) {
		refused(t, func(s string) string {
			return strings.Replace(s, "engine_gaps: []", "engine_gaps: [{id: g1, what: x, sources: [{note: tests/lab/results/L98-gone.md, register: L98}]}]", 1)
		}, "L98-gone.md")
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
			return strings.Replace(s, `commit: "000000000000"`, `commit: "`+strings.Repeat("a1", 20)+`"`, 1)
		}, "credential")
	})
	t.Run("a commit that is not exactly 12 hex", func(t *testing.T) {
		for _, c := range []string{"main", "0000000", "0000000000000"} {
			refused(t, func(s string) string { return strings.Replace(s, `commit: "000000000000"`, `commit: "`+c+`"`, 1) }, "vetted.commit")
		}
	})
}

func TestAnUnmeasuredRuleMayCiteAnotherFirmwaresNote(t *testing.T) {
	_, err := loadEdited(t, func(s string) string {
		return strings.Replace(s, "    status: measured\n    sources: [{note: tests/lab/results/L99-fixture_junos.md", "    status: unmeasured\n    sources: [{note: tests/lab/results/L99-fixture_junos-2.md", 1)
	})
	if err != nil {
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
