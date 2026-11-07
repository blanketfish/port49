package docgen

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/blanketfish/port49/internal/platform"
	"github.com/blanketfish/port49/internal/policy"
	"github.com/blanketfish/port49/internal/userconfig"
)

// A key whose description names the values it takes must name the values its loader takes. Each entry
// here is one such key: accept is the set (from a constant of the loader's package, or, where the
// loader keeps its set in a literal, proved by loading each value), and others are the backticked
// words in the description that are not values. A backticked word that is in neither is a value the
// loader may not take, which is how a hyphen written for an underscore is found.
type enumKey struct {
	file, key string
	accept    []string
	others    []string
	// loads reports whether the real loader takes v for this key; nil when accept comes from constants.
	loads func(t *testing.T, v string) bool
}

const notAValue = "zz_not_a_value"

func policyBody(t *testing.T, body string) bool {
	t.Helper()
	// A policy with no subjects is refused as the wrong file; give every body one.
	if !strings.Contains(body, "subjects:") {
		body += "subjects:\n  - {name: someone, group: g}\n"
	}
	_, err := policy.Parse([]byte(body), policy.Env{})
	if err != nil {
		t.Logf("policy refused: %v", err)
	}
	return err == nil
}

func userconfigKey(key string) func(t *testing.T, v string) bool {
	return func(t *testing.T, v string) bool {
		t.Helper()
		d := t.TempDir()
		if err := os.Chmod(d, 0o700); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(d, "config.yaml")
		if err := os.WriteFile(p, []byte(key+": "+v+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, _, err := userconfig.Load(p, userconfig.WithoutCA())
		return err == nil
	}
}

func enumKeys() []enumKey {
	mfa := []string{string(policy.HardwareKeyTouch), string(policy.IdPMFA)}
	mfaLoads := func(t *testing.T, v string) bool {
		return policyBody(t, "defaults:\n  per_login_mfa: {accept: ["+v+"]}\n")
	}
	enable := func(t *testing.T, v string) bool {
		return policyBody(t, "subjects:\n  - {name: a, group: g, enable: "+v+"}\n")
	}
	return []enumKey{
		{file: "policy.yaml", key: "platforms.<name>.bit_delivery",
			accept: []string{platform.BitDeliveryUserPermissions, platform.BitDeliveryLocalUserName},
			others: []string{"local_user_names", "bit_delivery"}},
		{file: "policy.yaml", key: "platforms.<name>.command_projection", accept: []string{platform.ProjectionJunosRegex}},
		{file: "policy.yaml", key: "platforms.<name>.enable_username", accept: []string{platform.EnablePrincipal}},
		{file: "policy.yaml", key: "scopes.[].on_missing", accept: []string{"include", "exclude"},
			others: []string{"per_login_mfa"},
			loads: func(t *testing.T, v string) bool {
				return policyBody(t, "scopes:\n  - {name: s, match: {site: x}, on_missing: "+v+"}\n")
			}},
		{file: "policy.yaml", key: "subjects.[].enable", accept: []string{"none", "auto", "token"}, loads: enable},
		{file: "policy.yaml", key: "tests.[].expect", accept: []string{"permit", "deny"},
			loads: func(t *testing.T, v string) bool {
				return policyBody(t, "subjects:\n  - {name: a, group: g}\ntests:\n  - {subject: a, device: d, command: show version, expect: "+v+"}\n")
			}},
		{file: "policy.yaml", key: "tests.[].enable", accept: []string{"none", "auto", "token"},
			others: []string{"auto"},
			loads: func(t *testing.T, v string) bool {
				return policyBody(t, "subjects:\n  - {name: a, group: g}\ntests:\n  - {subject: a, device: d, enable: "+v+"}\n")
			}},
		{file: "policy.yaml", key: "subjects.[].api",
			accept: []string{policy.RightRevokeOthers, policy.RightExplainOthers, policy.RightLiftRevocations,
				policy.RightForgetPrincipals, policy.RightResetSecondFactor, policy.RightUnlockSignIn,
				policy.RightImportEnrollments, policy.RightSync, policy.RightKeysShow, policy.RightReplay}},
		{file: "policy.yaml", key: "defaults.per_login_mfa.accept", accept: mfa,
			others: []string{"per_login_mfa"}, loads: mfaLoads},
		{file: "config.yaml", key: "method", accept: []string{"x509", "oidc", "directory"}, loads: userconfigKey("method")},
		{file: "config.yaml", key: "broker_crl", accept: []string{"check", "require", "off"}, loads: userconfigKey("broker_crl")},
		{file: "config.yaml", key: "issued_key_store",
			accept: []string{"auto", "file", "tpm", "secure_enclave", "pkcs11"}, loads: userconfigKey("issued_key_store"),
			others: []string{"pkcs11:", "tpm:"}},
	}
}

var backticked = regexp.MustCompile("`([a-z][a-z0-9_-]*)`")

func TestEnumeratedValuesAreTheLoadersValues(t *testing.T) {
	byFile := map[string]Schema{}
	for _, s := range Schemas() {
		byFile[s.File] = s
	}
	for _, e := range enumKeys() {
		s, ok := byFile[e.file]
		if !ok {
			t.Errorf("%s: no such schema", e.file)
			continue
		}
		desc, err := LoadDescriptions(repoRoot, s)
		if err != nil {
			t.Fatal(err)
		}
		d, ok := desc[e.key]
		if !ok {
			t.Errorf("%s %s: no description", e.file, e.key)
			continue
		}
		// The loader takes every value the entry lists, and not a value it does not.
		if e.loads != nil {
			for _, v := range e.accept {
				if !e.loads(t, v) {
					t.Errorf("%s %s: the loader refuses %q, which the test lists as accepted", e.file, e.key, v)
				}
			}
			if e.loads(t, notAValue) {
				t.Errorf("%s %s: the loader takes %q, so the test proves nothing", e.file, e.key, notAValue)
			}
		}
		// The page names each accepted value, and every backticked word is one or a listed non-value.
		var named []string
		for _, m := range backticked.FindAllStringSubmatch(d, -1) {
			named = append(named, m[1])
		}
		for _, v := range e.accept {
			if !slices.Contains(named, v) {
				t.Errorf("%s %s: the description does not name `%s`", e.file, e.key, v)
			}
		}
		var stray []string
		for _, w := range named {
			if !slices.Contains(e.accept, w) && !slices.Contains(e.others, w) {
				stray = append(stray, w)
			}
		}
		sort.Strings(stray)
		if len(stray) > 0 {
			t.Errorf("%s %s: the description names %s, which the loader does not take (accepted: %s)", e.file, e.key,
				strings.Join(stray, ", "), strings.Join(e.accept, ", "))
		}
	}
}
