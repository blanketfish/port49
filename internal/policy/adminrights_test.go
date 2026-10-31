package policy

import (
	"slices"
	"strings"
	"testing"
)

const adminRightsPolicy = `
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: readonly, permit: [show **]}]
subjects:
  - {name: oncall, identity: ["user:bob@example.com"], username: bob, token_ttl: 60s, api: [lift_revocations, explain_others]}
  - {name: dirs, identity: ["user:dan@example.com"], username: dan, token_ttl: 60s, api: [forget_principals, reset_second_factor, unlock_sign_in, import_enrollments]}
  - {name: ops, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s, api: [explain_others, sync]}
  - {name: g, group: "CN=g,OU=Groups,DC=example,DC=com", token_ttl: 60s, api: [revoke_others]}
  - {name: plain, identity: ["user:eve@example.com"], username: eve, token_ttl: 60s}
grants: [{subject: ops, scope: all_devices, roles: [r]}]`

// The five rights the admin endpoints add are rights a subject may declare
// (spec §2), and each is its own: holding one grants none of the others.
func TestTheAdminRightsAreRights(t *testing.T) {
	p := mustParse(t, adminRightsPolicy)
	for _, c := range []struct {
		principal, right string
		want             bool
	}{
		{"user:bob@example.com", RightLiftRevocations, true},
		{"user:bob@example.com", RightRevokeOthers, false}, // a lift is not a revoke right
		{"user:dan@example.com", RightForgetPrincipals, true},
		{"user:dan@example.com", RightResetSecondFactor, true},
		{"user:dan@example.com", RightUnlockSignIn, true},
		{"user:dan@example.com", RightImportEnrollments, true},
		{"user:dan@example.com", RightLiftRevocations, false},
		{"user:alice@example.com", RightForgetPrincipals, false},
	} {
		if got := p.HasRight(c.principal, c.right); got != c.want {
			t.Errorf("HasRight(%s, %s) = %v", c.principal, c.right, got)
		}
	}
	if RightLiftRevocations != "lift_revocations" || RightForgetPrincipals != "forget_principals" ||
		RightResetSecondFactor != "reset_second_factor" || RightUnlockSignIn != "unlock_sign_in" ||
		RightImportEnrollments != "import_enrollments" {
		t.Fatal("a right's name is spec §2's")
	}
}

// A misspelt right still fails the load, and the error names the list, which
// now holds the admin rights.
func TestAnUnknownRightStillFailsLoad(t *testing.T) {
	body := strings.Replace(adminRightsPolicy, "lift_revocations", "lift_revocation", 1)
	_, err := Parse([]byte(body), Env{Now: noon})
	if err == nil || !strings.Contains(err.Error(), "api[0] is not a right") {
		t.Fatalf("a misspelt right loaded: %v", err)
	}
	for _, r := range []string{"lift_revocations", "forget_principals", "reset_second_factor", "unlock_sign_in",
		"import_enrollments", "revoke_others"} {
		if !strings.Contains(err.Error(), r) {
			t.Errorf("the error does not name %s: %v", r, err)
		}
	}
}

// AdminRightHolders is the subjects that declare an admin-level right (spec
// §2), sorted: the start line's condition. explain_others and the reserved
// rights are not admin-level, and a group subject counts, since a member of
// its group holds the right.
func TestAdminRightHoldersAreTheSubjectsWithAnAdminRight(t *testing.T) {
	p := mustParse(t, adminRightsPolicy)
	if got := p.AdminRightHolders(); !slices.Equal(got, []string{"dirs", "g", "oncall"}) {
		t.Fatalf("holders = %v, want [dirs g oncall]", got)
	}
	none := mustParse(t, strings.Replace(strings.Replace(strings.Replace(adminRightsPolicy,
		"lift_revocations, ", "", 1), "forget_principals, reset_second_factor, unlock_sign_in, import_enrollments",
		"sync", 1), "api: [revoke_others]", "api: [replay]", 1))
	if got := none.AdminRightHolders(); len(got) != 0 {
		t.Fatalf("a policy with no admin-level right has holders %v", got)
	}
}

// The api_rights finding names the admin-level rights a subject holds, so a
// reviewer sees which need a key press; a subject with none names none.
func TestTheAPIRightsFindingNamesTheAdminLevelRights(t *testing.T) {
	p := mustParse(t, adminRightsPolicy)
	got := map[string]string{}
	for _, f := range p.Lint(noon) {
		if f.Kind == FindingAPIRights {
			for _, name := range []string{"oncall", "dirs", "ops"} {
				if strings.Contains(f.Message, `subject "`+name+`"`) {
					got[name] = f.Message
				}
			}
		}
	}
	if !strings.Contains(got["oncall"], "admin-level") || !strings.Contains(got["oncall"], "lift_revocations") ||
		strings.Contains(got["oncall"], "key press: lift_revocations explain_others") {
		t.Errorf("oncall: %q", got["oncall"])
	}
	if !strings.Contains(got["dirs"], "forget_principals reset_second_factor unlock_sign_in import_enrollments") {
		t.Errorf("dirs: %q", got["dirs"])
	}
	if strings.Contains(got["ops"], "admin-level") {
		t.Errorf("ops holds no admin-level right: %q", got["ops"])
	}
}
