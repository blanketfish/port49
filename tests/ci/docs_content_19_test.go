package ci

// Task 19: policy, roles and grants, revocation. Each string is a fact the page owes the operator.
func init() {
	mustSay["admin/policy.md"] = append(mustSay["admin/policy.md"],
		"on_missing: exclude", "acknowledge:",
	)
	mustSay["admin/policy-rules.md"] = append(mustSay["admin/policy-rules.md"],
		"on_missing: exclude", "deny_scope_unlogged", "no match key",
	)
	mustSay["admin/policy-tests.md"] = append(mustSay["admin/policy-tests.md"],
		"acknowledge:", "reason: no_permit_dominates_deny",
	)
	mustSay["admin/policy-review.md"] = append(mustSay["admin/policy-review.md"],
		"acknowledge:", "per_login_mfa_weakened", "new `group:` or `machine_group:` subject",
	)
	mustSay["admin/platform-sets.md"] = append(mustSay["admin/platform-sets.md"],
		"rpc_entry_denies", "view-configuration",
	)
	mustSay["admin/roles-and-grants.md"] = append(mustSay["admin/roles-and-grants.md"],
		"per_login_mfa_weakened", "new or changed", "core_access", "Do not put the requirement on an `on_missing: exclude` scope",
	)
	mustSay["admin/revocation.md"] = append(mustSay["admin/revocation.md"],
		"--cert-serial", "client-commands.md#port49-revoke",
	)
	mustSay["admin/sign-in/x509.md"] = append(mustSay["admin/sign-in/x509.md"],
		"certificate_status_unavailable", "issuer_file", "disabled: true", "admitted with its revocation status unchecked",
	)
}
