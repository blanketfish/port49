package ci

// Task 19: policy, roles and grants, revocation. Each string is a fact the page owes the operator.
func init() {
	mustSay["admin/policy.md"] = append(mustSay["admin/policy.md"],
		"on_missing: exclude", "deny_scope_unlogged", "acknowledge:", "rpc_entry_denies", "view-configuration",
		"per_login_mfa_weakened", "new `group:` or `machine_group:` subject", "no match key",
	)
	mustSay["admin/roles-and-grants.md"] = append(mustSay["admin/roles-and-grants.md"],
		"per_login_mfa_weakened", "new or changed", "core_access", "Do not put the requirement on an `on_missing: exclude` scope",
	)
	mustSay["admin/revocation.md"] = append(mustSay["admin/revocation.md"],
		"--cert-serial", "certificate_status_unavailable", "issuer_file", "disabled: true",
		"revocation_unconfirmed", "store_unavailable", "admitted with its revocation status unchecked",
	)
}
