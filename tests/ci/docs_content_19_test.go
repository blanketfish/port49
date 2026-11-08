package ci

// Task 19: policy, roles and grants, revocation. Each string is a fact the page owes the operator.
func init() {
	mustSay["admin/policy.md"] = append(mustSay["admin/policy.md"],
		"on_missing: exclude", "deny_scope_unlogged", "acknowledge:", "rpc_entry_denies", "view-configuration",
	)
	mustSay["admin/revocation.md"] = append(mustSay["admin/revocation.md"],
		"--cert-serial", "certificate_status_unavailable", "issuer_file", "disabled: true",
	)
}
