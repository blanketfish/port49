package ci

// Task 20: identity providers, workloads and inventory. Each string is a fact the page owes the operator.
func init() {
	mustSay["admin/identity-providers.md"] = append(mustSay["admin/identity-providers.md"],
		"POST /v1/certificate", "idp_mfa", "`sid`", "identity_unmapped", "trust_domain_unresolved", "jwks_max_age",
		"certificate_lifetime", "`sub`", "port49 revoke --lift", "multi-valued", "enrollment_closed", "new_entries_for",
		"X509:<I>", "nested_groups",
	)
	mustSay["admin/workloads.md"] = append(mustSay["admin/workloads.md"],
		"machine_group:", "step-ca", "step-ca-workload.tpl", "identity_ambiguous", "port49 directory forget",
		"directory_unavailable", "spiffe_id",
	)
	mustSay["admin/inventory.md"] = append(mustSay["admin/inventory.md"],
		"max_removed_percent", "`interval`", "quarantine", "device_quarantined", "HTTPS_PROXY", "inventory.service",
	)
}
