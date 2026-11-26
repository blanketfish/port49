package ci

// Task 20: identity providers, workloads and inventory. Each string is a fact the page owes the operator.
func init() {
	mustSay["admin/sign-in/oidc.md"] = append(mustSay["admin/sign-in/oidc.md"],
		"POST /v1/certificate", "idp_mfa", "`sid`", "trust_domain_unresolved", "jwks_max_age",
		"certificate_lifetime", "`sub`", "port49 revoke --lift",
	)
	mustSay["admin/directory.md"] = append(mustSay["admin/directory.md"],
		"identity_unmapped", "multi-valued", "X509:<I>", "nested_groups",
	)
	mustSay["admin/sign-in/directory-password.md"] = append(mustSay["admin/sign-in/directory-password.md"],
		"enrollment_closed", "new_entries_for",
	)
	mustSay["admin/admin-access.md"] = append(mustSay["admin/admin-access.md"],
		"attestation_roots_file", "revoke_others", "lift_revocations", "`identity:`", "`group:`",
		"systemctl reload port49-broker", "kill -s HUP", "attestationRootsConfigMap",
	)
	mustSay["admin/workloads.md"] = append(mustSay["admin/workloads.md"],
		"machine_group:", "step-ca", "step-ca-workload.tpl", "identity_ambiguous", "port49 directory forget",
		"directory_unavailable", "spiffe_id",
	)
	mustSay["admin/inventory.md"] = append(mustSay["admin/inventory.md"],
		"max_removed_percent", "`interval`", "quarantine", "device_quarantined", "HTTPS_PROXY", "inventory.service",
	)
}
