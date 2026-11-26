package ci

// Task 12: the Concepts pages. Each string is a fact the page owes its reader.
func init() {
	mustSay["concepts/index.md"] = []string{
		"port49 gives people and workloads their own identity on network devices that only speak TACACS+.",
		"## Terms",
		"Two things follow from how a login works.",
	}
	mustSay["concepts/tokens-receipts-contexts.md"] = []string{
		"receipt_idle_ttl", "receipt_max_age", "token_spent", "(nas, username)",
		"## The session", "**Logging in again joins it.**", "**It belongs to one principal.**",
		"session.replaced_ctx_id", "never from anything the device sends",
	}
	mustSay["concepts/revocation.md"] = []string{"port49 revoke", "credential_revoked"}
	mustSay["concepts/trust-domains.md"] = []string{"trust_domain_unresolved"}
}
