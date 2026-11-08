package ci

// Task 12: the Concepts pages. Each string is a fact the page owes its reader.
func init() {
	mustSay["concepts/tokens-receipts-contexts.md"] = []string{
		"receipt_idle_ttl", "receipt_max_age", "token_spent", "(nas, username)",
	}
	mustSay["concepts/revocation.md"] = []string{"port49 revoke", "credential_revoked"}
	mustSay["concepts/trust-domains.md"] = []string{"trust_domain_unresolved"}
}
